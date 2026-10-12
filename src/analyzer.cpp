#include "analyzer.hpp"
#include "sdk_logs.hpp"
#include "analysis_util.hpp"
#include "diagnostics.hpp"
#include <miniz.h>
#include <xmllite.h>
#include <shlwapi.h>
#include <algorithm>
#include <array>
#include <sstream>
#include <tuple>
#include <bcrypt.h>
#include <exception>

namespace fnc {
using namespace detail;
namespace {
constexpr size_t file_limit=64*1024*1024, total_limit=256*1024*1024;
constexpr size_t record_limit=100000, line_limit=1024*1024;
bool user_log_name(std::string_view name) {
    for(size_t i=1;i<=kUserLogCount;++i)if(name=="user-log-"+std::to_string(i)+".log")return true;return false;
}
bool streamed_log_name(std::string_view name) {return sdk_log_name(name)||name=="sapera-Logs.dat";}
void account_size(std::string_view name,uint64_t size,uint64_t& retained,uint64_t& logs,uint64_t& mvsdk) {
    if(name=="manifest.json"){need(size<=1024*1024,"Manifest size limit exceeded.");return;}
    if(user_log_name(name)) {
        need(size<=kUserLogBytes&&size<=kUserLogBytes*kUserLogCount-logs,"User log size limit exceeded.");logs+=size;
    } else {
        if(mvsdk_log_name(name)){need(size<=kUserLogBytes&&size<=kMvSdkLogBytes-mvsdk,"MVSDK log size limit exceeded.");mvsdk+=size;}
        need(size<=file_limit&&size<=total_limit-retained,"Evidence size limit exceeded.");retained+=size;
    }
}
class StreamHash {
    BCRYPT_ALG_HANDLE alg_=nullptr;BCRYPT_HASH_HANDLE hash_=nullptr;
    static void check(NTSTATUS status){if(status<0)fail_win("Evidence SHA-256",static_cast<DWORD>(status));}
public:
    uint64_t bytes=0;std::exception_ptr error;
    uint64_t limit=kUserLogBytes;
    SdkLogParser* parser=nullptr;
    StreamHash(){check(BCryptOpenAlgorithmProvider(&alg_,BCRYPT_SHA256_ALGORITHM,nullptr,0));
        try{check(BCryptCreateHash(alg_,&hash_,nullptr,0,nullptr,0,0));}catch(...){BCryptCloseAlgorithmProvider(alg_,0);throw;}}
    ~StreamHash(){if(hash_)BCryptDestroyHash(hash_);if(alg_)BCryptCloseAlgorithmProvider(alg_,0);}
    StreamHash(const StreamHash&)=delete;StreamHash& operator=(const StreamHash&)=delete;
    void update(const void* buffer,size_t size) {
        need(size<=limit-bytes,"Log stream limit exceeded.");bytes+=size;
        if(parser)parser->feed(std::string_view(static_cast<const char*>(buffer),size));
        auto* p=static_cast<const BYTE*>(buffer);
        while(size){auto n=static_cast<ULONG>((std::min)(size,size_t(65536)));check(BCryptHashData(hash_,const_cast<BYTE*>(p),n,0));p+=n;size-=n;}
    }
    EvidenceDigest finish(){BYTE digest[32];check(BCryptFinishHash(hash_,digest,sizeof(digest),0));
        std::string out;char b[3];for(auto v:digest){sprintf_s(b,"%02x",v);out+=b;}return {bytes,out};}
};
size_t hash_zip_chunk(void* opaque,mz_uint64 offset,const void* buffer,size_t size) noexcept {
    auto& hash=*static_cast<StreamHash*>(opaque);
    try{need(offset==hash.bytes,"Non-sequential ZIP log stream.");hash.update(buffer,size);return size;}
    catch(...){hash.error=std::current_exception();return 0;}
}
bool safe_name(std::string_view name) {
    if(name.empty()||name.size()>240||name.front()=='.'||name.back()=='.')return false;
    for(unsigned char c:name)if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.'))return false;
    auto stem=lower(std::string(name.substr(0,name.find('.'))));
    return stem!="con"&&stem!="prn"&&stem!="aux"&&stem!="nul"&&
        !(stem.size()==4&&(stem.starts_with("com")||stem.starts_with("lpt"))&&stem[3]>='1'&&stem[3]<='9');
}
Json parse_json(std::string_view bytes) {
    need(bytes.size()<=file_limit,"JSON size limit exceeded.");
    if(bytes.starts_with("\xef\xbb\xbf"))bytes.remove_prefix(3);
    // nlohmann parses deeply nested input recursively. Bound depth before parsing.
    size_t depth=0;bool quoted=false,escaped=false;
    for(char c:bytes) {
        if(quoted){if(escaped)escaped=false;else if(c=='\\')escaped=true;else if(c=='"')quoted=false;continue;}
        if(c=='"')quoted=true;else if(c=='{'||c=='[')need(++depth<=128,"JSON nesting limit exceeded.");
        else if(c=='}'||c==']'){if(depth)--depth;}
    }
    return Json::parse(bytes);
}
void verify_files(const EvidenceFiles& files) {
    need(files.contains("manifest.json")&&files.contains("snapshot.json"),"A complete bundle with manifest.json and snapshot.json is required.");
    auto manifest=parse_json(files.at("manifest.json"));need(manifest.contains("files")&&manifest["files"].is_array(),"Invalid manifest files list.");
    need(manifest["files"].size()<=255,"Manifest file count limit exceeded.");
    std::set<std::string> seen;uint64_t total=0,logs=0,mvsdk=0;
    for(const auto& item:manifest["files"]) {
        auto name=item.at("name").get<std::string>();need(safe_name(name)&&name!="manifest.json","Unsafe manifest name.");
        need(seen.insert(lower(name)).second,"Duplicate manifest filename.");
        auto it=files.find(name);need(it!=files.end(),"Manifest evidence file is missing: "+name);
        auto streamed=files.streamed_digests().find(name);EvidenceDigest digest;
        if(streamed!=files.streamed_digests().end()) {
            need(streamed_log_name(name)&&it->second.empty(),"Invalid streamed evidence.");digest=streamed->second;
        } else digest={it->second.size(),sha256_bytes(it->second)};
        account_size(name,digest.size_bytes,total,logs,mvsdk);
        need(item.at("size_bytes").get<uint64_t>()==digest.size_bytes,"Evidence size mismatch: "+name);
        need(lower(item.at("sha256").get<std::string>())==digest.sha256,"Evidence SHA-256 mismatch: "+name);
    }
    need(files.size()==seen.size()+1,"ZIP contains files not covered by manifest.");
}
size_t zip_read(void* opaque,mz_uint64 offset,void* buffer,size_t n) {
    if(n>MAXDWORD||offset>MAXLONGLONG)return 0;
    LARGE_INTEGER pos{};pos.QuadPart=static_cast<LONGLONG>(offset);auto h=static_cast<HANDLE>(opaque);
    if(!SetFilePointerEx(h,pos,nullptr,FILE_BEGIN))return 0;DWORD done=0;
    return ReadFile(h,buffer,static_cast<DWORD>(n),&done,nullptr)?done:0;
}
// Join by the saved adapter GUID, never by a mutable name or shared driver description.
void setting_nic(Json& setting,const Json& nics,std::string id) {
    auto end=id.find("::");if(end!=std::string::npos)id.resize(end);id=lower(id);
    setting["nic_state"]="미매핑";setting["ip_mtu"]=nullptr;setting["if_index"]=nullptr;
    if(id.empty())return;
    for(const auto& n:nics)if(lower(string_value(n,"adapter_name"))==id) {
        setting["Name"]=string_value(n,"friendly_name");setting["nic_state"]=n["state"];setting["if_index"]=n["if_index"];
        const auto& i=obj(n,"interface");setting["ip_mtu"]=i.value("mtu",n.value("mtu",Json(nullptr)));return;
    }
}
std::optional<size_t> nic_index(const Json& row,const Json& nics) {
    std::string id;
    for(auto key:{"InstanceID","GUID","SettingID"})if(row.contains(key)&&row[key].is_string()&&!row[key].get<std::string>().empty()){id=row[key].get<std::string>();break;}
    if(!id.empty()) {
        auto end=id.find("::");if(end!=std::string::npos)id.resize(end);id=lower(id);
        for(size_t i=0;i<nics.size();++i)if(lower(string_value(nics[i],"adapter_name"))==id)return i;
        return {}; // A conflicting GUID must not fall back to names or indices.
    }
    if(row.contains("InterfaceIndex")&&row["InterfaceIndex"].is_number()) {
        for(size_t i=0;i<nics.size();++i)if(row["InterfaceIndex"]==nics[i]["if_index"])return i;
    }
    return {};
}
void nic_details(Json& report,const Json& snapshot) {
    auto& nics=report["nics"];
    for(auto& nic:nics) {
        nic["details"]=Json::object();
        for(auto group:{"advanced","power","offload","bindings","profiles","drivers","ip_configuration","saved_settings"})nic["details"][group]=Json::array();
    }
    auto attach=[&](const Json& row,const Json& query,const char* group){
        if(auto i=nic_index(row,nics)){Json copy=row;copy["evidence"]=string_value(query,"source");nics[*i]["details"][group].push_back(copy);}
    };
    for(auto group:{"advanced","power","offload"})for(const auto& q:arr(module(snapshot,group),"queries"))for(const auto& a:arr(q,"rows"))attach(a,q,group);
    for(const auto& q:arr(module(snapshot,"bindings"),"queries"))for(const auto& a:arr(q,"rows")) {
        if(a.contains("ComponentID"))attach(a,q,"bindings");
        else if(a.contains("NetworkCategory"))attach(a,q,"profiles");
    }
    std::map<std::string,std::set<size_t>> devices;
    for(const auto& q:arr(module(snapshot,"drivers"),"queries"))for(const auto& a:arr(q,"rows")) {
        if(auto i=nic_index(a,nics)) {
            if(a.contains("PNPDeviceID")&&a["PNPDeviceID"].is_string())devices[lower(a["PNPDeviceID"].get<std::string>())].insert(*i);
            if(a.contains("SettingID"))attach(a,q,"ip_configuration");
        }
    }
    for(const auto& q:arr(module(snapshot,"drivers"),"queries"))for(const auto& a:arr(q,"rows"))if(a.contains("DriverVersion")&&a.contains("DeviceID")&&a["DeviceID"].is_string()) {
        auto id=lower(a["DeviceID"].get<std::string>());auto it=devices.find(id);if(it==devices.end())continue;
        for(auto i:it->second){Json copy=a;copy["evidence"]=string_value(q,"source");nics[i]["details"]["drivers"].push_back(copy);}
    }
    for(const auto& a:arr(obj(report,"nic_settings"),"registry"))if(auto i=nic_index(a,nics))nics[*i]["details"]["saved_settings"].push_back(a);
}
struct XmlEvent {Json data=Json::object();std::string provider,id,record,time;};
XmlEvent xml_event(std::string_view xml) {
    need(xml.size()<=line_limit,"Event XML limit exceeded.");
    ComPtr<IStream> stream;stream.Attach(SHCreateMemStream(reinterpret_cast<const BYTE*>(xml.data()),static_cast<UINT>(xml.size())));need(bool(stream),"Cannot create XML memory stream.");
    ComPtr<IXmlReader> reader;check_hr(CreateXmlReader(__uuidof(IXmlReader),reinterpret_cast<void**>(reader.GetAddressOf()),nullptr),"Create XML reader");
    check_hr(reader->SetProperty(XmlReaderProperty_DtdProcessing,DtdProcessing_Prohibit),"Prohibit XML DTD");
    check_hr(reader->SetProperty(XmlReaderProperty_XmlResolver,0),"Disable external XML resolver");
    check_hr(reader->SetProperty(XmlReaderProperty_MaxElementDepth,64),"Bound XML depth");
    check_hr(reader->SetInput(stream.Get()),"Set XML input");
    auto value=[&](){const wchar_t* text=nullptr;UINT length=0;check_hr(reader->GetValue(&text,&length),"Read XML value");return utf8(std::wstring_view(text,length));};
    auto attr=[&](const wchar_t* name){std::string text;if(reader->MoveToAttributeByName(name,nullptr)==S_OK){text=value();reader->MoveToElement();}return text;};
    XmlEvent out;std::string tag,key;bool in_data=false;unsigned index=0;XmlNodeType type{};HRESULT hr;
    while((hr=reader->Read(&type))==S_OK) {
        const wchar_t* name=nullptr;UINT length=0;
        if(type==XmlNodeType_Element) {
            check_hr(reader->GetLocalName(&name,&length),"Read XML name");tag=utf8(std::wstring_view(name,length));
            if(tag=="Provider")out.provider=attr(L"Name");else if(tag=="TimeCreated")out.time=attr(L"SystemTime");
            else if(tag=="Data"){key=attr(L"Name");if(key.empty())key=std::to_string(index);++index;out.data[key]="";in_data=!reader->IsEmptyElement();}
        } else if(type==XmlNodeType_Text||type==XmlNodeType_CDATA) {
            auto text=value();if(in_data)out.data[key]=out.data[key].get<std::string>()+text;
            else if(tag=="EventID")out.id+=text;else if(tag=="EventRecordID")out.record+=text;
        } else if(type==XmlNodeType_EndElement){in_data=false;tag.clear();}
    }
    check_hr(hr,"Parse event XML");need(!out.provider.empty()&&!out.id.empty()&&!out.record.empty()&&!out.time.empty(),"Missing XML event identity.");return out;
}
void notice(Json& report,std::string text) {
    report["incomplete"]=true;if(report["notices"].size()<100)report["notices"].push_back(std::move(text));
    report["notice_count"]=report.value("notice_count",size_t(0))+1;
}
Json evidence(std::string file,size_t line,const Json& event) {
    return {{"file",file},{"line",line},{"time_utc",string_value(event,"time_utc")},{"time_local",string_value(event,"time_local")},{"message",event.value("message",Json(nullptr))}};
}
Handle open_evidence_file(const fs::path& path,uint64_t limit,uint64_t& size) {
    ensure_local_path(path);Handle file(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_SEQUENTIAL_SCAN,nullptr));if(!file)fail_win("Open saved evidence");
    BY_HANDLE_FILE_INFORMATION info{};need(GetFileInformationByHandle(file.get(),&info)!=FALSE,"Cannot inspect saved evidence.");
    need(GetFileType(file.get())==FILE_TYPE_DISK&&!(info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY)),"Evidence must be a regular local file without reparse points.");
    size=(uint64_t(info.nFileSizeHigh)<<32)|info.nFileSizeLow;need(size<=limit,"Saved evidence size limit exceeded.");return file;
}
EvidenceDigest hash_evidence_file(const fs::path& path,uint64_t expected_size,SdkLogParser* parser=nullptr) {
    auto limit=path.filename()==L"sapera-Logs.dat"?kSaperaLogBytes:kUserLogBytes;
    uint64_t size=0;auto file=open_evidence_file(path,limit,size);need(size==expected_size,"Saved log size mismatch.");
    StreamHash hash;hash.limit=limit;hash.parser=parser;std::array<char,65536> buffer{};
    while(hash.bytes<size){DWORD n=0;need(ReadFile(file.get(),buffer.data(),static_cast<DWORD>((std::min)(uint64_t(buffer.size()),size-hash.bytes)),&n,nullptr)!=FALSE&&n>0,"Log read failed or was truncated.");hash.update(buffer.data(),n);}
    return hash.finish();
}
std::string read_evidence_file(const fs::path& path,size_t limit) {
    uint64_t size=0;auto file=open_evidence_file(path,limit,size);
    std::string bytes(static_cast<size_t>(size),'\0');size_t offset=0;
    while(offset<bytes.size()) {
        DWORD n=0;need(ReadFile(file.get(),bytes.data()+offset,static_cast<DWORD>((std::min)(bytes.size()-offset,size_t(65536))),&n,nullptr)!=FALSE&&n>0,"Evidence read failed or was truncated.");offset+=n;
    }
    return bytes;
}
} // namespace

EvidenceFiles load_evidence(const fs::path& input) {
    auto path=canonical_local_path(input);EvidenceFiles files;SdkLogParser parser;Json snapshot;
    auto begin_log=[&](const std::string& name){auto meta=sdk_log_metadata(arr(snapshot,"modules"),name);
        if(mvsdk_log_name(name)&&!meta.contains("copied_bytes"))return false;
        parser.begin(name,string_value(meta,"path",name),meta.value("copied_offset_bytes",uint64_t(0)),meta.value("utf16le_detected",false));return true;};
    if(fs::is_directory(path)) {
        Output lock(path);files["manifest.json"]=read_evidence_file(lock.file("manifest.json"),1024*1024);
        auto manifest=parse_json(files.at("manifest.json"));need(arr(manifest,"files").size()<=255,"Manifest count limit exceeded.");
        snapshot=parse_json(read_evidence_file(lock.file("snapshot.json"),file_limit));
        uint64_t total=0,logs=0,mvsdk=0;
        for(const auto& item:arr(manifest,"files")) {
            auto name=item.at("name").get<std::string>();need(safe_name(name)&&name!="manifest.json","Unsafe manifest name.");
            auto size=item.at("size_bytes").get<uint64_t>();account_size(name,size,total,logs,mvsdk);
            need(!files.contains(name),"Duplicate manifest file.");
            if(sdk_log_name(name)){auto text=begin_log(name);files.streamed_[name]=hash_evidence_file(lock.file(name),size,text?&parser:nullptr);if(text)parser.end();files[name]="";}
            else if(name=="sapera-Logs.dat"){files.streamed_[name]=hash_evidence_file(lock.file(name),size);files[name]="";}
            else files[name]=read_evidence_file(lock.file(name),static_cast<size_t>(size));
        }
    } else {
        Handle file(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_SEQUENTIAL_SCAN,nullptr));if(!file)fail_win("Open diagnostics ZIP");
        BY_HANDLE_FILE_INFORMATION info{};need(GetFileInformationByHandle(file.get(),&info)!=FALSE,"Cannot inspect ZIP input.");
        need(GetFileType(file.get())==FILE_TYPE_DISK&&!(info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY)),"ZIP input must be a regular local file.");
        LARGE_INTEGER size{};need(GetFileSizeEx(file.get(),&size)!=FALSE&&size.QuadPart>=0&&size.QuadPart<=512LL*1024*1024,"ZIP size limit exceeded.");
        auto sidecar=path;sidecar+=L".sha256";
        if(fs::exists(sidecar)){auto checksum=read_evidence_file(sidecar,1024);need(checksum.size()>=64&&lower(checksum.substr(0,64))==sha256(path),"ZIP SHA-256 mismatch.");}
        mz_zip_archive zip{};zip.m_pRead=zip_read;zip.m_pIO_opaque=file.get();need(mz_zip_reader_init(&zip,static_cast<mz_uint64>(size.QuadPart),0)!=0,"Invalid ZIP archive.");
        try {
            auto count=mz_zip_reader_get_num_files(&zip);need(count<=256,"ZIP entry count limit exceeded.");uint64_t total=0,logs=0,mvsdk=0;std::set<std::string> names;
            int snapshot_index=mz_zip_reader_locate_file(&zip,"snapshot.json",nullptr,0);need(snapshot_index>=0,"Missing snapshot.json.");mz_zip_archive_file_stat ss{};
            need(mz_zip_reader_file_stat(&zip,static_cast<mz_uint>(snapshot_index),&ss)!=0&&ss.m_uncomp_size<=file_limit,"Snapshot size limit exceeded.");
            std::string sb(static_cast<size_t>(ss.m_uncomp_size),'\0');need(mz_zip_reader_extract_to_mem(&zip,static_cast<mz_uint>(snapshot_index),sb.data(),sb.size(),0)!=0,"Snapshot extraction failed.");snapshot=parse_json(sb);
            for(mz_uint i=0;i<count;++i) {
                mz_zip_archive_file_stat stat{};need(mz_zip_reader_file_stat(&zip,i,&stat)!=0,"Invalid ZIP entry.");
                std::string name=stat.m_filename;need(safe_name(name)&&!stat.m_is_directory,"ZIP requires flat safe evidence filenames.");
                need(names.insert(lower(name)).second,"Duplicate ZIP filename.");account_size(name,stat.m_uncomp_size,total,logs,mvsdk);
                if(streamed_log_name(name)) {
                    bool text_log=sdk_log_name(name)&&begin_log(name);
                    StreamHash hash;hash.limit=name=="sapera-Logs.dat"?kSaperaLogBytes:kUserLogBytes;hash.parser=text_log?&parser:nullptr;
                    auto ok=mz_zip_reader_extract_to_callback(&zip,i,hash_zip_chunk,&hash,0);
                    if(hash.error)std::rethrow_exception(hash.error);need(ok!=0,"ZIP log extraction/CRC failed.");
                    need(hash.bytes==stat.m_uncomp_size,"ZIP log size mismatch.");files.streamed_[name]=hash.finish();if(text_log)parser.end();files[name]="";continue;
                }
                std::string bytes(static_cast<size_t>(stat.m_uncomp_size),'\0');char dummy=0;
                need(mz_zip_reader_extract_to_mem(&zip,i,bytes.empty()?&dummy:bytes.data(),bytes.size(),0)!=0,"ZIP extraction/CRC failed.");
                files.emplace(name,std::move(bytes));
            }
            mz_zip_reader_end(&zip);
        } catch(...){mz_zip_reader_end(&zip);throw;}
    }
    verify_files(files);files.streamed_sdk_=parser.finish();return files;
}

EventDateFilter event_date_filter(std::string date,std::string offset) {
    need(date.size()==10&&date[4]=='-'&&date[7]=='-',"--date requires YYYY-MM-DD.");
    need(offset.size()==6&&(offset[0]=='+'||offset[0]=='-')&&offset[3]==':',"--utc-offset requires +HH:MM or -HH:MM.");
    for(size_t i=0;i<date.size();++i)if(i!=4&&i!=7)need(date[i]>='0'&&date[i]<='9',"Invalid date.");
    for(auto i:{1,2,4,5})need(offset[i]>='0'&&offset[i]<='9',"Invalid UTC offset.");
    int hours=(offset[1]-'0')*10+offset[2]-'0',minutes=(offset[4]-'0')*10+offset[5]-'0';
    need(hours<=14&&minutes<60&&(hours<14||minutes==0),"UTC offset must be within -14:00..+14:00.");
    auto from=parse_iso_time(date+"T00:00:00"+offset);need(from.has_value(),"Invalid calendar date or unsupported date range.");
    EventDateFilter f;f.date=std::move(date);f.utc_offset=std::move(offset);f.from=*from;f.to=*from+864000000000ULL;
    f.offset_minutes=(hours*60+minutes)*(f.utc_offset[0]=='-'?-1:1);return f;
}
namespace {
std::string selected_time(ULONGLONG ticks,const EventDateFilter& filter) {
    auto shifted=static_cast<int64_t>(ticks)+static_cast<int64_t>(filter.offset_minutes)*600000000LL;
    need(shifted>=0,"Selected time is outside the supported range.");auto value=iso_time(static_cast<ULONGLONG>(shifted));
    if(value.ends_with('Z'))value.pop_back();return value+filter.utc_offset;
}
}
Json analyze_evidence(const EvidenceFiles& files,const std::optional<EventDateFilter>& filter,const std::optional<std::string>& log_offset) {
    verify_files(files);auto s=parse_json(files.at("snapshot.json"));
    need(s.value("schema_version",0)==1,"Unsupported snapshot schema version.");need(s.contains("modules")&&s["modules"].is_array(),"Invalid snapshot modules.");
    Json r={{"schema_version",1},{"incomplete",false},{"notices",Json::array()},{"notice_count",0},{"snapshot",s},{"nics",Json::array()},{"overlaps",Json::array()},
        {"event_channels",Json::array()},{"event_groups",Json::array()},{"links",Json::array()},{"power_events",Json::array()},{"setupapi",Json::array()},
        {"selected_events",Json::array()},{"source_event_count",0},{"source_setupapi_count",0},{"undated_setupapi_count",0},
        {"app_incidents",Json::array()},{"dumps",Json::array()},{"sdk_event_count",0},{"undated_sdk_count",0}};
    r["event_date_filter"]=filter?Json{{"date",filter->date},{"utc_offset",filter->utc_offset},{"from_utc",iso_time(filter->from)},{"to_utc_exclusive",iso_time(filter->to)}}:Json(nullptr);
    for(const auto& warning:arr(s,"report_warnings"))notice(r,"수집 보고서: "+str(warning));
    for(const auto& m:s["modules"])if(string_value(m,"status")!="ok"&&string_value(m,"status")!="empty")notice(r,field(m,"task_id")+": "+field(m,"status")+" — "+json_text(arr(m,"issues")));
    const auto& net=module(s,"network");std::map<unsigned,Json> interfaces;
    size_t filter_count=0;for(const auto& i:arr(net,"interfaces")) {if(i.value("filter_interface",false)){++filter_count;continue;}interfaces[i.at("if_index").get<unsigned>()]=i;}
    r["interface_count"]=arr(net,"interfaces").size();r["filter_count"]=filter_count;
    for(const auto& a:arr(net,"adapters")) {
        if(a.value("filter_interface",false))continue;auto index=a.at("if_index").get<unsigned>();Json row=a;
        row["interface"]=interfaces.contains(index)?interfaces[index]:Json::object();row["state"]=state(row["interface"]);row["ipv4"]=Json::array();
        for(const auto& addr:arr(a,"addresses"))if(auto p=prefix(addr)) {
            Json ip=addr;auto origin=addr.value("prefix_origin",0U);
            ip["assignment"]=origin==1?"Manual":origin==3?"DHCP":origin==2?"WellKnown":"미판정";
            ip["link_local"]=(p->first&0xffff0000U)==0xa9fe0000U;row["ipv4"].push_back(ip);
        }
        r["nics"].push_back(row);
    }
    auto& nics=r["nics"];
    r["nic_settings"]={{"advanced",Json::array()},{"registry",Json::array()}};
    for(const auto& q:arr(module(s,"advanced"),"queries"))for(const auto& a:arr(q,"rows")) {
        auto keyword=string_value(a,"RegistryKeyword");
        if(keyword.empty())notice(r,"NIC 고급 설정의 RegistryKeyword가 미수집/미해석입니다. 원래 조회값은 전체 고급 설정 표에 보존합니다.");
        auto kind=setting_kind(keyword);if(kind.empty())continue;
        Json setting=a;setting["category"]=kind;setting["evidence"]=string_value(q,"source");
        setting_nic(setting,nics,string_value(a,"InstanceID"));r["nic_settings"]["advanced"].push_back(setting);
    }
    for(const auto& key:arr(module(s,"registry"),"keys")) {
        std::string id,description;
        for(const auto& v:arr(key,"values")) {
            auto name=lower(string_value(v,"name"));
            if(name=="netcfginstanceid"&&v.contains("raw_value")&&v["raw_value"].is_string())id=v["raw_value"].get<std::string>();
            if(name=="driverdesc"&&v.contains("raw_value")&&v["raw_value"].is_string())description=v["raw_value"].get<std::string>();
        }
        if(id.empty())continue; // Only NIC class keys with an explicit adapter identity.
        for(const auto& v:arr(key,"values")) {
            auto kind=setting_kind(string_value(v,"name"));if(kind.empty())continue;
            Json setting={{"Name",description},{"InstanceID",id},{"InterfaceDescription",description},{"category",kind},
                {"RegistryKeyword",string_value(v,"name")},{"RegistryValue",v.value("raw_value",Json(nullptr))},
                {"registry_type",v.value("registry_type",Json(nullptr))},{"evidence",string_value(key,"source")}};
            setting_nic(setting,nics,id);r["nic_settings"]["registry"].push_back(setting);
        }
    }
    for(size_t i=0;i<nics.size();++i)for(size_t j=i+1;j<nics.size();++j) {
        if(nics[i]["if_index"]==nics[j]["if_index"])continue;bool overlap=false;
        for(const auto& a:arr(nics[i],"ipv4"))for(const auto& b:arr(nics[j],"ipv4")) {
            auto pa=prefix(a),pb=prefix(b);if(pa&&pb&&pa->second&&pb->second&&((pa->first^pb->first)&mask((std::min)(pa->second,pb->second)))==0)overlap=true;
        }
        if(overlap)r["overlaps"].push_back({{"a",nics[i]["friendly_name"]},{"b",nics[j]["friendly_name"]},{"both_up",nics[i]["state"]=="Up"&&nics[j]["state"]=="Up"}});
    }
    struct Group {size_t count=0;Json example;std::string oldest,newest;};
    struct Link {size_t down=0,up=0;std::map<std::string,std::pair<size_t,size_t>> daily;Json samples=Json::array();std::vector<std::pair<ULONGLONG,int>> ordered;};
    std::map<std::tuple<std::string,std::string,int,int>,Group> groups;
    std::map<std::string,Link> links;size_t event_total=0,line_total=0;std::set<std::string> identities;
    for(const auto& [name,bytes]:files) {
        bool events=name.starts_with("events-")&&name.ends_with(".jsonl"),setup=name=="setupapi-timeline.jsonl";
        if(!events&&!setup)continue;size_t line_number=0,count=0,bad=0,outside=0,valid=0;std::string oldest,newest;std::istringstream input(bytes);std::string line;
        while(std::getline(input,line)) {
            ++line_number;if(line.empty())continue;need(++line_total<=record_limit,"Evidence record count limit exceeded.");
            try {
                need(line.size()<=line_limit,"Evidence line size limit exceeded.");auto e=parse_json(line);need(e.is_object(),"Event must be an object.");
                auto time=e.contains("time_utc")&&e["time_utc"].is_string()?e["time_utc"].get<std::string>():"";auto ticks=parse_iso_time(time);if(events)need(ticks.has_value(),"Invalid event time.");
                if(!setup) {
                    auto xml=xml_event(e.at("xml").get<std::string>());
                    need(xml.provider==e.at("provider").get<std::string>()&&xml.id==str(e.at("event_id"))&&xml.record==str(e.at("record_id")),"XML event identity mismatch.");
                    auto xt=parse_iso_time(xml.time);need(xt&&*xt/10000==*ticks/10000,"XML event time mismatch.");
                    auto identity=string_value(e,"channel",name)+":"+xml.provider+":"+xml.record;
                    if(!identities.insert(identity).second){notice(r,name+":"+std::to_string(line_number)+" 중복 이벤트 제외");++bad;continue;}
                    int id=e.at("event_id").get<int>(),level=e.value("level",0);auto provider=e.at("provider").get<std::string>();
                    ++valid;r["source_event_count"]=r["source_event_count"].get<size_t>()+1;
                    if(filter&&(*ticks<filter->from||*ticks>=filter->to)){++outside;continue;}
                    if(string_value(e,"channel")=="Application"&&((lower(provider)=="application error"&&id==1000)||(lower(provider)=="application hang"&&id==1002)||(lower(provider)=="windows error reporting"&&id==1001)||(lower(provider)==".net runtime"&&id==1026))) {
                        auto value=[&](std::initializer_list<const char*> keys){for(auto key:keys)for(const auto& [name,v]:xml.data.items())if(lower(name)==lower(key)&&v.is_string()&&!v.get<std::string>().empty())return v.get<std::string>();return std::string();};
                        Json incident=evidence(name,line_number,e);incident["provider"]=provider;incident["event_id"]=id;incident["record_id"]=e["record_id"];incident["data"]=xml.data;
                        incident["app_name"]=value({"AppName","ApplicationName","P1","0"});incident["app_path"]=value({"AppPath","ApplicationPath"});incident["app_version"]=value({"AppVersion","P2"});
                        incident["module_name"]=value({"ModuleName","FaultingModuleName","P4"});incident["module_path"]=value({"ModulePath"});incident["exception_code"]=value({"ExceptionCode","P7"});
                        incident["pid"]=value({"ProcessId","AppProcessId"});incident["report_id"]=value({"ReportId","IntegratorReportId"});incident["related_records"]=Json::array();r["app_incidents"].push_back(std::move(incident));
                    }
                    auto& g=groups[{name,provider,id,level}];++g.count;
                    if(g.newest.empty()||time>g.newest){g.newest=time;g.example=evidence(name,line_number,e);}if(g.oldest.empty()||time<g.oldest)g.oldest=time;
                    // PC power transitions take every NIC down; diagnosis uses them to separate PC-side link drops.
                    std::string power=provider=="Microsoft-Windows-Kernel-General"?(id==12?"boot":id==13?"shutdown":""):provider=="Microsoft-Windows-Kernel-Power"?(id==41?"unexpected":id==42?"sleep":id==107?"resume":""):
                        provider=="EventLog"&&id==6008?"unexpected":provider=="Microsoft-Windows-Power-Troubleshooter"&&id==1?"resume":"";
                    if(!power.empty()&&r["power_events"].size()<2000)r["power_events"].push_back({{"time_utc",time},{"kind",power}});
                    bool intel=provider=="e1rexpress"||provider=="e2fnexpress";
                    int action=intel&&id==27?-1:intel&&id==32?1:provider=="aqnic650"&&id==14?-1:0;
                    if(action) {
                        std::string device;
                        std::set<size_t> candidates;
                        for(const auto& v:xml.data.items())for(size_t i=0;i<nics.size();++i)
                            if(v.value().is_string()&&!v.value().get<std::string>().empty()&&v.value()==string_value(nics[i],"description"))candidates.insert(i);
                        if(candidates.size()==1)device=string_value(nics[*candidates.begin()],"friendly_name");
                        if(candidates.size()>1) {
                            device="모호한 NIC: "+provider;Json names=Json::array();for(auto i:candidates)names.push_back(field(nics[i],"friendly_name"));
                            if(!r.contains("ambiguous_link_nics"))r["ambiguous_link_nics"]=Json::object();r["ambiguous_link_nics"][device]=names;
                        }
                        if(device.empty())device="미매핑: "+provider;
                        auto& link=links[device];if(action<0)++link.down;else ++link.up;
                        auto day=string_value(e,"time_local",time).substr(0,10);if(action<0)++link.daily[day].first;else ++link.daily[day].second;
                        link.ordered.emplace_back(*ticks,action);if(link.samples.size()<6){auto sample=evidence(name,line_number,e);sample["action"]=action<0?"분리":"설정";link.samples.push_back(sample);}
                    }
                    ++event_total;
                } else {
                    ++valid;r["source_setupapi_count"]=r["source_setupapi_count"].get<size_t>()+1;
                    if(filter&&!ticks){r["undated_setupapi_count"]=r["undated_setupapi_count"].get<size_t>()+1;continue;}
                    if(filter&&(*ticks<filter->from||*ticks>=filter->to)){++outside;continue;}
                    auto sample=evidence(name,line_number,e);sample["message"]=e.value("message",Json(nullptr));r["setupapi"].push_back(sample);
                }
                if(filter)r["selected_events"].push_back({{"kind",events?"event":"setupapi"},{"source_file",name},{"source_line",line_number},{"time_selected",selected_time(*ticks,*filter)},{"record",e}});
                ++count;if(!time.empty()){if(oldest.empty()||time<oldest)oldest=time;if(newest.empty()||time>newest)newest=time;}
            } catch(const std::exception& ex) {++bad;notice(r,name+":"+std::to_string(line_number)+" 분석 제외: "+ex.what());}
        }
        if(events)r["event_channels"].push_back({{"file",name},{"count",count},{"valid_source_count",valid},{"outside_date",outside},{"excluded",bad},{"oldest",oldest},{"newest",newest}});
    }
    r["event_count"]=event_total;
    for(const auto& [key,g]:groups)r["event_groups"].push_back({{"file",std::get<0>(key)},{"provider",std::get<1>(key)},{"id",std::get<2>(key)},{"level",std::get<3>(key)},
        {"count",g.count},{"oldest",g.oldest},{"newest",g.newest},{"example",g.example}});
    std::sort(r["event_groups"].begin(),r["event_groups"].end(),[](const auto& a,const auto& b){return a["count"].template get<size_t>()>b["count"].template get<size_t>();});
    for(auto& [name,link]:links) {
        std::sort(link.ordered.begin(),link.ordered.end());std::vector<double> durations;
        for(size_t i=1;i<link.ordered.size();++i)if(link.ordered[i-1].second==-1&&link.ordered[i].second==1)durations.push_back(double(link.ordered[i].first-link.ordered[i-1].first)/10000000.0);
        std::sort(durations.begin(),durations.end());Json daily=Json::array();for(const auto& [day,n]:link.daily)daily.push_back({{"day",day},{"down",n.first},{"up",n.second}});
        Json median=nullptr;if(!durations.empty()){auto k=durations.size()/2;median=durations.size()%2?durations[k]:(durations[k-1]+durations[k])/2;}
        Json times=Json::array();for(const auto& [ticks,action]:link.ordered){if(times.size()>=20000)break;times.push_back({{"time_utc",iso_time(ticks)},{"action",action<0?"down":"up"}});}
        r["links"].push_back({{"name",name},{"down",link.down},{"up",link.up},{"pairs",durations.size()},{"median_s",median},{"daily",daily},{"samples",link.samples},{"times",times}});
    }
    std::optional<std::string> sdk_offset=log_offset;if(!sdk_offset){const auto& saved=obj(s,"inputs");if(saved.contains("log_utc_offset")&&saved["log_utc_offset"].is_string())sdk_offset=saved["log_utc_offset"].get<std::string>();}
    if(sdk_offset)utc_offset_minutes(*sdk_offset);Json sdk_events=Json::array(),sdk_sources=Json::array();
    // Prefer a fresh parse of the verified raw logs so older bundles benefit from parser improvements.
    bool fresh=files.streamed_sdk().is_object()&&!arr(files.streamed_sdk(),"sources").empty();
    if(files.contains("sdk-events.jsonl")&&!fresh) {
        need(files.at("sdk-events.jsonl").size()<=kSdkEventBytes,"SDK derived event byte limit exceeded.");std::istringstream stream(files.at("sdk-events.jsonl"));std::string line;size_t count=0;
        while(std::getline(stream,line)){if(line.empty())continue;need(++count<=kSdkEventCount,"SDK derived event count limit exceeded.");
            try{auto e=parse_json(line);need(e.is_object()&&e.contains("fields")&&e["fields"].is_object()&&e.contains("source_line")&&e["source_line"].is_number_unsigned(),"Invalid SDK record.");
                auto source=e.at("source_file").get<std::string>();need(sdk_log_name(source)&&files.contains(source),"Missing SDK source file.");
                auto digest=files.streamed_digests().find(source);auto size=digest==files.streamed_digests().end()?files.at(source).size():digest->second.size_bytes;
                auto meta=sdk_log_metadata(arr(s,"modules"),source);need(!mvsdk_log_name(source)||meta.contains("copied_bytes"),"Missing MVSDK source metadata.");uint64_t base=meta.value("copied_offset_bytes",uint64_t(0));
                need(e.contains("source_byte_offset")&&e["source_byte_offset"].is_number_unsigned(),"Invalid SDK byte offset.");auto at=e.at("source_byte_offset").get<uint64_t>();need(at>=base&&at-base<=size,"SDK source offset outside copied log.");
                for(auto key:{"kind","original_timestamp","pid","thread_id","level","message"})need(e.contains(key)&&e[key].is_string(),"Invalid SDK text field.");sdk_events.push_back(std::move(e));
            }catch(const std::exception& ex){notice(r,"sdk-events.jsonl 분석 제외: "+std::string(ex.what()));}
        }
        if(files.contains("sdk-summary.json")){auto summary=parse_json(files.at("sdk-summary.json"));sdk_sources=arr(summary,"sources");if(summary.value("truncated",false))notice(r,"SDK 구조화 기록이 수집 한도 또는 로그 꼬리 범위로 제한되었습니다.");}
    } else if(files.streamed_sdk().is_object()){sdk_events=arr(files.streamed_sdk(),"events");sdk_sources=arr(files.streamed_sdk(),"sources");if(files.streamed_sdk().value("truncated",false))notice(r,"SDK 로그의 긴 행·부분 꼬리·건수/크기 한도로 일부 기록이 제외되었습니다.");}
    else {
        SdkLogParser parser;for(const auto& [name,bytes]:files)if(sdk_log_name(name)) {auto meta=sdk_log_metadata(arr(s,"modules"),name);
            if(mvsdk_log_name(name)&&!meta.contains("copied_bytes"))continue;
            parser.begin(name,string_value(meta,"path",name),meta.value("copied_offset_bytes",uint64_t(0)),meta.value("utf16le_detected",false));parser.feed(bytes);parser.end();}
        auto summary=parser.finish();sdk_events=summary["events"];sdk_sources=summary["sources"];if(summary.value("truncated",false))notice(r,"SDK 로그 구조화 한도로 일부 기록이 제외되었습니다.");
    }
    r["sdk"]=sdk_summary(sdk_events,sdk_sources,sdk_offset);r["source_sdk_event_count"]=sdk_events.size();
    for(auto e:arr(r["sdk"],"events")) {
        auto ticks=parse_iso_time(string_value(e,"time_utc"));if(!ticks){r["undated_sdk_count"]=r["undated_sdk_count"].get<size_t>()+1;if(filter)continue;}
        if(filter&&ticks&&(*ticks<filter->from||*ticks>=filter->to))continue;r["sdk_event_count"]=r["sdk_event_count"].get<size_t>()+1;
        if(filter){e["time_local"]=e["original_timestamp"];e["channel"]="SDK";e["provider"]=e["kind"];r["selected_events"].push_back({{"kind","sdk"},{"source_file",e["source_file"]},{"source_line",e["source_line"]},{"time_selected",selected_time(*ticks,*filter)},{"record",e}});}
    }
    if(filter&&r["undated_sdk_count"].get<size_t>())notice(r,"UTC 시각이 미확정인 SDK 기록 "+field(r,"undated_sdk_count")+"개는 날짜 추출에서 제외했습니다. --log-utc-offset으로 원본 로그의 오프셋을 지정할 수 있습니다.");
    for(const auto& [name,bytes]:files)if(name.starts_with("dump-")&&name.ends_with("-metadata.json")){try{auto dump=parse_json(bytes);need(dump.is_object()&&dump.contains("exception_stream_present")&&dump["exception_stream_present"].is_boolean(),"Invalid dump metadata.");dump["evidence_file"]=name;r["dumps"].push_back(std::move(dump));}catch(const std::exception& ex){notice(r,name+": "+ex.what());}}
    auto normalized_pid=[](std::string p){try{size_t used=0;auto n=std::stoull(p,&used,p.starts_with("0x")?16:10);if(used==p.size())return std::to_string(n);}catch(...){}return lower(p);};
    std::map<std::string,std::vector<size_t>> report_index,pid_index;
    for(size_t i=0;i<r["app_incidents"].size();++i){auto& a=r["app_incidents"][i];auto id=lower(string_value(a,"report_id")),pid=normalized_pid(string_value(a,"pid")),app=lower(string_value(a,"app_name"));std::map<size_t,std::string> candidates;
        bool valid_id=!id.empty()&&id!="00000000-0000-0000-0000-000000000000"&&id!="{00000000-0000-0000-0000-000000000000}";
        if(valid_id)for(auto j:report_index[id])candidates[j]="ReportID";
        auto key=app+":"+pid;auto at=parse_iso_time(string_value(a,"time_utc"));
        if(!app.empty()&&!pid.empty()&&pid!="0")for(auto j:pid_index[key]){auto bt=parse_iso_time(string_value(r["app_incidents"][j],"time_utc"));if(at&&bt&&(*at>*bt?*at-*bt:*bt-*at)<=3000000000ULL&&!candidates.contains(j))candidates[j]="app/PID within 5 minutes";}
        for(const auto& [j,basis]:candidates){auto& b=r["app_incidents"][j];if(a["related_records"].size()<8)a["related_records"].push_back({{"file",b["file"]},{"line",b["line"]},{"basis",basis}});if(b["related_records"].size()<8)b["related_records"].push_back({{"file",a["file"]},{"line",a["line"]},{"basis",basis}});}
        auto remember=[&](auto& index,const std::string& k){auto& ids=index[k];ids.push_back(i);if(ids.size()>8)ids.erase(ids.begin());};
        if(valid_id)remember(report_index,id);if(!app.empty()&&!pid.empty()&&pid!="0")remember(pid_index,key);
    }
    r["external_attachments"]=arr(parse_json(files.at("manifest.json")),"external_attachments");
    if(filter) {
        std::sort(r["selected_events"].begin(),r["selected_events"].end(),[](const auto& a,const auto& b){return std::tuple{*parse_iso_time(a.at("record").at("time_utc").template get<std::string>()),a.at("source_file").template get<std::string>(),a.at("source_line").template get<size_t>()}<std::tuple{*parse_iso_time(b.at("record").at("time_utc").template get<std::string>()),b.at("source_file").template get<std::string>(),b.at("source_line").template get<size_t>()};});
        if(r["undated_setupapi_count"].get<size_t>())notice(r,"시각이 없는 SetupAPI 기록 "+field(r,"undated_setupapi_count")+"개는 날짜 추출에서 제외했습니다.");
    }
    nic_details(r,s);
    for(const auto& n:nics)if(filter_counts(n).unknown)notice(r,field(n,"friendly_name")+": 필터 활성 여부 미확인 "+std::to_string(filter_counts(n).unknown)+"개 — 비활성으로 간주하지 않습니다.");
    if(r.contains("ambiguous_link_nics"))notice(r,"동일한 설명을 가진 NIC의 링크 이벤트는 특정 NIC에 연결하지 않았습니다. 모호한 NIC 후보를 링크 이력에서 확인하십시오.");
    r["diagnosis"]=diagnose(r);
    return r;
}

std::string selected_events_jsonl(const Json& report) {
    std::string bytes;for(const auto& row:arr(report,"selected_events")){bytes+=json_text(row)+"\n";need(bytes.size()<=file_limit,"Selected JSONL export exceeds 64 MiB.");}return bytes;
}
std::string selected_events_csv(const Json& report) {
    std::string bytes="\xef\xbb\xbf" "kind,time_selected,time_utc,time_local_original,channel,provider,event_id,level,record_id,message,source_file,source_line\r\n";
    for(const auto& row:arr(report,"selected_events")) {
        const auto& e=obj(row,"record");bool first=true;
        for(auto value:{field(row,"kind"),field(row,"time_selected"),field(e,"time_utc"),field(e,"time_local"),field(e,"channel"),field(e,"provider"),field(e,"event_id"),field(e,"level"),field(e,"record_id"),field(e,"message"),field(row,"source_file"),field(row,"source_line")}){if(!first)bytes+=',';first=false;bytes+=csv_cell(value);}
        bytes+="\r\n";need(bytes.size()<=file_limit,"Selected CSV export exceeds 64 MiB.");
    }return bytes;
}

int analyze_main(const std::vector<std::wstring>& args) {
    if(args.size()==2&&args[1]==L"--help") {
        console_text("Usage: FetchNetworkConfig.exe analyze <result-folder-or-zip> [--output <existing local folder>]\n"
            "       [--date YYYY-MM-DD] [--utc-offset +HH:MM|-HH:MM] (default +09:00)\n"
            "       [--log-utc-offset +HH:MM|-HH:MM] (explicit SDK source timezone)\n"
            "       [--ai-review <ai-review.json>] (merge an LLM opinion made by tools/ai-review.ps1)\n"
            "No administrator/Python required. Reads saved evidence only. Writes analysis.html,\n"
            "findings.json (rule-based GigE diagnosis) and llm-context.json (masked context) in a new folder.\n"
            "With --date, also exports selected-events.csv and selected-events.jsonl with original file/line references.\n"
            "Default output: beside this EXE. Exit 0 complete, 1 partial evidence, 2 invalid input/output.\n");return 0;
    }
    need(args.size()>=2,"Usage: analyze <result-folder-or-zip> [--output <folder>] [--date YYYY-MM-DD] [--utc-offset +HH:MM|-HH:MM]");
    fs::path parent_path=executable_path().parent_path();std::string date,offset="+09:00";std::optional<std::string> log_offset;std::optional<fs::path> ai_path;std::set<std::wstring> seen;
    for(size_t i=2;i<args.size();i+=2) {
        const auto& key=args[i];need(key==L"--output"||key==L"--date"||key==L"--utc-offset"||key==L"--log-utc-offset"||key==L"--ai-review","Unknown analyze option.");
        need(seen.insert(key).second&&i+1<args.size(),"Duplicate option or missing option value.");
        if(key==L"--output")parent_path=args[i+1];else if(key==L"--ai-review")ai_path=args[i+1];else if(key==L"--date")date=utf8(args[i+1]);else if(key==L"--log-utc-offset"){log_offset=utf8(args[i+1]);utc_offset_minutes(*log_offset);}else offset=utf8(args[i+1]);
    }
    need(!seen.contains(L"--utc-offset")||seen.contains(L"--date"),"--utc-offset requires --date.");
    std::optional<EventDateFilter> filter;if(seen.contains(L"--date"))filter=event_date_filter(date,offset);
    auto input=canonical_local_path(args[1]);auto parent=canonical_local_path(parent_path);need(fs::is_directory(parent),"--output must be an existing local directory.");
    if(fs::is_directory(input)) {
        auto input_copy=input,parent_copy=parent;input_copy.make_preferred();parent_copy.make_preferred();
        auto base=input_copy.native(),target=parent_copy.native();
        auto same=[](std::wstring_view a,std::wstring_view b){return a.size()==b.size()&&CompareStringOrdinal(a.data(),static_cast<int>(a.size()),b.data(),static_cast<int>(b.size()),TRUE)==CSTR_EQUAL;};
        bool inside=same(base,target);if(!base.empty()&&base.back()!=L'\\')base+=L'\\';
        inside=inside||(target.size()>=base.size()&&same(std::wstring_view(target).substr(0,base.size()),base));
        need(!inside,"Analysis output must be outside the evidence directory.");
    }
    Json ai_review;if(ai_path)ai_review=validate_ai_review(parse_json(read_evidence_file(canonical_local_path(*ai_path),1024*1024)));
    console_text("저장된 증거 무결성 확인 및 분석 중...\n");auto files=load_evidence(input);auto report=analyze_evidence(files,filter,log_offset);
    if(ai_path)report["ai_review"]=ai_review;auto html=analysis_html(report);
    auto findings=json_text(report.at("diagnosis"),2)+"\n",context=json_text(llm_context(report),2)+"\n";
    std::string csv,jsonl;if(filter){csv=selected_events_csv(report);jsonl=selected_events_jsonl(report);}
    auto root=Output::create_run(parent,"FetchNetworkAnalysis-");Output output(root);output.write("analysis.html",html);output.write("findings.json",findings);output.write("llm-context.json",context);
    if(filter){output.write("selected-events.csv",csv);output.write("selected-events.jsonl",jsonl);console_text("추출 날짜: "+date+" UTC"+offset+" / Windows 이벤트 "+field(report,"event_count")+"개, SetupAPI "+std::to_string(arr(report,"setupapi").size())+"개, SDK "+field(report,"sdk_event_count")+"개 (UTC 미확정 제외 "+field(report,"undated_sdk_count")+"개)\n");}
    const auto& d=report.at("diagnosis");const auto& counts=obj(d,"counts");
    console_text("종합 판정: "+field(d,"overall")+" (심각 "+field(counts,"critical")+", 주의 "+field(counts,"warning")+", 판단 불가 "+field(counts,"unknown")+") — "+field(d,"headline")+"\n");
    console_text("분석 보고서: "+utf8(output.file("analysis.html").native())+"\n"
        "이벤트 "+field(report,"event_count")+"개 / "+(report.at("incomplete").get<bool>()?"일부 수집/증거 누락 있음":"접근 가능한 증거 분석 완료")+"\n");
    return report.at("incomplete").get<bool>()?1:0;
}
} // namespace fnc
