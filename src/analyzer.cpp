#include "analyzer.hpp"
#include "sdk_logs.hpp"
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
namespace {
constexpr size_t file_limit=64*1024*1024, total_limit=256*1024*1024;
constexpr size_t record_limit=100000, line_limit=1024*1024;
const Json empty_array=Json::array(), empty_object=Json::object();
void need(bool condition,std::string_view message) {if(!condition)throw std::runtime_error(std::string(message));}
std::string string_value(const Json& row,std::string_view key,std::string fallback={}) {
    auto it=row.find(std::string(key));return it!=row.end()&&it->is_string()?it->get<std::string>():fallback;
}
std::optional<bool> boolean_value(const Json& row,std::string_view key) {
    auto it=row.find(std::string(key));if(it!=row.end()&&it->is_boolean())return it->get<bool>();return {};
}
bool user_log_name(std::string_view name) {
    for(size_t i=1;i<=kUserLogCount;++i)if(name=="user-log-"+std::to_string(i)+".log")return true;return false;
}
bool streamed_log_name(std::string_view name) {return user_log_name(name)||name=="sapera-Logs.dat";}
void account_size(std::string_view name,uint64_t size,uint64_t& retained,uint64_t& logs) {
    if(name=="manifest.json"){need(size<=1024*1024,"Manifest size limit exceeded.");return;}
    if(user_log_name(name)) {
        need(size<=kUserLogBytes&&size<=kUserLogBytes*kUserLogCount-logs,"User log size limit exceeded.");logs+=size;
    } else {
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
std::string str(const Json& v) {return v.is_null()?"—":v.is_string()?v.get<std::string>():json_text(v);}
std::string field(const Json& v,std::string_view key) {
    auto it=v.find(std::string(key));return it==v.end()?"—":str(*it);
}
const Json& arr(const Json& v,std::string_view key) {
    auto it=v.find(std::string(key));return it!=v.end()&&it->is_array()?*it:empty_array;
}
const Json& obj(const Json& v,std::string_view key) {
    auto it=v.find(std::string(key));return it!=v.end()&&it->is_object()?*it:empty_object;
}
const Json& module(const Json& snapshot,std::string_view id) {
    for(const auto& m:arr(snapshot,"modules"))if(string_value(m,"task_id")==id)return m;return empty_object;
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
    std::set<std::string> seen;uint64_t total=0,logs=0;
    for(const auto& item:manifest["files"]) {
        auto name=item.at("name").get<std::string>();need(safe_name(name)&&name!="manifest.json","Unsafe manifest name.");
        need(seen.insert(lower(name)).second,"Duplicate manifest filename.");
        auto it=files.find(name);need(it!=files.end(),"Manifest evidence file is missing: "+name);
        auto streamed=files.streamed_digests().find(name);EvidenceDigest digest;
        if(streamed!=files.streamed_digests().end()) {
            need(streamed_log_name(name)&&it->second.empty(),"Invalid streamed evidence.");digest=streamed->second;
        } else digest={it->second.size(),sha256_bytes(it->second)};
        account_size(name,digest.size_bytes,total,logs);
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
std::string esc(std::string_view text) {
    std::string out;out.reserve(text.size());
    for(char c:text)switch(c){case '&':out+="&amp;";break;case '<':out+="&lt;";break;case '>':out+="&gt;";break;case '"':out+="&quot;";break;case '\'':out+="&#39;";break;default:out+=c;}
    return out;
}
std::string state(const Json& i) {
    static const char* names[]={"Unknown","Up","Down","Testing","Unknown","Dormant","NotPresent","LowerLayerDown"};
    auto n=i.value("oper_status",0U);return n<8?names[n]:"Unknown";
}
std::optional<std::pair<uint32_t,unsigned>> prefix(const Json& a) {
    if(!a.contains("address")||!a["address"].is_string())return {};
    auto n=a.value("prefix_length",255U);if(n>32)return {};IN_ADDR ip{};auto s=wide(a["address"].get<std::string>());
    if(InetPtonW(AF_INET,s.c_str(),&ip)!=1)return {};return std::pair{ntohl(ip.S_un.S_addr),n};
}
uint32_t mask(unsigned n){return n?0xffffffffU<<(32-n):0;}
std::string power_value(const Json& row,const char* key) {
    if(!row.contains(key)||row[key].is_null())return "미수집";
    if(!row[key].is_number_unsigned()&&!row[key].is_number_integer())return "미해석 ("+str(row[key])+")";
    auto n=row[key].get<int64_t>();return n==0?"Unsupported (0)":n==1?"Disabled (1)":n==2?"Enabled (2)":n==3&&std::string_view(key)=="DeviceSleepOnDisconnect"?"Inactive (3)":"미해석 ("+std::to_string(n)+")";
}
std::string setting_kind(std::string keyword) {
    keyword=lower(keyword);
    if(keyword.find("jumbo")!=std::string::npos)return "Jumbo Packet";
    if(keyword=="pnpcapabilities")return "전원·EEE·Wake";
    for(auto term:{"eee","energy","greenethernet","power","suspend","sleep","wake","dmac","autodisablegigabit"})
        if(keyword.find(term)!=std::string::npos)return "전원·EEE·Wake";
    return {};
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
std::string list_text(const Json& row,const char* key) {
    const auto& values=arr(row,key);if(values.empty())return "기록 없음";std::string out;
    for(const auto& v:values){if(!out.empty())out+='\n';out+=str(v);}return out;
}
std::string speed_text(const Json& row,const char* key) {
    if(!row.contains(key)||!row[key].is_number())return "미수집";
    auto n=row[key].get<uint64_t>();std::ostringstream out;
    if(n==UINT64_MAX)return "미확인 (NDIS_LINK_SPEED_UNKNOWN)";
    if(n>=1000000000ULL)out<<double(n)/1000000000.0<<" Gbps";
    else if(n>=1000000ULL)out<<double(n)/1000000.0<<" Mbps";
    else out<<n<<" bps";return out.str();
}
std::string mask_text(const Json& address) {
    auto p=prefix(address);if(!p)return "—";auto m=mask(p->second);
    return std::to_string(m>>24)+"."+std::to_string((m>>16)&255)+"."+std::to_string((m>>8)&255)+"."+std::to_string(m&255);
}
std::string assignment_text(const Json& address) {
    auto n=address.value("prefix_origin",0U);return n==1?"수동 (Manual)":n==3?"DHCP":n==2?"WellKnown":"미판정";
}
struct FilterCounts {size_t enabled=0,total=0,unknown=0;};
FilterCounts filter_counts(const Json& nic) {
    FilterCounts counts;
    for(const auto& a:arr(obj(nic,"details"),"bindings"))if(string_value(a,"ComponentClassName")=="Filter") {
        ++counts.total;auto enabled=boolean_value(a,"Enabled");if(!enabled)++counts.unknown;else if(*enabled)++counts.enabled;
    }
    return counts;
}
bool core_setting(const Json& row) {
    auto key=lower(string_value(row,"RegistryKeyword"));if(!setting_kind(key).empty())return true;
    if(key.starts_with('*'))key.erase(0,1);
    for(auto k:{"speedduplex","receivebuffers","transmitbuffers","interruptmoderation","rss","numrssqueues","flowcontrol"})if(key==k)return true;
    return false;
}
std::string setting_value(const Json& row) {
    if(!row.contains("RegistryValue"))return "—";
    const auto& values=row["RegistryValue"];if(!values.is_array())return str(values);
    std::string out;for(const auto& v:values){if(!out.empty())out+=", ";out+=str(v);}return out.empty()?"—":out;
}
std::string driver_date(const Json& row) {
    auto date=field(row,"DriverDate");if(date.size()<8)return date;
    for(size_t i=0;i<8;++i)if(date[i]<'0'||date[i]>'9')return date;
    return date.substr(0,4)+"-"+date.substr(4,2)+"-"+date.substr(6,2);
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
std::string reference(const Json& e) {return field(e,"file")+":"+field(e,"line");}
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
    auto begin_log=[&](const std::string& name){std::string original=name;uint64_t base=0;bool utf16=false;
        for(const auto& m:arr(snapshot,"modules"))if(std::find(arr(m,"artifacts").begin(),arr(m,"artifacts").end(),Json(name))!=arr(m,"artifacts").end()) {
            const auto& meta=obj(m,"file_metadata");original=string_value(meta,"path",name);base=meta.value("copied_offset_bytes",uint64_t(0));utf16=meta.value("utf16le_detected",false);break;
        }parser.begin(name,original,base,utf16);};
    if(fs::is_directory(path)) {
        Output lock(path);files["manifest.json"]=read_evidence_file(lock.file("manifest.json"),1024*1024);
        auto manifest=parse_json(files.at("manifest.json"));need(arr(manifest,"files").size()<=255,"Manifest count limit exceeded.");
        snapshot=parse_json(read_evidence_file(lock.file("snapshot.json"),file_limit));
        uint64_t total=0,logs=0;
        for(const auto& item:arr(manifest,"files")) {
            auto name=item.at("name").get<std::string>();need(safe_name(name)&&name!="manifest.json","Unsafe manifest name.");
            auto size=item.at("size_bytes").get<uint64_t>();account_size(name,size,total,logs);
            need(!files.contains(name),"Duplicate manifest file.");
            if(user_log_name(name)){begin_log(name);files.streamed_[name]=hash_evidence_file(lock.file(name),size,&parser);parser.end();files[name]="";}
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
            auto count=mz_zip_reader_get_num_files(&zip);need(count<=256,"ZIP entry count limit exceeded.");uint64_t total=0,logs=0;std::set<std::string> names;
            int snapshot_index=mz_zip_reader_locate_file(&zip,"snapshot.json",nullptr,0);need(snapshot_index>=0,"Missing snapshot.json.");mz_zip_archive_file_stat ss{};
            need(mz_zip_reader_file_stat(&zip,static_cast<mz_uint>(snapshot_index),&ss)!=0&&ss.m_uncomp_size<=file_limit,"Snapshot size limit exceeded.");
            std::string sb(static_cast<size_t>(ss.m_uncomp_size),'\0');need(mz_zip_reader_extract_to_mem(&zip,static_cast<mz_uint>(snapshot_index),sb.data(),sb.size(),0)!=0,"Snapshot extraction failed.");snapshot=parse_json(sb);
            for(mz_uint i=0;i<count;++i) {
                mz_zip_archive_file_stat stat{};need(mz_zip_reader_file_stat(&zip,i,&stat)!=0,"Invalid ZIP entry.");
                std::string name=stat.m_filename;need(safe_name(name)&&!stat.m_is_directory,"ZIP requires flat safe evidence filenames.");
                need(names.insert(lower(name)).second,"Duplicate ZIP filename.");account_size(name,stat.m_uncomp_size,total,logs);
                if(streamed_log_name(name)) {
                    bool text_log=user_log_name(name);if(text_log)begin_log(name);
                    StreamHash hash;hash.limit=text_log?kUserLogBytes:kSaperaLogBytes;hash.parser=text_log?&parser:nullptr;
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
        {"event_channels",Json::array()},{"event_groups",Json::array()},{"links",Json::array()},{"setupapi",Json::array()},
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
        r["links"].push_back({{"name",name},{"down",link.down},{"up",link.up},{"pairs",durations.size()},{"median_s",median},{"daily",daily},{"samples",link.samples}});
    }
    std::optional<std::string> sdk_offset=log_offset;if(!sdk_offset){const auto& saved=obj(s,"inputs");if(saved.contains("log_utc_offset")&&saved["log_utc_offset"].is_string())sdk_offset=saved["log_utc_offset"].get<std::string>();}
    if(sdk_offset)utc_offset_minutes(*sdk_offset);Json sdk_events=Json::array(),sdk_sources=Json::array();
    if(files.contains("sdk-events.jsonl")) {
        need(files.at("sdk-events.jsonl").size()<=kSdkEventBytes,"SDK derived event byte limit exceeded.");std::istringstream stream(files.at("sdk-events.jsonl"));std::string line;size_t count=0;
        while(std::getline(stream,line)){if(line.empty())continue;need(++count<=kSdkEventCount,"SDK derived event count limit exceeded.");
            try{auto e=parse_json(line);need(e.is_object()&&e.contains("fields")&&e["fields"].is_object()&&e.contains("source_line")&&e["source_line"].is_number_unsigned(),"Invalid SDK record.");
                auto source=e.at("source_file").get<std::string>();need(user_log_name(source)&&files.contains(source),"Missing SDK source file.");
                auto digest=files.streamed_digests().find(source);auto size=digest==files.streamed_digests().end()?files.at(source).size():digest->second.size_bytes;
                uint64_t base=0;for(const auto& m:arr(s,"modules"))if(std::find(arr(m,"artifacts").begin(),arr(m,"artifacts").end(),Json(source))!=arr(m,"artifacts").end())base=obj(m,"file_metadata").value("copied_offset_bytes",uint64_t(0));
                need(e.contains("source_byte_offset")&&e["source_byte_offset"].is_number_unsigned(),"Invalid SDK byte offset.");auto at=e.at("source_byte_offset").get<uint64_t>();need(at>=base&&at-base<=size,"SDK source offset outside copied log.");
                for(auto key:{"kind","original_timestamp","pid","thread_id","level","message"})need(e.contains(key)&&e[key].is_string(),"Invalid SDK text field.");sdk_events.push_back(std::move(e));
            }catch(const std::exception& ex){notice(r,"sdk-events.jsonl 분석 제외: "+std::string(ex.what()));}
        }
        if(files.contains("sdk-summary.json")){auto summary=parse_json(files.at("sdk-summary.json"));sdk_sources=arr(summary,"sources");if(summary.value("truncated",false))notice(r,"SDK 구조화 기록이 수집 한도 또는 로그 꼬리 범위로 제한되었습니다.");}
    } else if(files.streamed_sdk().is_object()){sdk_events=arr(files.streamed_sdk(),"events");sdk_sources=arr(files.streamed_sdk(),"sources");if(files.streamed_sdk().value("truncated",false))notice(r,"SDK 로그의 긴 행·부분 꼬리·건수/크기 한도로 일부 기록이 제외되었습니다.");}
    else {
        SdkLogParser parser;for(const auto& [name,bytes]:files)if(user_log_name(name)) {std::string original=name;uint64_t base=0;bool utf16=false;
            for(const auto& m:arr(s,"modules"))if(std::find(arr(m,"artifacts").begin(),arr(m,"artifacts").end(),Json(name))!=arr(m,"artifacts").end()){const auto& meta=obj(m,"file_metadata");original=string_value(meta,"path",name);base=meta.value("copied_offset_bytes",uint64_t(0));utf16=meta.value("utf16le_detected",false);}
            parser.begin(name,original,base,utf16);parser.feed(bytes);parser.end();}
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

std::string analysis_html(const Json& r) {
    const auto& s=r.at("snapshot");const auto& net=module(s,"network");std::ostringstream h;
    h<<R"(<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-fnc-analyze'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>네트워크 구성 분석</title><style>
body{font:15px/1.6 system-ui,sans-serif;color:#172635;background:#f3f6f9;margin:0}main{max-width:1280px;margin:auto;padding:28px}
h1{font-size:28px;margin-bottom:4px}h2{margin:32px 0 12px;font-size:21px}h3{margin-bottom:8px}p{margin:8px 0}.muted{color:#526576}
.card{background:white;border:1px solid #dbe4eb;border-radius:12px;padding:18px;margin:12px 0}.alert{border-left:5px solid #b35c00;background:#fff7e8}
.scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;vertical-align:top;padding:9px 12px;border-bottom:1px solid #e2e8ee;white-space:pre-wrap;overflow-wrap:anywhere}
th{background:#eaf0f5}td{min-width:70px;max-width:420px}.controls{position:sticky;top:0;background:#f3f6f9;padding:12px 0;z-index:1;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
input{padding:10px 14px;border:1px solid #abbaca;border-radius:8px;min-width:270px;font:inherit}button{padding:10px 16px;border:1px solid #abbaca;border-radius:8px;background:white;cursor:pointer}
details{margin:14px 0}summary{cursor:pointer;font-weight:600}nav a{color:#13598a;margin-right:15px}a{color:#13598a}small{color:#526576}
.nic-card{background:white;border:1px solid #dbe4eb;border-radius:12px;overflow:hidden;scroll-margin-top:100px}.nic-card>summary{padding:18px 22px;list-style:none;display:flex;align-items:center;gap:16px;flex-wrap:wrap;background:#f9fbfd}.nic-card>summary::-webkit-details-marker{display:none}.nic-card>summary:before{content:'+';font-size:22px;color:#13598a}.nic-card[open]>summary:before{content:'−'}.nic-title{font-size:19px}.nic-summary{font-weight:400;color:#526576;flex:1;min-width:230px}.nic-body{padding:8px 22px 22px}.nic-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px 28px}.nic-grid>section{min-width:0}.nic-body h3{font-size:16px;margin:20px 0 10px}.facts{display:grid;grid-template-columns:140px 1fr;gap:7px 12px;margin:12px 0}.facts dt{color:#526576}.facts dd{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}.badge{font-size:12px;white-space:nowrap;border-radius:20px;padding:3px 10px;background:#e8edf2;color:#46596a}.badge.up,.badge.enabled{background:#e1f3ec;color:#126749}.badge.disabled{background:#f0f2f4;color:#65717c}.addresses td:first-child,.ip-summary{font-family:Consolas,monospace;font-weight:600}.ip-summary{white-space:pre-line}.nic-empty{font-size:13px;color:#687b8b}.nic-group{margin-top:28px}.nic-group>summary{font-size:17px;padding:10px 0;border-bottom:1px solid #dbe4eb}.technical>summary{padding:12px;border-radius:8px;background:#eaf0f5}summary:focus-visible,a:focus-visible,button:focus-visible{outline:3px solid #227dbe;outline-offset:3px}[hidden]{display:none!important}
@media(max-width:780px){main{padding:14px}.nic-grid{grid-template-columns:1fr}.facts{grid-template-columns:110px 1fr}.nic-card>summary,.nic-body{padding:14px}.controls{position:static}input{min-width:180px}td,th{padding:8px}}
.addresses td:first-child{white-space:nowrap;min-width:115px}
@media print{body{background:white}main{padding:0}.controls,nav{display:none}.scroll{overflow:visible}.card{break-inside:avoid}.nic-card{break-inside:auto}.nic-card>summary{break-after:avoid}.nic-grid{grid-template-columns:1fr}tr{break-inside:avoid}th{background:#eee}}
</style></head><body><main><h1>네트워크 구성 분석</h1><p class="muted">FetchNetworkConfig )"<<FNC_VERSION<<" · 저장된 증거의 오프라인 분석</p>";
    auto text=[&](std::string_view t){return esc(t);};
    auto cell=[&](std::string v){if(v.empty())v="—";if(v.size()>4000){size_t end=4000;while(end&&(static_cast<unsigned char>(v[end])&0xc0)==0x80)--end;v.resize(end);v+=" … [발췌]";}h<<"<td>"<<text(v)<<"</td>";};
    auto table=[&](std::initializer_list<const char*> headings){h<<"<div class=\"scroll\"><table><thead><tr>";for(auto label:headings)h<<"<th scope=\"col\">"<<text(label)<<"</th>";h<<"</tr></thead><tbody>";};
    auto end_table=[&](){h<<"</tbody></table></div>";};
    auto row=[&](std::initializer_list<std::string> cells){h<<"<tr>";for(auto v:cells)cell(v);h<<"</tr>";};
    auto heading=[&](const char* id,const char* title){h<<"<h2 id=\""<<id<<"\">"<<text(title)<<"</h2>";};
    auto query_rows=[&](std::string_view mod,auto callback){for(const auto& q:arr(module(s,mod),"queries"))for(const auto& a:arr(q,"rows"))callback(a,q);};
    const auto& sys=module(s,"system");std::string os=field(obj(sys,"os"),"ProductName");
    const auto& wmi=arr(obj(sys,"operating_system_wmi"),"rows");if(!wmi.empty())os=field(wmi[0],"Caption");
    h<<"<section class=\"card\"><strong>"<<text(field(sys,"computer_name"))<<"</strong> · "<<text(os)<<" · 빌드 "<<text(field(obj(sys,"os"),"CurrentBuildNumber"))<<"."<<text(field(obj(sys,"os"),"UBR"))
     <<"<p>수집 시작(UTC): "<<text(field(s,"started_at_utc"))<<" / 종료: "<<text(field(s,"completed_at_utc"))<<"</p>"
     <<"<p>요청 이력(UTC): "<<text(field(obj(s,"inputs"),"from_utc"))<<" ~ "<<text(field(obj(s,"inputs"),"to_utc"))<<"</p>"
     <<"<p>무결성: manifest에 포함된 파일의 크기·SHA-256 검증 완료. ZIP 입력은 각 항목의 CRC도 검증했습니다. 해시는 전자서명이 아닙니다.</p></section>";
    size_t active=0,hardware=0,overlap_up=0,overlap_other=0;for(const auto& n:r.at("nics"))if(n["state"]=="Up"){++active;if(n.value("hardware_interface",false))++hardware;}
    for(const auto& o:r.at("overlaps")){if(o["both_up"].get<bool>())++overlap_up;else ++overlap_other;}
    h<<"<section class=\"card"<<(r.at("incomplete").get<bool>()?" alert":"")<<"\"><h3>전체 요약</h3><p>분석 상태: <strong>"<<(r.at("incomplete").get<bool>()?"누락/부분 수집 또는 제외된 증거 있음":"검증된 접근 가능 자료 분석 완료")
     <<"</strong></p><p>인터페이스 "<<field(r,"interface_count")<<"개 (필터 "<<field(r,"filter_count")<<"개), Up "<<active<<"개 / 그중 하드웨어 인터페이스 "<<hardware
     <<"개. 실제 물리 카드 개수와 다릅니다.</p><p>이벤트 "<<field(r,"event_count")<<"개, SetupAPI 섹션 "<<arr(r,"setupapi").size()<<"개.</p><p>서브넷 중복: Up NIC 간 "<<overlap_up<<"쌍 / 비활성 NIC가 포함된 "<<overlap_other<<"쌍.</p>";
    for(const auto& link:arr(r,"links"))h<<"<p>"<<text(field(link,"name"))<<": 링크 분리 "<<field(link,"down")<<"건 / 설정 "<<field(link,"up")<<"건 (보존된 선택 이력 기준).</p>";
    h<<"<p class=\"muted\">현재 설정, 과거 이력, 원인 추론은 구분합니다. 기록 없음은 변경 없음의 증거가 아닙니다. 카메라 검색·설정 조회·통신 검증은 수행하지 않았습니다.</p></section>";
    if(!arr(r,"notices").empty()){h<<"<section class=\"card alert\"><h3>누락 및 분석 제외</h3><ul>";for(const auto& n:r["notices"])h<<"<li>"<<text(str(n))<<"</li>";h<<"</ul><p>총 "<<field(r,"notice_count")<<"건, 최대 100건 표시.</p></section>";}
    if(!obj(r,"event_date_filter").empty()) {
        const auto& f=obj(r,"event_date_filter");h<<"<section class=\"card\"><h3>지정 날짜의 이벤트 추출</h3><p>"<<text(field(f,"date"))<<" · UTC"<<text(field(f,"utc_offset"))
         <<" 기준 00:00 이상, 다음 날 00:00 미만.</p><p>UTC 범위: "<<text(field(f,"from_utc"))<<" ≤ 시각 &lt; "<<text(field(f,"to_utc_exclusive"))
         <<"</p><p>원본의 유효 이벤트 "<<field(r,"source_event_count")<<"개 중 "<<field(r,"event_count")<<"개, SetupAPI "<<field(r,"source_setupapi_count")<<"개 중 "<<arr(r,"setupapi").size()
         <<"개 선택. 시각 미상 SetupAPI "<<field(r,"undated_setupapi_count")<<"개 제외.</p><p><a href=\"#selected-events\">추출 이벤트 목록 바로 보기</a> · <a href=\"selected-events.csv\" download>CSV 전체 추출</a> · <a href=\"selected-events.jsonl\" download>원본 XML 포함 JSONL</a></p>"
         <<"<p class=\"muted\">이력 집계에만 날짜를 적용했습니다. NIC/IP/필터/설정은 수집 시점의 현재 상태이며 지정 날짜 당시 상태를 복원한 결과가 아닙니다.</p></section>";
    }
    h<<R"(<nav><a href="#nics">NIC</a><a href="#routes">경로</a><a href="#settings">고급 설정</a><a href="#drivers">드라이버·SDK</a><a href="#firewall">방화벽</a><a href="#history">이력</a><a href="#coverage">수집 범위</a></nav>
<div class="controls"><label for="search">검색</label><input id="search" type="search" placeholder="NIC 이름, IP, 필터, 설정 이름"><label><input id="active" type="checkbox" style="min-width:0"> NIC에서 Up만 보기</label><button id="expand" type="button">NIC 펼치기</button><button id="collapse" type="button">NIC 접기</button><button id="print" type="button">인쇄 / PDF 저장</button><span id="matches" aria-live="polite"></span></div>)";
    if(!obj(r,"event_date_filter").empty()) {
        heading("selected-events","지정 날짜의 이벤트 목록");table({"시각 (선택한 UTC offset)","구분 / 채널","Provider / ID / level","메시지","원본 파일:행"});size_t shown_events=0;
        for(const auto& a:arr(r,"selected_events")) {
            if(shown_events++>=1000)break;const auto& e=obj(a,"record");
            row({field(a,"time_selected"),field(a,"kind")+" / "+field(e,"channel"),field(e,"provider")+" / "+field(e,"event_id")+" / "+field(e,"level"),field(e,"message"),field(a,"source_file")+":"+field(a,"source_line")});
        }end_table();h<<"<p>시간순 최대 1,000개 표시. CSV/JSONL에는 선택된 전체 "<<arr(r,"selected_events").size()<<"개를 보존합니다. JSONL의 record에는 원래 XML과 원래 시각이 있습니다.</p>";
        if(arr(r,"selected_events").empty())h<<"<p class=\"muted\">저장된 자료에서 해당 날짜에 일치하는 유효 기록이 없습니다. 미보존·미수집 가능성이 있으며 해당 날짜에 이벤트가 없었다는 뜻으로 단정하지 않습니다.</p>";
    }
    auto group=[](const Json& n){if(n["state"]=="NotPresent")return 4;return n.value("hardware_interface",false)?(n["state"]=="Up"?0:1):(n["state"]=="Up"?2:3);};
    std::vector<const Json*> ordered;for(const auto& n:r["nics"])ordered.push_back(&n);
    std::sort(ordered.begin(),ordered.end(),[&](const Json* a,const Json* b){auto ga=group(*a),gb=group(*b);return ga!=gb?ga<gb:a->at("if_index").get<unsigned>()<b->at("if_index").get<unsigned>();});
    auto status_name=[](const Json& n){auto s=string_value(n,"state");return s=="Up"?"연결됨 (Up)":s=="Down"?"연결 끊김 (Down)":s=="NotPresent"?"장치 없음 (NotPresent)":s;};
    auto source_text=[](const Json& a){auto v=field(a,"Source");return v=="2"?"장치 조회 (2)":v=="3"?"저장 설정 (3)":"Source "+v;};
    auto bool_text=[](const Json& a,const char* key){if(!a.contains(key)||!a[key].is_boolean())return std::string("미수집");return std::string(a[key].get<bool>()?"활성 (true)":"비활성 (false)");};
    auto ip_summary=[&](const Json& n){std::string result;for(const auto& a:arr(n,"ipv4")){if(!result.empty())result+='\n';result+=field(a,"address")+"/"+field(a,"prefix_length")+" · "+assignment_text(a);}return result.empty()?"IPv4 기록 없음":result;};
    heading("nics","1. NIC별 IP 주소와 상세 구성");
    h<<"<p>NIC 이름을 누르면 IP·필터 드라이버·세부 설정을 함께 볼 수 있습니다. 연결된 하드웨어 NIC부터 표시합니다. 수동 169.254 주소를 DHCP 실패로 판정하지 않으며, 연결되지 않은 NIC의 주소도 수집 당시 기록을 그대로 표시합니다.</p>";
    auto overview=[&](bool up){table({"NIC","상태","장치","IPv4 주소 / 할당","IP MTU","활성 필터 / 전체","드라이버 버전"});
    for(const auto* p:ordered) {if((p->at("state")=="Up")!=up)continue;
        const auto& n=*p;const auto& d=obj(n,"details");auto filters=filter_counts(n);std::string version="미수집/미매핑";
        for(const auto& a:arr(d,"drivers")){version=field(a,"DriverVersion");break;}
        h<<"<tr data-nic=\"1\" data-up=\""<<(n["state"]=="Up"?"1":"0")<<"\"><td><a class=\"nic-link\" href=\"#nic-"<<field(n,"if_index")<<"\">"<<text(field(n,"friendly_name"))<<"</a></td>";
        for(auto v:{status_name(n),field(n,"description"),ip_summary(n),field(obj(n,"interface"),"mtu"),std::to_string(filters.enabled)+" / "+std::to_string(filters.total)+(filters.unknown?" ? ??? "+std::to_string(filters.unknown):""),version})cell(v);h<<"</tr>";
    }end_table();};
    h<<"<h3>연결된 NIC 주소 요약</h3>";overview(true);
    h<<"<details><summary>연결되지 않았거나 현재 장치가 없는 NIC 주소 요약</summary>";overview(false);h<<"</details>";
    h<<"<p class=\"muted\">필터 개수는 해당 NIC의 Filter 바인딩 조회값입니다. 0/0 또는 미수집은 모듈의 수집 상태와 함께 확인하십시오.</p>";
    int last_group=-1;static const char* groups[]={"연결된 하드웨어 NIC","연결되지 않은 하드웨어 NIC","연결된 가상·소프트웨어 NIC","연결되지 않은 가상·소프트웨어 NIC","현재 장치가 없는 NIC"};
    for(const auto* p:ordered) {
        const auto& n=*p;const auto& i=obj(n,"interface");const auto& d=obj(n,"details");auto filters=filter_counts(n);auto g=group(n);
        if(g!=last_group){if(last_group!=-1)h<<"</details>";size_t count=0;for(const auto* candidate:ordered)if(group(*candidate)==g)++count;
            h<<"<details class=\"nic-group\""<<((g==0||g==2)?" open":"")<<"><summary>"<<groups[g]<<" ("<<count<<"개)</summary>";last_group=g;}
        h<<"<details class=\"nic-card\" id=\"nic-"<<field(n,"if_index")<<"\" data-up=\""<<(n["state"]=="Up"?"1":"0")<<"\""<<(g==0?" open":"")<<">"
         <<"<summary><span class=\"nic-title\">"<<text(field(n,"friendly_name"))<<"</span><span class=\"badge"<<(n["state"]=="Up"?" up":"")<<"\">"<<text(status_name(n))<<"</span>"
         <<"<span class=\"nic-summary\">"<<text(field(n,"description"))<<"<br><span class=\"ip-summary\">"<<text(ip_summary(n))<<"</span></span></summary><div class=\"nic-body\"><div class=\"nic-grid\"><section><h3>IP 주소</h3>";
        h<<"<div class=\"addresses\">";table({"IPv4 주소","Prefix / 서브넷 마스크","할당 방식"});
        for(const auto& a:arr(n,"ipv4"))row({field(a,"address"),"/"+field(a,"prefix_length")+" · "+mask_text(a),assignment_text(a)+(a.value("link_local",false)?" · Link-local 대역":"")});end_table();h<<"</div>";
        if(arr(n,"ipv4").empty())h<<"<p class=\"nic-empty\">IPv4 주소 기록이 없습니다.</p>";
        h<<"<dl class=\"facts\">";
        auto fact=[&](std::string label,std::string value){h<<"<dt>"<<text(label)<<"</dt><dd>"<<text(value.empty()?"기록 없음":value)<<"</dd>";};
        fact("DHCP IPv4",bool_text(n,"dhcp_v4_enabled"));fact("DHCP 서버",field(n,"dhcp_v4_server"));
        fact("기본 게이트웨이",list_text(n,"gateways"));fact("DNS 서버",list_text(n,"dns_servers"));fact("DNS suffix",field(n,"dns_suffix"));
        for(const auto& a:arr(d,"profiles"))fact("네트워크 프로필",field(a,"Name")+" / "+(field(a,"NetworkCategory")=="0"?"Public":field(a,"NetworkCategory")=="1"?"Private":field(a,"NetworkCategory")=="2"?"Domain":"미해석"));
        h<<"</dl><details><summary>IPv6 주소</summary>";table({"IPv6 주소","Prefix","할당 출처"});
        for(const auto& a:arr(n,"addresses"))if(string_value(a,"address").find(':')!=std::string::npos)row({field(a,"address"),"/"+field(a,"prefix_length"),assignment_text(a)});end_table();h<<"</details>";
        h<<"<h3>장치와 NIC 드라이버</h3><dl class=\"facts\">";
        fact("MAC 주소",field(n,"mac"));fact("인터페이스 번호",field(n,"if_index"));fact("장치 GUID",field(n,"adapter_name"));
        fact("링크 수신 / 송신",speed_text(i,"rx_link_bps")+" / "+speed_text(i,"tx_link_bps"));fact("IP MTU",field(i,"mtu")+" bytes");
        for(const auto& a:arr(d,"drivers")){fact("드라이버 버전",field(a,"DriverVersion"));fact("공급자 / INF",field(a,"DriverProviderName")+" / "+field(a,"InfName"));fact("드라이버 날짜",driver_date(a));}
        if(arr(d,"drivers").empty())fact("드라이버 버전","미수집/미매핑 — 전체 드라이버 목록 확인");
        h<<"</dl></section><section><h3>NIC 전원관리</h3>";
        if(arr(d,"power").empty())h<<"<p class=\"nic-empty\">NIC에 대응하는 전원관리 조회값이 없습니다. 미지원·누락·미매핑을 수집 상태와 원본에서 확인하십시오.</p>";
        for(const auto& a:arr(d,"power")) {
            h<<"<p class=\"muted\">"<<text(source_text(a))<<"</p>";table({"설정","조회값"});
            for(const auto& kv:std::initializer_list<std::pair<const char*,const char*>>{{"장치 전원 차단 허용","AllowComputerToTurnOffDevice"},{"Selective Suspend","SelectiveSuspend"},{"연결 해제 시 절전","DeviceSleepOnDisconnect"},{"Wake on Magic Packet","WakeOnMagicPacket"},{"Wake on Pattern","WakeOnPattern"},{"ARP offload","ArpOffload"},{"NS offload","NSOffload"},{"RSN rekey offload","RsnRekeyOffload"},{"D0 packet coalescing","D0PacketCoalescing"}})row({kv.first,power_value(a,kv.second)});
            end_table();if(!a.contains("AllowComputerToTurnOffDevice")||a["AllowComputerToTurnOffDevice"]!=2)h<<"<p class=\"muted\">전원 차단 허용이 Enabled가 아니므로 하위 전원 속성은 정의되지 않은 값일 수 있습니다.</p>";
        }
        h<<"<p class=\"muted\">Unsupported (0) = 미지원, Disabled (1) = 비활성, Enabled (2) = 활성. 현재 절전 중이라는 의미가 아닙니다.</p></section></div>";
        h<<"<h3>필터 드라이버 <span class=\"badge\">활성 "<<filters.enabled<<" / 전체 "<<filters.total<<(filters.unknown?" ? ??? "+std::to_string(filters.unknown):"")<<"</span></h3>";
        table({"필터 드라이버","활성 여부","Component ID"});
        for(const auto& a:arr(d,"bindings"))if(string_value(a,"ComponentClassName")=="Filter") {
            auto enabled=boolean_value(a,"Enabled");h<<"<tr>";cell(field(a,"DisplayName"));h<<"<td><span class=\"badge "<<(!enabled?"unknown":*enabled?"enabled":"disabled")<<"\">"<<text(bool_text(a,"Enabled"))<<"</span></td>";cell(field(a,"ComponentID"));h<<"</tr>";
        }end_table();if(!filters.total)h<<"<p class=\"nic-empty\">매핑된 Filter 바인딩 기록이 없습니다.</p>";
        h<<"<details><summary>프로토콜·서비스를 포함한 모든 바인딩</summary>";table({"구성 요소","분류","활성 여부","Component ID"});
        for(const auto& a:arr(d,"bindings"))row({field(a,"DisplayName"),field(a,"ComponentClassName"),bool_text(a,"Enabled"),field(a,"ComponentID")});end_table();h<<"</details>";
        h<<"<h3>주요 NIC 세부 설정 — Jumbo·EEE·절전·버퍼</h3>";table({"설정 이름","표시값","원래 키","저장값","출처"});
        for(const auto& a:arr(d,"advanced"))if(core_setting(a))row({field(a,"DisplayName"),field(a,"DisplayValue"),field(a,"RegistryKeyword"),setting_value(a),source_text(a)});end_table();
        h<<"<p class=\"muted\">Jumbo Packet 드라이버 표시값과 IP MTU는 별도 값입니다. 저장값은 제조사 선택 코드일 수 있으며 적용 상태를 단정하지 않습니다.</p>";
        h<<"<details><summary>고급 설정 전체 ("<<arr(d,"advanced").size()<<"개)</summary>";table({"설정 이름","표시값","원래 키","저장값","출처"});
        for(const auto& a:arr(d,"advanced"))row({field(a,"DisplayName"),field(a,"DisplayValue"),field(a,"RegistryKeyword"),setting_value(a),source_text(a)});end_table();h<<"</details>";
        h<<"<details><summary>RSS·오프로드 세부 설정</summary>";table({"조회 종류","속성","조회값"});
        for(const auto& a:arr(d,"offload"))for(const auto& kv:a.items()) {
            if(kv.value().is_structured()||kv.value().is_null())continue;
            if(kv.key()=="evidence"||kv.key()=="Caption"||kv.key()=="Description"||kv.key()=="ElementName"||kv.key()=="InstanceID"||kv.key()=="InterfaceDescription"||kv.key()=="Name"||kv.key()=="SystemName")continue;
            auto query=string_value(a,"evidence");auto colon=query.rfind(':');if(colon!=std::string::npos)query.erase(0,colon+1);
            row({query,kv.key(),str(kv.value())});
        }end_table();h<<"<p class=\"muted\">수치형 enum은 원래 값입니다. 원본 snapshot에는 배열과 복합 속성도 보존됩니다.</p></details>";
        h<<"<details><summary>저장된 NIC 레지스트리 값·누적 카운터·조회 출처</summary>";table({"키","저장값","증거 경로"});
        for(const auto& a:arr(d,"saved_settings"))row({field(a,"RegistryKeyword"),field(a,"RegistryValue"),field(a,"evidence")});end_table();
        table({"누적 카운터","수집값"});for(const auto& kv:obj(i,"counters").items())row({kv.key(),str(kv.value())});end_table();
        h<<"<p class=\"muted\">IP/MAC/MTU: network.adapters / interfaces. 필터: bindings. 전원: power. 고급 설정: advanced. NIC 드라이버: drivers의 장치 GUID → PNPDeviceID → DeviceID 대응. 모듈의 조회 시각·오류는 수집 범위에서 확인할 수 있습니다.</p></details></div></details>";
    }
    if(last_group!=-1)h<<"</details>";
    h<<"<details><summary>서브넷 중복 상세 ("<<arr(r,"overlaps").size()<<"쌍)</summary>";table({"NIC A","NIC B","분류"});for(const auto& o:r["overlaps"])row({field(o,"a"),field(o,"b"),o.value("both_up",false)?"두 NIC 모두 Up":"비활성 NIC 포함 — 현재 경로 경쟁 근거 아님"});end_table();h<<"</details>";
    heading("routes","2. 경로 및 기존 Neighbor 캐시");h<<"<p>근거: snapshot.json → network.routes / neighbors. 캐시는 현재 장치 IP 또는 통신 성공을 검증한 결과가 아닙니다.</p>";
    h<<"<details class=\"technical\"><summary>전체 IPv4 경로와 Neighbor 캐시 펼치기</summary>";
    table({"목적지 / prefix","ifIndex","Next hop","경로 metric","NIC metric","합계"});
    for(const auto& a:arr(net,"routes")) {
        if(string_value(a,"destination").find(':')!=std::string::npos)continue;
        row({field(a,"destination")+"/"+field(a,"prefix_length"),field(a,"if_index"),field(a,"next_hop"),field(a,"route_metric"),field(a,"interface_metric"),
            a.contains("route_metric")&&a.contains("interface_metric")?std::to_string(a["route_metric"].get<uint64_t>()+a["interface_metric"].get<uint64_t>()):"미수집"});
    }end_table();h<<"<details><summary>Neighbor 캐시</summary>";table({"ifIndex","주소","MAC","상태(원시값)","Unreachable"});
    for(const auto& a:arr(net,"neighbors"))row({field(a,"if_index"),field(a,"address"),field(a,"mac"),field(a,"state"),field(a,"is_unreachable")});end_table();h<<"</details></details>";
    heading("settings","3. 필터·전원관리·고급 설정");
    h<<"<details class=\"technical\"><summary>전체 NIC 비교표와 NIC에 매핑되지 않은 설정 펼치기</summary>";
    h<<"<h3>Jumbo Packet 설정과 IP MTU</h3><p>근거: snapshot.json → advanced. 드라이버 표시값과 저장값을 그대로 기록합니다. 드라이버의 숫자 선택 코드(예: 2)를 바이트 수로 변환하지 않습니다. IP MTU는 별도 조회값이며 Jumbo 설정과 같은 단위·범위라는 뜻이 아닙니다.</p>";
    table({"NIC / 상태","장치","IP MTU (bytes)","설정 이름 / 키","드라이버 표시값","저장값","Source"});
    for(const auto& a:arr(obj(r,"nic_settings"),"advanced"))if(string_value(a,"category")=="Jumbo Packet")
        row({field(a,"Name")+" / "+field(a,"nic_state"),field(a,"InterfaceDescription"),field(a,"ip_mtu"),field(a,"DisplayName")+" / "+field(a,"RegistryKeyword"),field(a,"DisplayValue"),field(a,"RegistryValue"),field(a,"Source")});
    end_table();
    h<<"<h3>NIC 전원관리</h3>";
    table({"NIC","장치 전원 차단 허용","Selective Suspend","연결 해제 시 절전","Wake on Magic Packet","Wake on Pattern","Source"});
    query_rows("power",[&](const Json& a,const Json&){row({field(a,"Name"),power_value(a,"AllowComputerToTurnOffDevice"),power_value(a,"SelectiveSuspend"),power_value(a,"DeviceSleepOnDisconnect"),power_value(a,"WakeOnMagicPacket"),power_value(a,"WakeOnPattern"),field(a,"Source")});});end_table();
    h<<"<p>Source 2 = Device, 3 = Persistent storage. Unsupported(0)은 Disabled(1)과 다릅니다. 장치 전원 차단 허용이 Enabled가 아니면 하위 전원 속성은 정의되지 않은 값입니다. 이 표는 설정 조회이며 PC 또는 NIC가 현재 절전 중인지 측정한 결과가 아닙니다.</p>";
    h<<"<h3>드라이버의 절전·EEE·Wake 관련 고급 설정</h3><p>원래 키의 power/EEE/energy/suspend/sleep/wake/DMAC 등의 문자열로 선별했습니다. 제조사별 의미는 표시값을 우선 확인하고, 나머지 속성은 아래 전체 고급 속성 표에서 확인하십시오.</p>";
    table({"NIC / 상태","설정 이름","Registry keyword","드라이버 표시값","저장값","Source"});
    for(const auto& a:arr(obj(r,"nic_settings"),"advanced"))if(string_value(a,"category")=="전원·EEE·Wake")
        row({field(a,"Name")+" / "+field(a,"nic_state"),field(a,"DisplayName"),field(a,"RegistryKeyword"),field(a,"DisplayValue"),field(a,"RegistryValue"),field(a,"Source")});end_table();
    h<<"<details><summary>저장된 NIC 레지스트리의 Jumbo·절전 관련 값 (분리된 NIC 포함 가능)</summary><p>근거: snapshot.json → registry.keys. 장치 GUID로 매핑하며 현재 NIC가 없으면 미매핑으로 표시합니다. 저장된 값만으로 현재 적용 상태를 판정하지 않습니다.</p>";
    table({"NIC / 상태","장치 GUID","Registry keyword","저장값","레지스트리 형식","증거 경로"});
    for(const auto& a:arr(obj(r,"nic_settings"),"registry"))row({field(a,"Name")+" / "+field(a,"nic_state"),field(a,"InstanceID"),field(a,"RegistryKeyword"),field(a,"RegistryValue"),field(a,"registry_type"),field(a,"evidence")});end_table();h<<"</details>";
    h<<"<details><summary>전원관리의 나머지 속성</summary>";table({"NIC","ARP offload","NS offload","RSN rekey offload","D0 packet coalescing","Source"});
    query_rows("power",[&](const Json& a,const Json&){row({field(a,"Name"),power_value(a,"ArpOffload"),power_value(a,"NSOffload"),power_value(a,"RsnRekeyOffload"),power_value(a,"D0PacketCoalescing"),field(a,"Source")});});end_table();h<<"</details>";
    h<<"<p>값이 없거나 표가 비어 있으면 미지원·누락·조회 실패일 수 있습니다. 7절의 advanced / power / registry 수집 상태를 확인하십시오. 기능이 꺼졌다는 뜻으로 해석하지 않습니다.</p><h3>바인딩 / 필터</h3>";
    table({"NIC","Component ID","필터 이름","Enabled"});query_rows("bindings",[&](const Json& a,const Json&){if(string_value(a,"ComponentClassName")=="Filter"||string_value(a,"ComponentID")=="ms_tcpip"||string_value(a,"ComponentID")=="ms_tcpip6")row({field(a,"Name"),field(a,"ComponentID"),field(a,"DisplayName"),field(a,"Enabled")});});end_table();
    h<<"<p>여러 필터가 활성화됐다는 사실만으로 충돌이나 주소 변경을 단정하지 않습니다.</p>";
    h<<"<details><summary>고급 속성 원래 키·표시값·저장값</summary>";table({"NIC","Registry keyword","설정 이름","표시값","저장값","Source"});
    query_rows("advanced",[&](const Json& a,const Json&){row({field(a,"Name"),field(a,"RegistryKeyword"),field(a,"DisplayName"),field(a,"DisplayValue"),field(a,"RegistryValue"),field(a,"Source")});});end_table();h<<"</details>";
    h<<"<details><summary>오프로드 / RSS</summary>";table({"출처","NIC","관찰값"});query_rows("offload",[&](const Json& a,const Json& q){Json copy=a;for(auto key:{"_cim_types","Caption","InstanceID","SystemName","Description","ElementName"})copy.erase(key);row({field(q,"source"),field(a,"Name"),json_text(copy)});});end_table();h<<"</details>";
    h<<"</details>";
    heading("drivers","4. 드라이버와 설치된 영상 소프트웨어");
    table({"장치","버전","드라이버 날짜(원시값)","공급자","INF / Device ID"});query_rows("drivers",[&](const Json& a,const Json&){if(a.contains("DriverVersion"))row({field(a,"DeviceName"),field(a,"DriverVersion"),field(a,"DriverDate"),field(a,"DriverProviderName"),field(a,"InfName")+"\n"+field(a,"DeviceID")});});end_table();
    table({"설치 목록 이름","버전","보고된 설치일","Publisher","출처"});for(const auto& a:arr(module(s,"software"),"software"))row({field(a,"display_name"),field(a,"display_version"),field(a,"install_date_reported"),field(a,"publisher"),field(a,"registry_key")});end_table();
    h<<"<p>드라이버 날짜는 실제 설치일과 다릅니다. 설치 목록은 이름 검색 결과이므로 누락·과잉 매칭이 가능하며, 프로그램 실행 중 여부를 뜻하지 않습니다.</p>";
    heading("firewall","5. 네트워크 프로필과 방화벽");table({"NIC","프로필 이름","Category (0 Public / 1 Private / 2 Domain)","IPv4 connectivity (원시값)"});
    query_rows("bindings",[&](const Json& a,const Json&){if(a.contains("NetworkCategory"))row({field(a,"InterfaceAlias"),field(a,"Name"),field(a,"NetworkCategory"),field(a,"IPv4Connectivity")});});end_table();
    const auto& fw=module(s,"firewall");h<<"<p>근거: snapshot.json → firewall. 전체 규칙 "<<arr(fw,"rules").size()<<"개. 현재 프로필 비트 마스크: "<<field(fw,"current_profile_types")<<".</p>";
    table({"프로필 (1 Domain / 2 Private / 4 Public)","Enabled","기본 inbound (0 Block / 1 Allow)","기본 outbound","전체 inbound 차단"});
    for(const auto& a:arr(fw,"profiles"))row({field(a,"type"),field(a,"enabled"),field(a,"default_inbound_action"),field(a,"default_outbound_action"),field(a,"block_all_inbound")});end_table();
    h<<"<details><summary>영상 프로그램 관련 방화벽 규칙 (이름/경로 검색)</summary>";table({"규칙","실행 경로","Enabled","프로필 마스크","방향 / action","protocol"});
    for(const auto& a:arr(fw,"rules")) {
        auto searchable=lower(json_text(a));bool match=false;for(auto term:{"gige","genicam","sapera","balluff","matrox","teledyne","pylon","camera","galaxy","ebus"})if(searchable.find(term)!=std::string::npos)match=true;
        if(match)row({field(a,"name"),field(a,"application_name"),field(a,"enabled"),field(a,"profiles"),field(a,"direction")+" / "+field(a,"action"),field(a,"protocol")});
    }end_table();h<<"</details><p>프로필 마스크는 NIC별 프로필과 대조해야 합니다. 규칙 존재만으로 실제 패킷 허용·차단을 확정하지 않습니다.</p>";
    heading("history","6. 기존 이력 집계");h<<"<p>이벤트 시각은 원본의 UTC/local 값을 그대로 사용합니다. 증거 표시는 원본 JSONL 파일명:행 번호입니다. 시간 초과·보존 기간 제한이 있으면 전체 기간의 횟수가 아닙니다.</p>";
    table({"NIC","링크 분리","링크 설정","분리→설정 쌍","시각 간격 중앙값(초)"});for(const auto& a:arr(r,"links"))row({field(a,"name"),field(a,"down"),field(a,"up"),field(a,"pairs"),field(a,"median_s")});end_table();
    h<<"<p>링크 분류: e1rexpress/e2fnexpress의 ID 27(분리), 32(설정), aqnic650의 ID 14(분리). XML 장치명과 정확히 일치하는 NIC 설명이 하나일 때만 매핑합니다. 후보가 여러 개면 모호한 NIC로, 후보가 없으면 미매핑으로 표시합니다. 시각 간격은 실제 패킷 단절시간 측정값이 아닙니다.</p>";
    for(const auto& a:arr(r,"links")) {
        h<<"<details><summary>"<<text(field(a,"name"))<<" — 날짜별 링크 이력 및 증거</summary>";
        auto candidates=obj(r,"ambiguous_link_nics").find(field(a,"name"));
        if(candidates!=obj(r,"ambiguous_link_nics").end())h<<"<p>식별할 수 없는 NIC 후보: "<<text(str(*candidates))<<". 특정 포트의 이력으로 확정할 수 없습니다.</p>";
        table({"날짜(원본 local 기준)","분리","설정"});for(const auto& d:arr(a,"daily"))row({field(d,"day"),field(d,"down"),field(d,"up")});end_table();
        table({"원본 local 시각","동작","증거","메시지"});for(const auto& e:arr(a,"samples"))row({field(e,"time_local"),field(e,"action"),reference(e),field(e,"message")});end_table();h<<"<small>최대 6개 사례. 전체 횟수는 모든 유효 기록을 집계했습니다.</small></details>";
    }
    h<<"<details><summary>Provider / ID / 수준별 집계</summary>";table({"Provider","ID / level","건수","최초~최신(UTC)","최근 증거","메시지 예시"});size_t shown=0;
    for(const auto& a:arr(r,"event_groups")){if(shown++>=500)break;row({field(a,"provider"),field(a,"id")+" / "+field(a,"level"),field(a,"count"),field(a,"oldest")+"\n"+field(a,"newest"),reference(a.at("example")),field(a.at("example"),"message")});}end_table();h<<"<p>전체 그룹 "<<arr(r,"event_groups").size()<<"개 중 빈도순 최대 500개 표시. level 1 Critical / 2 Error / 3 Warning / 4 Information / 0 LogAlways.</p></details>";
    h<<"<details><summary>SetupAPI 기존 설치 이력</summary>";table({"원본 local 시각","작업","증거"});size_t sections=0;for(const auto& a:arr(r,"setupapi")){if(sections++>=500)break;row({field(a,"time_local"),field(a,"message"),reference(a)});}end_table();h<<"<p>최대 500개 표시. 장치 설치 기록이며 모든 설정 변경 이력이 아닙니다.</p></details>";
    heading("applications","애플리케이션 오류·응답 없음·WER 기록");
    h<<"<p>Windows 기록 "<<arr(r,"app_incidents").size()<<"개. Application Error와 WER는 각각 보존합니다. ReportID 또는 같은 앱·PID와 5분 이내 시각이 확인될 때만 연관 증거를 표시하며, 서로 다른 이벤트를 하나의 사고로 합산하지 않습니다.</p>";
    table({"시각(UTC)","Provider / ID","앱 / 버전","모듈 / 예외 코드","PID / ReportID","연관 기록","증거"});size_t app_shown=0;
    for(const auto& a:arr(r,"app_incidents")){if(app_shown++>=500)break;row({field(a,"time_utc"),field(a,"provider")+" / "+field(a,"event_id"),field(a,"app_name")+" / "+field(a,"app_version"),field(a,"module_name")+" / "+field(a,"exception_code"),field(a,"pid")+" / "+field(a,"report_id"),json_text(arr(a,"related_records")),reference(a)});}end_table();h<<"<p class=\"muted\">최대 500개 표시. 상세 경로와 원본 EventData는 이벤트 JSONL의 XML에서 확인할 수 있습니다.</p>";
    heading("sdk","SDK 로그의 세션과 통계");const auto& sdk=obj(r,"sdk");
    h<<"<p>SDK 구조화 기록 "<<field(r,"source_sdk_event_count")<<"개 / 날짜 선택에 포함된 기록 "<<field(r,"sdk_event_count")<<"개 / UTC 미확정 "<<field(r,"undated_sdk_count")<<"개. 원본 로그 오프셋: "<<text(field(sdk,"utc_offset"))<<". 세션과 버전 표는 전체 원본 범위입니다. 원본 로그마다 PID와 연결·취득 경계로 구분하며 다른 파일의 세션은 합치지 않습니다.</p>";
    table({"원본 파일 / PID","세션의 원래 시각 범위","설정·카메라 정보","ERROR / WARN","오류 유형","통계 / 근거 행"});size_t sdk_shown=0;
    for(const auto& a:arr(sdk,"sessions")){if(sdk_shown++>=500)break;row({field(a,"source_file")+" / "+field(a,"pid"),field(a,"first_timestamp")+" ~ "+field(a,"last_timestamp"),json_text(obj(a,"fields")),field(a,"error_count")+" / "+field(a,"warning_count"),json_text(obj(a,"families")),json_text(arr(a,"statistics"))});}end_table();
    table({"실행 중 SDK·GigE 버전","근거 파일:행"});for(const auto& a:arr(sdk,"versions"))row({json_text(obj(a,"fields")),field(a,"source_file")+":"+field(a,"source_line")});end_table();
    h<<"<p>ERROR 건수, 미지원 파라미터, 취득 중단 전환만으로 네트워크 장애나 크래시 원인을 확정하지 않습니다. 설치 목록·실행 중 SDK·덤프 모듈 버전은 서로 다른 관찰값입니다. 날짜 추출은 UTC를 확정한 SDK 기록만 포함하며 Windows 이벤트 건수와 별도로 집계합니다.</p>";
    h<<"<details><summary>SDK 구조화 이벤트와 원본 위치 (최대 500개)</summary>";table({"원래 시각 / UTC","종류 / 수준","PID / thread","원본 파일:행 / 바이트 위치","내용"});size_t sdk_rows=0;
    for(const auto& e:arr(sdk,"events")){if(sdk_rows++>=500)break;row({field(e,"original_timestamp")+" / "+field(e,"time_utc"),field(e,"kind")+" / "+field(e,"level"),field(e,"pid")+" / "+field(e,"thread_id"),field(e,"source_file")+":"+field(e,"source_line")+" / "+field(e,"source_byte_offset"),field(e,"message")});}end_table();h<<"</details>";
    heading("memory","물리 메모리 관찰값");const auto& memory=obj(sys,"physical_memory");
    table({"총 물리 메모리(bytes)","사용 가능(bytes)","부하(%)","관찰 시각(UTC)"});row({field(memory,"total_bytes"),field(memory,"available_bytes"),field(memory,"load_percent"),field(memory,"observed_at_utc")});end_table();
    table({"제조사","Part number","용량(bytes, 64비트)","보고 속도 / 구성 속도(MHz)","관찰 시각(UTC)"});for(const auto& a:arr(obj(sys,"memory_modules_wmi"),"rows"))row({field(a,"Manufacturer"),field(a,"PartNumber"),field(a,"Capacity"),field(a,"Speed")+" / "+field(a,"ConfiguredClockSpeed"),field(sys,"memory_modules_observed_at_utc")});end_table();
    heading("dumps","명시한 덤프의 메타데이터");h<<"<p>메타데이터만 읽었습니다. 스택과 장애 원인은 분석하지 않습니다. 예외 스트림이 없으면 예외 정보 없음으로 표시합니다. 원본을 선택 첨부한 경우 diagnostics.zip과 별도의 파일로 전달합니다.</p>";
    table({"원본 경로 / 크기(bytes)","생성 시각(UTC)","아키텍처 / OS build","플래그 / Full memory","예외 정보","근거"});
    for(const auto& a:arr(r,"dumps"))row({field(a,"source_path")+" / "+field(a,"source_size_bytes"),field(a,"created_at_utc"),field(a,"architecture_name")+" ("+field(a,"architecture")+") / "+field(a,"os_build"),field(a,"flags")+" / "+field(a,"includes_full_memory"),a.value("exception_stream_present",false)?json_text(obj(a,"exception")):"예외 정보 없음",field(a,"evidence_file")});end_table();
    h<<"<details><summary>덤프 모듈의 파일 버전 (실행 중 SDK 버전과 별도, 최대 500개 표시)</summary>";table({"메타데이터 파일","모듈 경로","파일 버전"});size_t dump_modules=0;for(const auto& a:arr(r,"dumps"))for(const auto& m:arr(a,"modules")){if(dump_modules++<500)row({field(a,"evidence_file"),field(m,"path"),field(m,"file_version")});}end_table();h<<"<p>전체 "<<dump_modules<<"개. 전체 목록은 각 메타데이터 JSON을 확인하십시오.</p></details>";
    table({"별도 첨부 파일","크기(bytes)","SHA-256"});for(const auto& a:arr(r,"external_attachments"))row({field(a,"name"),field(a,"size_bytes"),field(a,"sha256")});end_table();
    heading("coverage","7. 수집 상태와 증거 범위");table({"모듈","상태","관찰 시각(UTC)","채널 활성","가장 오래 보존된 시각(local)","누락/오류"});
    for(const auto& a:arr(s,"modules"))row({field(a,"task_id"),field(a,"status"),field(a,"observed_at_utc"),field(obj(a,"metadata"),"enabled"),field(obj(obj(a,"metadata"),"oldest_retained_event"),"time_local"),json_text(arr(a,"issues"))});end_table();
    table({"이벤트 파일","선택된 이벤트","원본 유효 이벤트","날짜 범위 외","제외 행","선택 시각 범위(UTC)"});for(const auto& a:arr(r,"event_channels"))row({field(a,"file"),field(a,"count"),field(a,"valid_source_count"),field(a,"outside_date"),field(a,"excluded"),field(a,"oldest")+"\n"+field(a,"newest")});end_table();
    h<<"<p>원본 snapshot에는 더 많은 속성과 원래 형식이 있습니다. SDK 로그는 인식한 MVSDK/CamClient 형식만 구조화합니다. 다른 사용자 로그와 SetupAPI 원문은 원본 증거로 확인하십시오. Security 변경 기록은 기존 감사 설정과 보존 기간에 따라 없을 수 있습니다.</p>"
     <<"<p>값 정의: <a href=\"https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_if_row2\" rel=\"noreferrer\">Microsoft NIC 상태</a> · <a href=\"https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/netadaptercimprov/msft-netadapterpowermanagementsettingdata\" rel=\"noreferrer\">전원관리 CIM</a>. 외부 자료는 링크를 눌렀을 때만 열립니다.</p>";
    h<<R"(<script nonce="fnc-analyze">
const search=document.getElementById('search'),active=document.getElementById('active');
const cards=Array.from(document.querySelectorAll('.nic-card'));
function filter(){const q=search.value.toLocaleLowerCase();if(q)document.querySelectorAll('details:not(.nic-card)').forEach(d=>d.open=true);let count=0,nics=0;
cards.forEach(card=>{const header=card.querySelector('summary').textContent.toLocaleLowerCase();const match=(!active.checked||card.dataset.up==='1')&&card.textContent.toLocaleLowerCase().includes(q);card.hidden=!match;if(match){nics++;if(q)card.open=true;}card.querySelectorAll('tbody tr').forEach(row=>{row.hidden=!!q&&!header.includes(q)&&!row.textContent.toLocaleLowerCase().includes(q);});});
document.querySelectorAll('tbody tr').forEach(row=>{if(row.closest('.nic-card')){if(!row.hidden&&!row.closest('.nic-card').hidden)count++;return;}const match=row.textContent.toLocaleLowerCase().includes(q)&&(!active.checked||!row.dataset.nic||row.dataset.up==='1');row.hidden=!match;if(match)count++;});
document.querySelectorAll('.nic-group').forEach(group=>group.hidden=!Array.from(group.querySelectorAll('.nic-card')).some(card=>!card.hidden));document.getElementById('matches').textContent='NIC '+nics+'개 / 표 '+count+'개 행 표시';}
document.querySelectorAll('.nic-link').forEach(link=>link.addEventListener('click',()=>{const card=document.getElementById(link.getAttribute('href').slice(1));if(card){card.closest('.nic-group').open=true;card.open=true;}}));
document.getElementById('expand').addEventListener('click',()=>cards.filter(c=>!c.hidden).forEach(c=>{c.closest('.nic-group').open=true;c.open=true;}));document.getElementById('collapse').addEventListener('click',()=>cards.forEach(c=>c.open=false));
search.addEventListener('input',filter);active.addEventListener('change',filter);document.getElementById('print').addEventListener('click',()=>{document.querySelectorAll('details').forEach(d=>d.open=true);window.print();});filter();
</script></main></body></html>)";
    auto html=h.str();need(html.size()<=20*1024*1024,"HTML report size limit exceeded.");return html;
}

int analyze_main(const std::vector<std::wstring>& args) {
    if(args.size()==2&&args[1]==L"--help") {
        console_text("Usage: FetchNetworkConfig.exe analyze <result-folder-or-zip> [--output <existing local folder>]\n"
            "       [--date YYYY-MM-DD] [--utc-offset +HH:MM|-HH:MM] (default +09:00)\n"
            "       [--log-utc-offset +HH:MM|-HH:MM] (explicit SDK source timezone)\n"
            "No administrator/Python required. Reads saved evidence only. Writes analysis.html in a new folder.\n"
            "With --date, also exports selected-events.csv and selected-events.jsonl with original file/line references.\n"
            "Default output: beside this EXE. Exit 0 complete, 1 partial evidence, 2 invalid input/output.\n");return 0;
    }
    need(args.size()>=2,"Usage: analyze <result-folder-or-zip> [--output <folder>] [--date YYYY-MM-DD] [--utc-offset +HH:MM|-HH:MM]");
    fs::path parent_path=executable_path().parent_path();std::string date,offset="+09:00";std::optional<std::string> log_offset;std::set<std::wstring> seen;
    for(size_t i=2;i<args.size();i+=2) {
        const auto& key=args[i];need(key==L"--output"||key==L"--date"||key==L"--utc-offset"||key==L"--log-utc-offset","Unknown analyze option.");
        need(seen.insert(key).second&&i+1<args.size(),"Duplicate option or missing option value.");
        if(key==L"--output")parent_path=args[i+1];else if(key==L"--date")date=utf8(args[i+1]);else if(key==L"--log-utc-offset"){log_offset=utf8(args[i+1]);utc_offset_minutes(*log_offset);}else offset=utf8(args[i+1]);
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
    console_text("저장된 증거 무결성 확인 및 분석 중...\n");auto files=load_evidence(input);auto report=analyze_evidence(files,filter,log_offset);auto html=analysis_html(report);
    std::string csv,jsonl;if(filter){csv=selected_events_csv(report);jsonl=selected_events_jsonl(report);}
    auto root=Output::create_run(parent,"FetchNetworkAnalysis-");Output output(root);output.write("analysis.html",html);
    if(filter){output.write("selected-events.csv",csv);output.write("selected-events.jsonl",jsonl);console_text("추출 날짜: "+date+" UTC"+offset+" / Windows 이벤트 "+field(report,"event_count")+"개, SetupAPI "+std::to_string(arr(report,"setupapi").size())+"개, SDK "+field(report,"sdk_event_count")+"개 (UTC 미확정 제외 "+field(report,"undated_sdk_count")+"개)\n");}
    console_text("분석 보고서: "+utf8(output.file("analysis.html").native())+"\n"
        "이벤트 "+field(report,"event_count")+"개 / "+(report.at("incomplete").get<bool>()?"일부 수집/증거 누락 있음":"접근 가능한 증거 분석 완료")+"\n");
    return report.at("incomplete").get<bool>()?1:0;
}
} // namespace fnc
