#include "sdk_logs.hpp"
#include <algorithm>
#include <regex>
#include <sstream>
#include <charconv>
#include <cmath>

namespace fnc {
namespace {
std::string decode(std::string_view b,bool utf16) {
    if(utf16){std::wstring w(b.size()/2,L'\0');if(!w.empty())memcpy(w.data(),b.data(),w.size()*2);if(!w.empty()&&w.front()==0xfeff)w.erase(0,1);return utf8(w);}
    if(b.starts_with("\xef\xbb\xbf"))b.remove_prefix(3);
    if(b.empty()||MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,b.data(),int(b.size()),nullptr,0)>0)return std::string(b);
    // The fallback is explicit in the source summary and never changes the copied bytes.
    int n=MultiByteToWideChar(949,0,b.data(),int(b.size()),nullptr,0);std::wstring w(n,L'\0');
    if(n)MultiByteToWideChar(949,0,b.data(),int(b.size()),w.data(),n);return utf8(w);
}
std::string capture(const std::string& s,const char* pattern) {
    static thread_local std::map<std::string,std::regex> patterns;auto it=patterns.find(pattern);if(it==patterns.end())it=patterns.emplace(pattern,std::regex(pattern,std::regex::icase)).first;
    std::smatch m;if(std::regex_search(s,m,it->second)&&m.size()>1)return m[1];return {};
}
Json numeric(std::string s) {
    if(s.empty())return nullptr;uint64_t n=0;auto r=std::from_chars(s.data(),s.data()+s.size(),n);
    if(r.ec==std::errc()&&r.ptr==s.data()+s.size())return n;
    try{size_t used=0;double d=std::stod(s,&used);if(used==s.size()&&std::isfinite(d))return d;}catch(...){}return s;
}
std::string pid_from(std::string_view file) {
    return capture(std::string(file),"[.]([0-9]+)[.](?:MVSDK|CamClient)[.]log$");
}
}
void SdkLogParser::begin(std::string source,std::string original,uint64_t base,bool utf16) {
    source_=std::move(source);original_=original.empty()?source_:std::move(original);pending_.clear();
    pid_=pid_from(original_);
    offset_=line_offset_=base_offset_=base;line_number_=recognized_=skipped_=0;utf16_=utf16;probed_=false;tail_=base!=0;oversized_=false;
}
void SdkLogParser::feed(std::string_view bytes) {
    // Input chunks are bounded by the caller. Carry at most one bounded line.
    for(char c:bytes) {
        ++offset_;pending_+=c;
        if(!probed_&&pending_.size()>=2){utf16_=utf16_||(static_cast<unsigned char>(pending_[0])==0xff&&static_cast<unsigned char>(pending_[1])==0xfe);probed_=true;}
        bool newline=utf16_?pending_.size()>=2&&offset_%2==0&&pending_[pending_.size()-2]=='\n'&&pending_.back()==0:c=='\n';
        if(pending_.size()>kSdkLineBytes){oversized_=true;pending_.erase(0,pending_.size()-(utf16_?2:1));}
        if(newline){++line_number_;if(oversized_||tail_){++skipped_;oversized_=tail_=false;}else line(pending_);pending_.clear();line_offset_=offset_;}
    }
}
void SdkLogParser::end() {
    if(!pending_.empty()){++line_number_;if(!oversized_&&!tail_)line(pending_);else ++skipped_;}
    files_.push_back({{"source_file",source_},{"original_path",original_},{"line_count",line_number_},{"recognized_lines",recognized_},{"skipped_lines",skipped_},
        {"encoding",utf16_?"UTF-16LE":"UTF-8 or CP949 fallback"},{"copied_offset_bytes",base_offset_},{"tail_only",base_offset_!=0},{"line_numbers_relative_to_copy",true},
        {"camera_ips",camera_ips_},{"reset_times",reset_times_},{"identities",identities_}});pending_.clear();camera_ips_.clear();reset_times_.clear();identities_=Json::array();
}
void SdkLogParser::line(std::string raw) {
    auto s=decode(raw,utf16_);while(!s.empty()&&(s.back()=='\n'||s.back()=='\r'))s.pop_back();auto l=lower(s);
    if(s.size()<24||s[4]!='-'||s[7]!='-'||s[10]!=' '||l.find("[tid:")==std::string::npos)return;
    bool sdk=lower(original_).find("mvsdk")!=std::string::npos||lower(original_).find("camclient")!=std::string::npos;
    for(auto token:{"mvsdk","gige","cameraimpl","cmvdevice","streamsourceimpl","cdevicemanager","mainwindow","discoverydevicethread"})if(l.find(token)!=std::string::npos)sdk=true;
    if(!sdk)return;++recognized_;
    // Camera addresses seen by the SDK ("... dev ip [169.254.1.2]") identify camera NICs; kept per file, outside the event budget.
    if(camera_ips_.size()<64)if(auto ip=capture(s,"dev ip[ :=]*\\[([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\]");!ip.empty())camera_ips_.insert(ip);
    // An application-issued DeviceReset reboots the camera, which drops the NIC link; kept to explain those link events.
    if(reset_times_.size()<20000&&l.find("devicereset")!=std::string::npos&&l.find("execute")!=std::string::npos)reset_times_.push_back(s.substr(0,23));
    // SDK/driver versions and camera identities are few but needed for the synthesis even after the event budget runs out.
    if(identities_.size()<64&&(l.find("mvsdk ver")!=std::string::npos||l.find("gige user")!=std::string::npos||l.find("vendor=[")!=std::string::npos)) {
        Json v={{"timestamp",s.substr(0,23)}};auto put=[&](const char* key,const char* pattern){auto value=capture(s,pattern);if(!value.empty())v[key]=value;};
        put("sdk_version","MVSDK ver(?:ison|sion)[:=]\\[([^\\]]+)\\]");put("gige_user_version","gige user[:=]\\[([^\\]]+)\\]");put("gige_kernel_version","gige kernel[:=]\\[([^\\]]+)\\]");
        put("vendor","Vendor=\\[([^\\]]+)\\]");put("model","Model=\\[([^\\]]+)\\]");put("serial_number","SerialNumber=\\[([^\\]]+)\\]");put("firmware_version","Version=\\[([^\\]]+)\\]");
        if(v.size()>1&&(identities_.empty()||identities_.back()!=v))identities_.push_back(std::move(v));
    }
    if(budget_exhausted_){++skipped_;return;}
    auto ts=s.substr(0,23);auto iso=ts;iso[10]='T';if(!parse_iso_time(iso+"Z"))return;
    std::string kind;Json fields=Json::object();
    auto set=[&](const char* key,const char* pattern,bool number=false){auto value=capture(s,pattern);if(!value.empty())fields[key]=number?numeric(value):Json(value);};
    if(l.find("mvsdk ver")!=std::string::npos){kind="version";set("sdk_version","MVSDK ver(?:ison|sion)[:=]\\[([^\\]]+)\\]");}
    if(l.find("gige user")!=std::string::npos){kind="version";set("gige_user_version","gige user[:=]\\[([^\\]]+)\\]");set("gige_kernel_version","gige kernel[:=]\\[([^\\]]+)\\]");}
    if(l.find("vendor=[")!=std::string::npos){kind="connect";set("vendor","Vendor=\\[([^\\]]+)\\]");set("model","Model=\\[([^\\]]+)\\]");set("serial_number","SerialNumber=\\[([^\\]]+)\\]");set("firmware_version","Version=\\[([^\\]]+)\\]");}
    if(l.find("opendevice")!=std::string::npos&&l.find("begin")!=std::string::npos)kind="connect";
    if(l.find("disconnect")!=std::string::npos&&l.find("begin")!=std::string::npos)kind="disconnect";
    if(l.find("startgrabbing")!=std::string::npos||l.find("acquisitionstart")!=std::string::npos)kind="start";
    if(l.find("stopgrabbing")!=std::string::npos||l.find("acquisitionstop")!=std::string::npos)kind="stop";
    if((kind=="start"||kind=="stop"||kind=="connect"||kind=="disconnect")&&(l.find(" begin.")!=std::string::npos||l.find(" begin!")!=std::string::npos))fields["boundary"]="begin";
    if((kind=="start"||kind=="stop"||kind=="disconnect")&&l.find(" end.")!=std::string::npos)fields["boundary"]="end";
    set("nic_mtu","get NIC MTU Value[ :]+([0-9]+)",true);set("mtu_90_percent","90 percent MTU[ :]+([0-9]+)",true);
    set("packet_size","negotiatePacketSize[ :]+([0-9]+)",true);
    set("heartbeat_timeout_ms","heartbeatTimeout[ :]+([0-9]+)",true);set("answer_timeout_ms","setAnswerTimeout[ :]+([0-9]+)",true);
    set("buffer_count","bufferCount[ :=\\[]+([0-9]+)",true);set("buffer_size","bufferSize[ :=\\[]+([0-9]+)",true);set("gev_scpd","GevSCPD[ :=\\[]+([0-9]+)",true);
    if(!fields.empty()&&kind.empty())kind="configuration";
    if(l.find("statistics info")!=std::string::npos){kind="statistics";
        for(auto key:{"softwareTrigger","imageReceived","fps","lostPacket","resendPacket","errorImage","lostPacketImage","overrideImage","missingBlock"}) {
            auto pattern=std::string(key)+"=\\[([0-9.]+)\\]";set(key,pattern.c_str(),true);
        }set("serial_number","SerialNumber=\\[([^\\]]+)\\]");}
    auto severity=capture(s,"[0-9] (INFO|ERROR|WARN|WARNING|DEBUG|TRACE) ");
    if(severity=="ERROR"||severity=="WARN"||severity=="WARNING") {
        if(kind.empty())kind="diagnostic";
        fields["family"]=l.find("binning")!=std::string::npos?"unsupported_binning":l.find("pixelsize")!=std::string::npos?"unsupported_pixel_size":l.find("not grabbing")!=std::string::npos?"not_grabbing_transition":l.find("timeout")!=std::string::npos?"timeout":l.find("open file error")!=std::string::npos?"resource_open":"other";
    }
    if(kind.empty())return;
    Json e={{"kind",kind},{"source_file",source_},{"source_line",line_number_},{"source_byte_offset",line_offset_},{"original_timestamp",ts},{"time_utc",nullptr},
        {"pid",pid_},{"thread_id",capture(s,"\\[tid:([0-9]+)\\]")},{"level",severity},{"fields",fields},{"message",s}};
    auto size=json_text(e).size()+1;if(events_.size()>=kSdkEventCount||retained_bytes_+size>kSdkEventBytes){++skipped_;budget_exhausted_=true;return;}
    retained_bytes_+=size;events_.push_back(std::move(e));
}
Json sdk_summary(Json events,Json sources,const std::optional<std::string>& offset) {
    if(offset)utc_offset_minutes(*offset);Json sessions=Json::array(),versions=Json::array(),retained=Json::array();std::map<std::string,size_t> active;std::map<std::string,Json> last_fields;size_t bytes=0;bool limited=false;
    for(auto& e:events) {
        auto ts=e.value("original_timestamp","");e["time_utc"]=nullptr;
        if(offset&&ts.size()>=19){ts[10]='T';auto ticks=parse_iso_time(ts+*offset);if(ticks)e["time_utc"]=iso_time(*ticks);}
        auto key=e.value("source_file","")+":"+e.value("pid","");auto kind=e.value("kind","");
        if(!active.contains(key)||kind=="connect"||(kind=="start"&&e["fields"].value("boundary","")=="begin")) {
            active[key]=sessions.size();sessions.push_back({{"id",key+":"+std::to_string(sessions.size()+1)},{"source_file",e["source_file"]},{"pid",e["pid"]},
                {"first_timestamp",e["original_timestamp"]},{"last_timestamp",e["original_timestamp"]},{"event_count",0},{"error_count",0},{"warning_count",0},{"fields",last_fields.contains(key)?last_fields[key]:Json::object()},{"families",Json::object()},{"statistics",Json::array()}});
        }
        auto& session=sessions[active[key]];e["session_id"]=session["id"];auto size=json_text(e).size()+1;if(bytes+size>kSdkEventBytes){limited=true;break;}bytes+=size;retained.push_back(e);session["last_timestamp"]=e["original_timestamp"];
        session["event_count"]=session["event_count"].get<size_t>()+1;auto level=e.value("level","");
        if(level=="ERROR")session["error_count"]=session["error_count"].get<size_t>()+1;
        if(level=="WARN"||level=="WARNING")session["warning_count"]=session["warning_count"].get<size_t>()+1;
        if(kind=="version")versions.push_back({{"source_file",e["source_file"]},{"source_line",e["source_line"]},{"fields",e["fields"]}});
        if(kind=="statistics")session["statistics"].push_back({{"source_line",e["source_line"]},{"fields",e["fields"]}});
        else for(const auto& [name,value]:e["fields"].items())if(name!="family"&&name!="boundary"){session["fields"][name]=value;last_fields[key][name]=value;}
        if(e["fields"].contains("family")){auto f=e["fields"]["family"].get<std::string>();session["families"][f]=session["families"].value(f,size_t(0))+1;}
        if(kind=="disconnect"||(kind=="stop"&&e["fields"].value("boundary","")=="end")){session["ended_by"]=kind;active.erase(key);}
    }
    size_t skipped=0;for(const auto& s:sources)if(s.value("recognized_lines",size_t(0)))skipped+=s.value("skipped_lines",size_t(0))+(s.value("tail_only",false)?1:0);
    return {{"schema_version",1},{"utc_offset",offset?Json(*offset):Json(nullptr)},{"events",retained},{"sources",sources},{"sessions",sessions},{"versions",versions},{"truncated",skipped!=0||limited},
        {"interpretation_note","ERROR counts, unsupported parameters and grabbing transitions alone do not establish a network failure or crash cause. Runtime SDK, installed software and dump module versions are separate observations."}};
}
Json SdkLogParser::finish(const std::optional<std::string>& offset) {return sdk_summary(events_,files_,offset);}
bool mvsdk_log_name(std::string_view name) {
    for(size_t i=1;i<=kMvSdkLogCount;++i)if(name=="mvsdk-log-"+std::to_string(i)+".log")return true;return false;
}
bool sdk_log_name(std::string_view name) {
    for(size_t i=1;i<=kUserLogCount;++i)if(name=="user-log-"+std::to_string(i)+".log")return true;return mvsdk_log_name(name);
}
Json sdk_log_metadata(const Json& modules,std::string_view name) {
    for(const auto& m:modules) {
        if(m.contains("files")&&m["files"].is_array())for(const auto& file:m["files"])
            if(file.value("artifact","")==name)return file.value("file_metadata",Json::object());
        if(m.contains("artifacts")&&m["artifacts"].is_array()&&std::find(m["artifacts"].begin(),m["artifacts"].end(),Json(std::string(name)))!=m["artifacts"].end()&&m.contains("file_metadata"))return m["file_metadata"];
    }
    return Json::object();
}
Json collect_sdk_logs(const Json& input,const Output& output) {
    auto r=result("Automatic and explicit SDK log analysis");SdkLogParser parser;
    auto parse=[&](const std::string& name,const std::string& original,const Json& meta){
        parser.begin(name,original,meta.value("copied_offset_bytes",uint64_t(0)),meta.value("utf16le_detected",false));
        Handle h(CreateFileW(output.file(name).c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,nullptr));if(!h)fail_win("Read copied SDK log");
        char b[65536];DWORD n=0;while(true){if(!ReadFile(h.get(),b,sizeof(b),&n,nullptr))fail_win("SDK log stream");if(!n)break;parser.feed(std::string_view(b,n));}parser.end();
    };
    for(size_t i=0;i<input.at("log_files").size();++i) {
        auto name="user-log-"+std::to_string(i+1)+".log";if(!fs::exists(output.file(name)))continue;
        Json meta=Json::object();if(input.contains("log_metadata")&&input["log_metadata"].size()>i)meta=input["log_metadata"][i];
        parse(name,input["log_files"][i].get<std::string>(),meta);
    }
    if(fs::exists(output.file("mvsdk-index.json"))) {
        auto index=Json::parse(read_local_file(output.file("mvsdk-index.json"),2*1024*1024));
        for(const auto& file:index.at("files")) {
            auto name=file.at("artifact").get<std::string>();const auto& meta=file.at("file_metadata");
            if(!mvsdk_log_name(name)||!meta.contains("copied_bytes")||!fs::exists(output.file(name)))continue;
            parse(name,meta.at("path").get<std::string>(),meta);
        }
    }
    std::optional<std::string> offset;if(input.contains("log_utc_offset")&&input["log_utc_offset"].is_string())offset=input["log_utc_offset"].get<std::string>();
    auto summary=parser.finish(offset);std::string lines;
    for(const auto& e:summary["events"]){auto line=json_text(e)+"\n";if(lines.size()+line.size()>kSdkEventBytes){summary["truncated"]=true;break;}lines+=line;}
    output.write("sdk-events.jsonl",lines);summary.erase("events");output.write("sdk-summary.json",json_text(summary,2)+"\n");
    r["artifacts"]={"sdk-events.jsonl","sdk-summary.json"};r["summary"]=summary;
    if(summary["sources"].empty())r["status"]="empty";
    if(summary["truncated"]==true)issue(r,"partial","SDK count/byte/line limits or copied tail omitted records.");return r;
}
}
