#include "common.hpp"
#include <algorithm>
#include <sstream>
#include <cctype>

namespace fnc {
namespace {
std::wstring xml_escape(std::wstring_view s) {
    std::wstring out;for(wchar_t c:s) {if(c==L'&')out+=L"&amp;";else if(c==L'\'')out+=L"&apos;";else if(c==L'<')out+=L"&lt;";else if(c==L'>')out+=L"&gt;";else if(c==L'\"')out+=L"&quot;";else out+=c;}return out;
}
std::string artifact_name(std::string_view channel) {
    std::string name="events-"; for(char c:channel)name+=((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-')?c:'_';return name+".jsonl";
}
std::vector<BYTE> render_values(EVT_HANDLE context,EVT_HANDLE event) {
    DWORD bytes=0,count=0;
    if(!EvtRender(context,event,EvtRenderEventValues,0,nullptr,&bytes,&count) && GetLastError()!=ERROR_INSUFFICIENT_BUFFER)fail_win("Render event system fields");
    if(bytes>1024*1024)throw std::runtime_error("Event system-field size limit exceeded.");
    std::vector<BYTE> data(bytes);
    if(!EvtRender(context,event,EvtRenderEventValues,bytes,data.data(),&bytes,&count))fail_win("Render event values");
    return data;
}
std::string event_xml(EVT_HANDLE event) {
    DWORD bytes=0,count=0;
    if(!EvtRender(nullptr,event,EvtRenderEventXml,0,nullptr,&bytes,&count) && GetLastError()!=ERROR_INSUFFICIENT_BUFFER)fail_win("Render original event XML");
    if(bytes>1024*1024)throw std::runtime_error("Event XML exceeds 1 MiB limit.");
    std::vector<wchar_t> xml(bytes/2+1);
    if(!EvtRender(nullptr,event,EvtRenderEventXml,bytes,xml.data(),&bytes,&count))fail_win("Render XML");
    return utf8(xml.data());
}
Json system_fields(EVT_HANDLE context,EVT_HANDLE event) {
    auto data=render_values(context,event);auto* v=reinterpret_cast<EVT_VARIANT*>(data.data());
    auto text=[&](int i){return v[i].Type==EvtVarTypeString && v[i].StringVal?utf8(v[i].StringVal):std::string();};
    Json j{{"provider",text(EvtSystemProviderName)},{"channel",text(EvtSystemChannel)},{"computer",text(EvtSystemComputer)}};
    j["event_id"]=v[EvtSystemEventID].UInt16Val;j["record_id"]=v[EvtSystemEventRecordId].UInt64Val;
    j["level"]=v[EvtSystemLevel].ByteVal;
    if(v[EvtSystemTimeCreated].Type==EvtVarTypeFileTime) {j["time_utc"]=iso_time(v[EvtSystemTimeCreated].FileTimeVal);j["time_local"]=local_time(v[EvtSystemTimeCreated].FileTimeVal);}
    else {j["time_utc"]=nullptr;j["time_local"]=nullptr;}
    return j;
}
Json channel_metadata(std::wstring_view channel) {
    Json info=Json::object(); std::wstring c(channel);EventHandle cfg(EvtOpenChannelConfig(nullptr,c.c_str(),0));
    if(!cfg.value) {info["metadata_error"]=win_error(GetLastError());return info;}
    for(auto [id,key]:std::vector<std::pair<EVT_CHANNEL_CONFIG_PROPERTY_ID,const char*>>{{EvtChannelConfigEnabled,"enabled"},
        {EvtChannelLoggingConfigRetention,"retention"},{EvtChannelLoggingConfigAutoBackup,"auto_backup"},{EvtChannelLoggingConfigMaxSize,"max_size_bytes"}}) {
        EVT_VARIANT value{};DWORD n=0;
        if(EvtGetChannelConfigProperty(cfg.value,id,0,sizeof(value),&value,&n)) {
            if(value.Type==EvtVarTypeBoolean)info[key]=value.BooleanVal!=FALSE;
            else if(value.Type==EvtVarTypeUInt64)info[key]=value.UInt64Val;
        }
    }
    EventHandle log(EvtOpenLog(nullptr,c.c_str(),EvtOpenChannelPath));
    if(log.value)for(auto [id,key]:std::vector<std::pair<EVT_LOG_PROPERTY_ID,const char*>>{{EvtLogNumberOfLogRecords,"retained_record_count"},{EvtLogOldestRecordNumber,"oldest_record_number"}}) {
        EVT_VARIANT value{};DWORD n=0;if(EvtGetLogInfo(log.value,id,sizeof(value),&value,&n)&&value.Type==EvtVarTypeUInt64)info[key]=value.UInt64Val;
    }
    EventHandle context(EvtCreateRenderContext(0,nullptr,EvtRenderContextSystem));
    if(context.value)for(auto [direction,key]:std::vector<std::pair<DWORD,const char*>>{{EvtQueryForwardDirection,"oldest_retained_event"},{EvtQueryReverseDirection,"newest_retained_event"}}) {
        EventHandle query(EvtQuery(nullptr,c.c_str(),L"*",EvtQueryChannelPath|direction));if(!query.value)continue;
        EVT_HANDLE raw=nullptr;DWORD n=0;if(EvtNext(query.value,1,&raw,1000,0,&n)&&n) {EventHandle event(raw);info[key]=system_fields(context.value,event.value);}
    }
    return info;
}
bool interesting_impl(const Json& event,std::string_view channel,const Json& input) {
    auto provider=lower(event.value("provider",""));auto xml=lower(event.value("xml",""));auto id=event.value("event_id",0);
    if(channel=="Security")return id==1102 || (id==4657 && (xml.find("\\services\\tcpip\\")!=std::string::npos ||
        xml.find("\\services\\tcpip6\\")!=std::string::npos || xml.find("{4d36e972-e325-11ce-bfc1-08002be10318}")!=std::string::npos));
    if(channel=="Application") {
        if(provider=="msiinstaller")return true;
        for(auto word:{"gige","genicam","pylon","basler","vimba","spinnaker","camera","lucid","baumer","pleora","teledyne","hikrobot","sapera","huaray","mvsdk"})if(provider.find(word)!=std::string::npos)return true;
        bool incident=(provider=="application error"&&id==1000)||(provider=="application hang"&&id==1002)||(provider=="windows error reporting"&&id==1001)||(provider==".net runtime"&&id==1026);
        if(incident) {
            for(auto word:{"mvsdk","mvviewer","camclient","huaray","genicam","gige","pylon","basler","vimba","spinnaker","hikrobot","sapera","pleora","baumer","teledyne","lucid","camera"})if(xml.find(word)!=std::string::npos)return true;
            for(const auto& app:input.value("app_names",Json::array()))if(app.is_string()){
                auto text=lower(app.get<std::string>());size_t at=0;
                while((at=xml.find(text,at))!=std::string::npos){auto boundary=[](unsigned char c){return !std::isalnum(c)&&c!='_'&&c!='-'&&c!='.';};if((!at||boundary(xml[at-1]))&&(at+text.size()==xml.size()||boundary(xml[at+text.size()])))return true;++at;}
            }
        }
        return false;
    }
    if(channel=="mvGenICamForEthernet")return provider=="mvgenicamforethernet";
    if(channel!="System")return true;
    if(provider=="mvgenicamforethernet")return false;
    for(auto word:{"tcpip","dhcp","ndis","network","kernel-pnp","userpnp","kernel-power","power-troubleshooter","kernel-boot","kernel-general","eventlog"})if(provider.find(word)!=std::string::npos)return true;
    if(input.contains("nic_tokens"))for(const auto& token:input["nic_tokens"])if(token.is_string()) {
        auto t=lower(token.get<std::string>());if(t.size()>=5&&(provider==t||xml.find(t)!=std::string::npos))return true;
    }
    return false;
}
std::string decode_log(std::string_view bytes,std::string& encoding) {
    if(bytes.size()>=2 && static_cast<unsigned char>(bytes[0])==0xff && static_cast<unsigned char>(bytes[1])==0xfe) {
        std::wstring text((bytes.size()-2)/2,L'\0');if(!text.empty())memcpy(text.data(),bytes.data()+2,text.size()*2);encoding="UTF-16LE";return utf8(text);
    }
    auto s=bytes;if(s.starts_with("\xef\xbb\xbf"))s.remove_prefix(3);
    int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),int(s.size()),nullptr,0);
    if(n>0 || s.empty()) {encoding="UTF-8";return std::string(s);}
    n=MultiByteToWideChar(CP_ACP,0,s.data(),int(s.size()),nullptr,0);std::wstring text(n,L'\0');
    if(n)MultiByteToWideChar(CP_ACP,0,s.data(),int(s.size()),text.data(),n);encoding="Windows ANSI code page "+std::to_string(GetACP());return utf8(text);
}
struct LogSlice {std::string bytes;Json metadata;};
LogSlice log_tail(const fs::path& path,size_t limit) {
    ensure_local_path(path);Handle h(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));if(!h)fail_win("Open existing log");
    if(GetFileType(h.get())!=FILE_TYPE_DISK)throw std::runtime_error("Log input is not a regular disk file.");
    BY_HANDLE_FILE_INFORMATION before{},after{};if(!GetFileInformationByHandle(h.get(),&before))fail_win("Log metadata");
    if(before.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))throw std::runtime_error("Log must be a regular file without reparse points.");
    ULONGLONG size=(ULONGLONG(before.nFileSizeHigh)<<32)|before.nFileSizeLow;
    ULONGLONG offset=size>limit?size-limit:0;
    char bom[3]{};DWORD bn=0;if(!ReadFile(h.get(),bom,3,&bn,nullptr))fail_win("Log encoding probe");
    bool utf16=bn>=2&&static_cast<unsigned char>(bom[0])==0xff&&static_cast<unsigned char>(bom[1])==0xfe;
    if(utf16 && offset%2)++offset;
    LARGE_INTEGER position{};position.QuadPart=static_cast<LONGLONG>(offset);if(!SetFilePointerEx(h.get(),position,nullptr,FILE_BEGIN))fail_win("Read log tail offset");
    LogSlice slice; slice.bytes.resize(static_cast<size_t>(size-offset));size_t done=0;
    while(done<slice.bytes.size()) {DWORD n=0;if(!ReadFile(h.get(),slice.bytes.data()+done,DWORD((std::min)(slice.bytes.size()-done,size_t(65536))),&n,nullptr))fail_win("Read existing log");if(!n)break;done+=n;}
    slice.bytes.resize(done);if(!GetFileInformationByHandle(h.get(),&after))fail_win("Log final metadata");
    auto modified=[](const BY_HANDLE_FILE_INFORMATION& i){return (ULONGLONG(i.ftLastWriteTime.dwHighDateTime)<<32)|i.ftLastWriteTime.dwLowDateTime;};
    bool changed=modified(before)!=modified(after)||before.nFileSizeHigh!=after.nFileSizeHigh||before.nFileSizeLow!=after.nFileSizeLow||done!=size-offset;
    slice.metadata={{"path",utf8(path.native())},{"source_size_before",size},{"source_size_after",(ULONGLONG(after.nFileSizeHigh)<<32)|after.nFileSizeLow},
        {"source_modified_before_utc",iso_time(modified(before))},{"source_modified_after_utc",iso_time(modified(after))},
        {"copied_offset_bytes",offset},{"copied_bytes",done},{"tail_only",offset!=0},{"changed_during_read",changed},
        {"utf16le_detected",utf16}};
    return slice;
}
std::optional<ULONGLONG> setup_time(std::string_view block) {
    auto pos=block.find("Section start ");if(pos==std::string_view::npos)return {};std::string text(block.substr(pos+14,32));
    unsigned y=0,mo=0,d=0,h=0,mi=0,s=0,ms=0;
    int n=sscanf_s(text.c_str(),"%u/%u/%u %u:%u:%u.%u",&y,&mo,&d,&h,&mi,&s,&ms);if(n<6||y<1601||y>9999||mo<1||mo>12||d<1||d>31||h>23||mi>59||s>59||ms>999)return {};
    SYSTEMTIME local{};local.wYear=WORD(y);local.wMonth=WORD(mo);local.wDay=WORD(d);local.wHour=WORD(h);local.wMinute=WORD(mi);local.wSecond=WORD(s);local.wMilliseconds=WORD(ms);
    SYSTEMTIME utc{};if(!TzSpecificLocalTimeToSystemTimeEx(nullptr,&local,&utc))return {};FILETIME ft{};if(!SystemTimeToFileTime(&utc,&ft))return {};
    return (ULONGLONG(ft.dwHighDateTime)<<32)|ft.dwLowDateTime;
}
} // namespace

bool event_interesting(const Json& e,std::string_view channel,const Json& input){return interesting_impl(e,channel,input);}

Json collect_events(std::string_view channel,const Json& input,const Output& output) {
    auto r=result("Windows Event Log:"+std::string(channel));auto name=wide(channel=="mvGenICamForEthernet"?"System":channel);r["channel"]=utf8(name);
    r["metadata"]=channel_metadata(name);r["requested_from_utc"]=input.at("from_utc");r["requested_to_utc"]=input.at("to_utc");
    auto expression=L"*[System[TimeCreated[@SystemTime >= '"+xml_escape(wide(input.at("from_utc").get<std::string>()))+
        L"' and @SystemTime <= '"+xml_escape(wide(input.at("to_utc").get<std::string>()))+L"']";
    if(channel=="Security")expression+=L" and (EventID=4657 or EventID=1102)";
    if(channel=="mvGenICamForEthernet")expression+=L" and Provider[@Name='mvGenICamForEthernet']";
    if(channel=="System")expression+=L" and Provider[@Name!='mvGenICamForEthernet']";
    expression+=L"]]";
    EventHandle query(EvtQuery(nullptr,name.c_str(),expression.c_str(),EvtQueryChannelPath|EvtQueryReverseDirection));
    if(!query.value) {auto e=GetLastError();issue(r,e==ERROR_ACCESS_DENIED?"access_denied":e==ERROR_EVT_CHANNEL_NOT_FOUND?"missing":"error",win_error(e),e);return r;}
    EventHandle context(EvtCreateRenderContext(0,nullptr,EvtRenderContextSystem));if(!context.value)fail_win("Event render context");
    auto filename=artifact_name(channel);auto file=output.create(filename);r["artifacts"].push_back(filename);
    size_t kept=0,scanned=0,bytes=0;bool limit=false;auto count_limit=(std::min)(kEventCount,input.value("history_remaining",kEventCount));
    std::set<std::string> failed_messages;
    while(scanned<200000 && kept<count_limit) {
        EVT_HANDLE raw=nullptr;DWORD n=0;
        if(!EvtNext(query.value,1,&raw,1000,0,&n)) {auto e=GetLastError();if(e==ERROR_NO_MORE_ITEMS)break;issue(r,"partial","Event enumeration: "+win_error(e),e);break;}
        EventHandle event(raw);++scanned;
        try {
            auto j=system_fields(context.value,event.value);j["xml"]=event_xml(event.value);
            if(!event_interesting(j,channel,input))continue;
            j["matched_identifier_tokens"]=Json::array();auto text=lower(j["xml"].get<std::string>());
            if(input.contains("nic_tokens"))for(const auto& token:input["nic_tokens"]) {auto t=lower(token.get<std::string>());if(t.size()>=5&&text.find(t)!=std::string::npos)j["matched_identifier_tokens"].push_back(token);}
            j["message"]=nullptr;j["message_status"]="unavailable";
            auto provider=j.value("provider","");
            if(!provider.empty() && !failed_messages.contains(provider)) {
                EventHandle meta(EvtOpenPublisherMetadata(nullptr,wide(provider).c_str(),nullptr,0,0));
                if(meta.value) {
                    DWORD count=0;
                    if(!EvtFormatMessage(meta.value,event.value,0,0,nullptr,EvtFormatMessageEvent,0,nullptr,&count)&&GetLastError()==ERROR_INSUFFICIENT_BUFFER&&count<32768) {
                        std::vector<wchar_t> message(count);
                        if(EvtFormatMessage(meta.value,event.value,0,0,nullptr,EvtFormatMessageEvent,count,message.data(),&count)) {j["message"]=utf8(message.data());j["message_status"]="rendered";}
                        else j["message_error_code"]=GetLastError();
                    } else j["message_error_code"]=GetLastError();
                } else {failed_messages.insert(provider);j["message_error_code"]=GetLastError();}
            }
            auto line=json_text(j)+"\n";if(bytes+line.size()>kEventBytes){limit=true;break;}
            write_all(file.get(),line);bytes+=line.size();++kept;
        } catch(const std::exception& e) {issue(r,"partial",e.what());if(r["issues"].size()>20)break;}
    }
    if(scanned>=200000||kept>=count_limit||limit)issue(r,"partial","Event scan/count/byte/shared history limit reached; newest matching records were kept.");
    if(!kept && r["status"]=="ok")r["status"]="empty";
    r["scanned_count"]=scanned;r["selected_count"]=kept;r["bytes"]=bytes;
    r["coverage_note"]="Existing retained events only. Reverse scan, no log activation, subscription, trace, clear, export-and-clear, or audit changes. Identifier matches are textual evidence links, not attribution of a configuration change. Missing localized messages do not invalidate the original XML.";
    return r;
}

std::wstring evtx_record_query(std::string_view channel,const std::vector<uint64_t>& ids) {
    if(channel!="System"&&channel!="Application")throw std::runtime_error("Invalid EVTX export channel.");
    auto path=wide(channel);std::wstring q=L"<QueryList><Query Id='0' Path='"+path+L"'>";
    for(size_t i=0;i<ids.size();i+=16){q+=L"<Select Path='"+path+L"'>*[System[";
        for(size_t j=i;j<(std::min)(ids.size(),i+16);++j){if(j!=i)q+=L" or ";q+=L"EventRecordID="+std::to_wstring(ids[j]);}q+=L"]]</Select>";}
    return q+L"</Query></QueryList>";
}
Json export_selected_evtx(const Json&,const Output& output) {
    auto r=result("Optional selected native event evidence");r["exports"]=Json::array();uint64_t total=0;
    for(auto channel:{"System","Application"}) {
        std::set<uint64_t> selected;
        for(auto source:{artifact_name(channel),std::string(channel)=="System"?artifact_name("mvGenICamForEthernet"):std::string()}) {
            if(source.empty()||!fs::exists(output.file(source)))continue;std::istringstream stream(read_local_file(output.file(source),kEventBytes));std::string line;
            while(std::getline(stream,line)){if(line.empty())continue;try{auto e=Json::parse(line);selected.insert(e.at("record_id").get<uint64_t>());}catch(...){issue(r,"partial","Incomplete JSONL record omitted from EVTX query.");}}
        }
        if(selected.empty())continue;std::vector<uint64_t> ids(selected.begin(),selected.end());auto q=evtx_record_query(channel,ids);auto name=std::string("selected-")+channel+".evtx";auto target=output.file(name);
        // EvtExportLog requires a nonexistent target. Output validates the absolute flat path.
        if(fs::exists(target))throw std::runtime_error("EVTX output already exists.");
        if(!EvtExportLog(nullptr,nullptr,q.c_str(),target.c_str(),EvtExportLogChannelPath)){issue(r,"partial","EVTX export failed for "+std::string(channel),GetLastError());continue;}
        ensure_local_path(target);auto size=fs::file_size(target);if(size>32ULL*1024*1024||size>64ULL*1024*1024-total){issue(r,"partial","EVTX export exceeded optional file/total limits; excluded from the bundle.");continue;}
        // Export can race log rollover. Compare IDs rather than claiming a complete copy.
        EventHandle query(EvtQuery(nullptr,target.c_str(),L"*",EvtQueryFilePath));EventHandle context(EvtCreateRenderContext(0,nullptr,EvtRenderContextSystem));std::set<uint64_t> actual;
        if(query.value&&context.value)while(true){EVT_HANDLE raw=nullptr;DWORD n=0;if(!EvtNext(query.value,1,&raw,1000,0,&n))break;EventHandle e(raw);actual.insert(system_fields(context.value,e.value).at("record_id").get<uint64_t>());if(actual.size()>ids.size())break;}
        if(actual!=selected){issue(r,"partial","EVTX Record IDs differ from selected JSONL (possibly rollover); excluded from bundle.");continue;}
        total+=size;r["artifacts"].push_back(name);r["exports"].push_back({{"channel",channel},{"selected_count",ids.size()},{"record_ids_verified",true},{"size_bytes",size}});
    }
    return r;
}
std::vector<std::string> setupapi_blocks(std::string_view text,const std::vector<std::string>& ids,ULONGLONG from,ULONGLONG to) {
    std::vector<std::string> out;size_t start=0;
    while((start=text.find(">>>  [",start))!=std::string_view::npos) {
        auto next=text.find(">>>  [",start+6);auto block=text.substr(start,next==std::string_view::npos?text.size()-start:next-start);
        auto folded=lower(std::string(block));bool match=false;for(const auto& id:ids)if(id.size()>=8&&folded.find(lower(id))!=std::string::npos){match=true;break;}
        auto time=setup_time(block);
        // Preserve matching undated sections instead of inventing a timestamp.
        if(match && (!time || (*time>=from&&*time<=to)))out.emplace_back(block);
        if(next==std::string_view::npos)break;start=next;
    }
    return out;
}
Json collect_setupapi(const Json& input,const Output& output) {
    auto r=result("Existing SetupAPI.dev.log NIC sections");wchar_t windows[32768]{};UINT n=GetWindowsDirectoryW(windows,32768);if(!n||n>=32768)fail_win("Windows directory");
    if(!input.contains("device_ids")||input["device_ids"].empty()) {issue(r,"not_collected","No network device IDs were available for reliable SetupAPI section matching.");return r;}
    auto path=fs::path(windows)/L"INF"/L"setupapi.dev.log";std::error_code ec;
    if(!fs::exists(path,ec)) {issue(r,"missing",ec?ec.message():"SetupAPI.dev.log does not exist.");return r;}
    auto slice=log_tail(path,32*1024*1024);r["file_metadata"]=slice.metadata;
    std::string bytes=slice.bytes;
    if(slice.metadata["tail_only"]==true && slice.metadata["utf16le_detected"]==true)bytes.insert(0,"\xff\xfe",2);
    std::string encoding;auto text=decode_log(bytes,encoding);r["decoded_encoding"]=encoding;
    std::vector<std::string> ids=input.value("device_ids",std::vector<std::string>());
    auto from=*parse_iso_time(input.at("from_utc").get<std::string>()),to=*parse_iso_time(input.at("to_utc").get<std::string>());
    auto blocks=setupapi_blocks(text,ids,from,to);auto file=output.create("setupapi-nic.log");auto timeline=output.create("setupapi-timeline.jsonl");
    r["artifacts"].push_back("setupapi-nic.log");r["artifacts"].push_back("setupapi-timeline.jsonl");size_t kept=0,total=0;
    for(const auto& block:blocks) {
        if(total+block.size()>8*1024*1024||kept>=kSetupSectionCount){issue(r,"partial","SetupAPI output size/section limit reached.");break;}
        write_all(file.get(),block);auto timestamp=setup_time(block);auto title_end=block.find('\n');
        Json j{{"channel","SetupAPI"},{"provider","SetupAPI"},{"event_id",nullptr},{"record_id",nullptr},
            {"message",block.substr(0,title_end)},{"time_utc",timestamp?Json(iso_time(*timestamp)):Json(nullptr)},
            {"time_local",timestamp?Json(local_time(*timestamp)):Json(nullptr)},{"artifact","setupapi-nic.log"},{"byte_offset",total},
            {"byte_length",block.size()},{"timestamp_interpretation","Local source timestamp interpreted using the PC's current Windows time-zone rules; historical time-zone changes are not reconstructed."}};
        write_all(timeline.get(),json_text(j)+"\n");total+=block.size();++kept;
    }
    r["selected_sections"]=kept;
    if(slice.metadata["tail_only"]==true)issue(r,"partial","Only the final 32 MiB of SetupAPI.dev.log were scanned; older sections may be unavailable.");
    if(slice.metadata["changed_during_read"]==true)issue(r,"partial","Source log changed during read; this is not an atomic snapshot.");
    if(!kept && r["status"]=="ok")r["status"]="empty";
    r["coverage_note"]="NIC device-ID matches only; not a complete registry-setting history. Undated matching sections are preserved without inferred times. No log rotation or renaming.";return r;
}
Json copy_user_log(size_t index,const Json& input,const Output& output) {
    auto r=result("User-specified existing log");const auto& logs=input.at("log_files");if(index>=logs.size())throw std::runtime_error("Invalid log index.");
    auto path=fs::path(wide(logs[index].get<std::string>()));auto slice=log_tail(path,kUserLogBytes);r["file_metadata"]=slice.metadata;
    auto name="user-log-"+std::to_string(index+1)+".log";output.write(name,slice.bytes);r["artifacts"].push_back(name);
    if(slice.metadata["tail_only"]==true)issue(r,"partial","Only the final 16 MiB were copied; bytes and original offset are preserved without decoding.");
    if(slice.metadata["changed_during_read"]==true)issue(r,"partial","Log changed during read; copied data may span concurrent writes.");return r;
}
} // namespace fnc
