#include "common.hpp"
#include "sdk_logs.hpp"
#include "analyzer.hpp"
#include <winioctl.h>
#include <iostream>

using namespace fnc;
namespace {
void require(bool value,const char* message){if(!value)throw std::runtime_error(message);}
fs::path directory(const fs::path& parent,const wchar_t* name) {
    auto path=parent/name;require(CreateDirectoryW(path.c_str(),nullptr)!=FALSE,"Create fixture directory");return path;
}
void put(const fs::path& app,std::string_view name,std::string_view bytes,uint64_t modified) {
    Output source(app);auto file=source.create(name);write_all(file.get(),bytes);FILETIME time{DWORD(modified),DWORD(modified>>32)};
    require(SetFileTime(file.get(),nullptr,nullptr,&time)!=FALSE,"Set fixture modification time");
}
Json input_for(const Output& output) {
    return {{"output_dir",utf8(output.root().native())},{"from_utc","2026-10-01T00:00:00Z"},{"to_utc","2026-10-12T00:00:00Z"},
        {"incident_time",nullptr},{"camera_mac",nullptr},{"expected_camera_ip",nullptr},{"log_files",Json::array()},{"log_metadata",Json::array()},{"log_utc_offset","+09:00"}};
}
void manifest(EvidenceFiles& files) {
    Json entries=Json::array();for(const auto& [name,bytes]:files)if(name!="manifest.json") {
        auto streamed=files.streamed_digests().find(name);auto digest=streamed==files.streamed_digests().end()?EvidenceDigest{bytes.size(),sha256_bytes(bytes)}:streamed->second;
        entries.push_back({{"name",name},{"size_bytes",digest.size_bytes},{"sha256",digest.sha256}});
    }files["manifest.json"]=json_text(Json{{"files",entries}});
}
void junction(const fs::path& link,const fs::path& target) {
    require(CreateDirectoryW(link.c_str(),nullptr)!=FALSE,"Create junction fixture directory");
    Handle folder(CreateFileW(link.c_str(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    require(bool(folder),"Open junction fixture directory");
    struct Header {DWORD tag;WORD bytes,reserved,substitute_offset,substitute_bytes,print_offset,print_bytes;};
    auto substitute=L"\\??\\"+target.native(),print=target.native();
    Header header{IO_REPARSE_TAG_MOUNT_POINT,0,0,0,WORD(substitute.size()*2),WORD((substitute.size()+1)*2),WORD(print.size()*2)};
    static_assert(sizeof(Header)==16);std::vector<BYTE> buffer(sizeof(Header)+(substitute.size()+print.size()+2)*2);
    header.bytes=WORD(buffer.size()-8);memcpy(buffer.data(),&header,sizeof(header));
    memcpy(buffer.data()+sizeof(header),substitute.c_str(),(substitute.size()+1)*2);
    memcpy(buffer.data()+sizeof(header)+header.print_offset,print.c_str(),(print.size()+1)*2);DWORD returned=0;
    if(!DeviceIoControl(folder.get(),FSCTL_SET_REPARSE_POINT,buffer.data(),DWORD(buffer.size()),nullptr,0,&returned,nullptr))fail_win("Create junction fixture");
}
} // namespace
int wmain() {
    try {
        auto root=Output::create_run(fs::current_path());auto source=directory(root,L"MVSDK");
        auto first=directory(source,L"한글 Camera App");auto second=directory(source,L"MVviewer");
        auto nested=directory(second,L"nested");auto time=*parse_iso_time("2026-10-09T03:00:00Z");
        std::string line="2026-10-09 12:00:00.000 1 INFO [tid:42] MVSDK initializes on windows, MVSDK verison:[V2.3.5.test]\r\n";
        put(first,"2026-10-09.123.MVSDK.log",line,time);put(second,"2026-10-09.123.MVSDK.log",line,time+1);
        put(source,"root.log",line,time+2);put(second,"camera.dmp",line,time+3);put(source,"UserLogInfo.zip",line,time+4);put(nested,"nested.log",line,time+5);
        auto hash=sha256(first/L"2026-10-09.123.MVSDK.log");
        auto destination=Output::create_run(root);Output output(destination);auto collected=copy_mvsdk_logs(source,output);collected["task_id"]="mvsdk";
        require(collected["status"]=="ok"&&collected["files"].size()==2,"Discover logs only in immediate application directories");
        require(collected["files"][0]["application_name"]=="MVviewer"&&collected["files"][1]["application_name"]=="한글 Camera App","Newest logs first; retain Unicode application names");
        require(collected["files"][0]["relative_path"]=="MVviewer\\2026-10-09.123.MVSDK.log","Index retains source filename and application directory");
        require(sha256(output.file("mvsdk-log-1.log"))==hash&&sha256(output.file("mvsdk-log-2.log"))==hash,"Identical filenames from different applications retain exact bytes");
        auto input=input_for(output);input["log_files"].push_back(utf8((first/L"2026-10-09.123.MVSDK.log").native()));
        auto explicit_log=copy_user_log(0,input,output);explicit_log["task_id"]="log:0";input["log_metadata"].push_back(explicit_log["file_metadata"]);
        auto sdk=collect_sdk_logs(input,output);sdk["task_id"]="sdk";
        require(sdk["status"]=="ok"&&sdk["summary"]["sources"].size()==3,"Automatic and explicit logs share SDK analysis without name collisions");
        auto modules=Json::array({collected,explicit_log,sdk});write_reports(output,input,modules,utc_now(),utc_now());write_manifest(output,input,modules,utc_now(),utc_now());create_zip(output);
        auto folder=load_evidence(destination),zip=load_evidence(output.file("diagnostics.zip"));
        require(folder.streamed_digests().at("mvsdk-log-1.log").sha256==hash&&zip.streamed_digests().at("mvsdk-log-1.log").sha256==hash,"Folder and ZIP verify automatic log hashes through streaming");
        auto analysis=analyze_evidence(zip);require(analysis["sdk_event_count"]==3,"Derived automatic SDK records must be accepted by offline analysis");
        require(analysis["sdk"]["events"][1]["pid"]=="123","Original filename PID survives flattened output");
        auto fallback=zip;fallback.erase("sdk-events.jsonl");fallback.erase("sdk-summary.json");
        manifest(fallback);
        require(analyze_evidence(fallback)["sdk_event_count"]==3,"Offline fallback parses automatic logs without derived SDK artifacts");
        EvidenceFiles raw;for(const auto& [name,bytes]:fallback)raw[name]=sdk_log_name(name)?line:bytes;manifest(raw);
        require(analyze_evidence(raw)["sdk_event_count"]==3,"In-memory fallback retains original metadata for automatic logs");
        raw["mvsdk-log-1.log"]+="tampered";bool rejected=false;try{analyze_evidence(raw);}catch(const std::exception&){rejected=true;}
        require(rejected,"Automatic source corruption must fail manifest verification");
        auto dates=event_date_filter("2026-10-09","+09:00");require(analyze_evidence(zip,dates)["sdk_event_count"]==3,"Automatic SDK timestamps support existing date selection");
        require(sha256(first/L"2026-10-09.123.MVSDK.log")==hash,"Collection and analysis preserve source bytes");
        auto absent=Output::create_run(root);Output absent_output(absent);require(copy_mvsdk_logs(root/L"missing",absent_output)["status"]=="missing","Missing MVSDK root is optional evidence");
        auto empty=directory(root,L"empty");auto empty_run=Output::create_run(root);Output empty_output(empty_run);require(copy_mvsdk_logs(empty,empty_output)["status"]=="empty","Empty root reports empty");
        auto locked_run=Output::create_run(root);Output locked_output(locked_run);
        {Handle lock(CreateFileW((first/L"2026-10-09.123.MVSDK.log").c_str(),GENERIC_READ,0,nullptr,OPEN_EXISTING,0,nullptr));require(bool(lock),"Lock fixture log");
            auto locked=copy_mvsdk_logs(source,locked_output);require(locked["status"]=="partial"&&locked["artifacts"].size()==2,"Locked log records a failure while another application's log is collected");}
        auto many=directory(root,L"many");auto many_app=directory(many,L"Application");
        for(size_t i=0;i<kMvSdkLogCount+1;++i)put(many_app,"2026-10-09."+std::to_string(i)+".MVSDK.log","x",time+i);
        auto many_run=Output::create_run(root);Output many_output(many_run);auto limited=copy_mvsdk_logs(many,many_output);
        require(limited["status"]=="partial"&&limited["files"].size()==kMvSdkLogCount&&limited["discovery"]["omitted_files"]==1,"Count cap retains newest files and reports omissions");
        auto large=directory(root,L"large");auto large_app=directory(large,L"Application");
        for(size_t i=0;i<5;++i){Output large_source(large_app);auto file=large_source.create("2026-10-09."+std::to_string(i)+".MVSDK.log");
            LARGE_INTEGER size{};size.QuadPart=kUserLogBytes+2;require(SetFilePointerEx(file.get(),size,nullptr,FILE_BEGIN)&&SetEndOfFile(file.get()),"Create large log fixture");}
        auto large_run=Output::create_run(root);Output large_output(large_run);auto large_result=copy_mvsdk_logs(large,large_output);
        require(large_result["status"]=="partial"&&large_result["copied_bytes"]==kMvSdkLogBytes&&large_result["discovery"]["omitted_files"]==1,"Aggregate cap is bounded independently of explicit logs");
        require(large_result["files"][0]["file_metadata"]["copied_offset_bytes"]==2&&fs::file_size(large_output.file("mvsdk-log-1.log"))==kUserLogBytes,"Oversized automatic logs preserve their final bytes and original offset");
        auto utf_run=Output::create_run(root);Output utf_output(utf_run);std::wstring text=L"\ufeff"+std::wstring(200,L'x')+L"\r\n"+wide(line);std::string bytes(reinterpret_cast<const char*>(text.data()),text.size()*sizeof(wchar_t));
        put(first,"utf16.log",bytes,time+10);auto tail=copy_text_log(first/L"utf16.log","mvsdk-log-1.log",utf_output,301);
        require(tail["file_metadata"]["utf16le_detected"]==true&&tail["file_metadata"]["copied_offset_bytes"].get<uint64_t>()%2==0,"UTF-16 tails retain code-unit alignment");
        SdkLogParser parser;auto meta=tail["file_metadata"];parser.begin("mvsdk-log-1.log","utf16.MVSDK.log",meta["copied_offset_bytes"],true);parser.feed(read_local_file(utf_output.file("mvsdk-log-1.log"),301));parser.end();
        require(parser.finish()["events"].size()==1,"UTF-16 tail skips its partial first line and retains the next SDK event");
        auto outside=directory(root,L"outside");put(outside,"foreign.log",line,time);
        junction(source/L"linked",outside);
        {
            auto link_run=Output::create_run(root);Output link_output(link_run);auto links=copy_mvsdk_logs(source,link_output);
            require(links["status"]=="partial"&&links["discovery"]["skipped_reparse_points"]==1&&links["files"].size()==3,"Linked application directories are skipped without following external paths");
            auto root_link_run=Output::create_run(root);Output root_link_output(root_link_run);require(copy_mvsdk_logs(source/L"linked",root_link_output)["status"]=="error","Linked MVSDK root is rejected");
        }
        auto tasks=collection_tasks(0);bool automatic=false,structured=false;for(const auto& task:tasks){automatic|=task.id=="mvsdk";structured|=task.id=="sdk";}
        require(automatic&&structured,"Default collection includes discovery and SDK analysis without --log-file");
        std::cout<<"MVSDK tests passed. Bundle: "<<utf8(output.file("diagnostics.zip").native())<<"\n";return 0;
    }catch(const std::exception& e){std::cerr<<"MVSDK test failed: "<<e.what()<<"\n";return 1;}
}
