#include "analyzer.hpp"
#include "sdk_logs.hpp"
#include <dbghelp.h>
#include <miniz.h>
#include <iostream>
#include <cstring>

using namespace fnc;
namespace {
void require(bool v,const char* reason){if(!v)throw std::runtime_error(reason);}
template<class F>void rejects(F f,const char* why){bool bad=false;try{f();}catch(const std::exception&){bad=true;}require(bad,why);}
template<class T>void put(std::string& b,size_t at,const T& value){if(b.size()<at+sizeof(T))b.resize(at+sizeof(T));memcpy(b.data()+at,&value,sizeof(T));}
std::string dump_fixture(bool exception) {
    MINIDUMP_HEADER header{};header.Signature=MINIDUMP_SIGNATURE;header.Version=MINIDUMP_VERSION;header.TimeDateStamp=1767225600;header.Flags=MiniDumpWithFullMemory;
    header.NumberOfStreams=exception?3:2;header.StreamDirectoryRva=sizeof(header);std::string b(1024,'\0');put(b,0,header);
    MINIDUMP_DIRECTORY sys{};sys.StreamType=SystemInfoStream;sys.Location={sizeof(MINIDUMP_SYSTEM_INFO),128};put(b,sizeof(header),sys);
    MINIDUMP_SYSTEM_INFO si{};si.ProcessorArchitecture=PROCESSOR_ARCHITECTURE_AMD64;si.BuildNumber=26100;si.NumberOfProcessors=48;put(b,128,si);
    MINIDUMP_DIRECTORY modules{};modules.StreamType=ModuleListStream;modules.Location={4+sizeof(MINIDUMP_MODULE),256};put(b,sizeof(header)+sizeof(sys),modules);
    put(b,256,ULONG32(1));MINIDUMP_MODULE m{};m.ModuleNameRva=512;m.VersionInfo.dwSignature=0xfeef04bd;m.VersionInfo.dwFileVersionMS=1<<16;m.VersionInfo.dwFileVersionLS=1;
    put(b,260,m);std::wstring name=L"C:\\Synthetic\\MVSDKmd.dll";put(b,512,ULONG32(name.size()*2));memcpy(b.data()+516,name.data(),name.size()*2);
    if(exception){MINIDUMP_DIRECTORY ex{};ex.StreamType=ExceptionStream;ex.Location={sizeof(MINIDUMP_EXCEPTION_STREAM),640};put(b,sizeof(header)+2*sizeof(sys),ex);MINIDUMP_EXCEPTION_STREAM s{};s.ThreadId=7;s.ExceptionRecord.ExceptionCode=0xc0000005;s.ExceptionRecord.ExceptionAddress=0x12345678;put(b,640,s);}
    return b;
}
std::string sdk_fixture() {
    auto line=[](const char* s){return std::string("2026-10-09 07:20:54.238 INFO [tid:42][CameraImpl.cpp(101) connect] ")+s+"\r\n";};
    return line("MVSDK initializes on windows, MVSDK verison:[V2.3.5.285395]")+line("gige driver initializes, gige user:[2.0.0.275528], gige kernel:[2.2.1.216674]")+
        line("begin! Vendor=[Huaray Technology], Model=[ENS-0160GC4], SerialNumber=[SYNTHETIC-001], Version=[V1.001]")+
        line("get NIC MTU Value 9000")+line("When Jumbo Packet is opened, The actual use of 90 percent MTU 8100")+line("negotiatePacketSize 8016")+
        line("heartbeatTimeout 3000 ms")+line("setAnswerTimeout 1000 ms")+
        "2026-10-09 07:20:56.486 INFO [tid:42][StreamSourceImpl.cpp(805) startGrabbingImpl] Begin.\r\n"+
        line("bufferCount=[8], bufferSize=[4147200], GevSCPD=[0]")+
        line("GIGE statistics info:softwareTrigger=[0], imageReceived=[268], fps=[120.04], lostPacket=[0], resendPacket=[0], errorImage=[0], missingBlock=[0]")+
        "2026-10-09 07:20:58.901 ERROR [tid:42][StreamSourceImpl.cpp(1088) getFrameFromProtocolStack] the camera is not grabbing\r\n"+
        "2026-10-09 07:20:58.902 ERROR [tid:42][CameraImpl.cpp(9) param] BinningHorizontal invalid\r\n";
}
Json app_event(std::string provider,int id,unsigned record,std::string report="REPORT-001") {
    auto xml="<Event><System><Provider Name='"+provider+"'/><EventID>"+std::to_string(id)+"</EventID><EventRecordID>"+std::to_string(record)+"</EventRecordID><TimeCreated SystemTime='2026-10-09T00:00:00Z'/></System><EventData><Data Name='AppName'>MVviewer.exe</Data><Data Name='ProcessId'>0x2a</Data><Data Name='ReportId'>"+report+"</Data><Data Name='ModuleName'>MVSDKmd.dll</Data><Data Name='ExceptionCode'>c0000005</Data></EventData></Event>";
    return {{"channel","Application"},{"provider",provider},{"event_id",id},{"record_id",record},{"time_utc","2026-10-09T00:00:00Z"},{"xml",xml}};
}
void manifest(EvidenceFiles& files){Json entries=Json::array();for(const auto& [name,b]:files)if(name!="manifest.json")entries.push_back({{"name",name},{"size_bytes",b.size()},{"sha256",sha256_bytes(b)}});files["manifest.json"]=json_text(Json{{"schema_version",1},{"files",entries}});}
Json parse_sdk(const std::string& bytes,size_t chunk=17,bool utf16=false,uint64_t base=0) {
    SdkLogParser parser;parser.begin("user-log-1.log","2026-10-09.123.MVSDK.log",base,utf16);
    for(size_t i=0;i<bytes.size();i+=chunk)parser.feed(std::string_view(bytes).substr(i,(std::min)(chunk,bytes.size()-i)));parser.end();return parser.finish("+09:00");
}
}
int wmain() {
    try {
        auto root=Output::create_run(fs::current_path());Output output(root);
        auto opts=parse_options({L"--output",root.native(),L"--app-name",L"Example.exe",L"--app-name",L"MVviewer.exe",L"--log-utc-offset",L"-05:30",L"--dump-file",(root/L"tiny.dmp").native(),L"--attach-dumps",L"--include-evtx"});
        require(opts.app_names[0]=="example.exe"&&opts.attach_dumps&&opts.include_evtx,"New CLI options");
        rejects([]{parse_options({L"--attach-dumps"});},"Attachment must require explicit dump input");
        rejects([]{parse_options({L"--app-name",L"C:\\bad.exe"});},"App names must be pathless");rejects([]{utc_offset_minutes("+14:01");},"Invalid offset must fail");
        Json input{{"app_names",Json::array({"example.exe"})},{"nic_tokens",Json::array({"NIC identifier"})}};
        auto e=app_event("Application Error",1000,1);require(event_interesting(e,"Application",input),"MVSDK module/app incident must match");
        e["xml"]="<Data>Unrelated.exe unrelated.dll</Data>";require(!event_interesting(e,"Application",input),"Unrelated application error must be excluded");
        e["xml"]="<Data>C:\\Apps\\Example.exe</Data>";require(event_interesting(e,"Application",input),"Explicit app name must match");
        e["xml"]="<Data>NotExample.exe</Data>";require(!event_interesting(e,"Application",input),"App suffix match must not select another executable");
        e={{"provider","mvGenICamForEthernet"},{"event_id",7},{"xml","NIC identifier"}};require(!event_interesting(e,"System",input)&&event_interesting(e,"mvGenICamForEthernet",input),"Vendor events must use an independent budget");
        auto query=evtx_record_query("System",{1,2,999});require(query.find(L"EventRecordID=999")!=std::wstring::npos&&query.find(L"TimeCreated")==std::wstring::npos,"EVTX query must select exact Record IDs");
        auto text=sdk_fixture();auto sdk=parse_sdk(text);require(sdk["events"].size()>=12,"SDK golden log must yield records");
        require(sdk["versions"][0]["fields"]["sdk_version"]=="V2.3.5.285395","Runtime SDK version");
        require(sdk["versions"][1]["fields"]["gige_kernel_version"]=="2.2.1.216674","GigE runtime version");
        bool mtu=false,statistics=false,timeout=false;
        for(const auto& ev:sdk["events"]){const auto& f=ev["fields"];if(f.contains("nic_mtu"))mtu=f["nic_mtu"]==9000;if(f.contains("imageReceived"))statistics=f["imageReceived"]==268&&f["fps"]==120.04;if(f.contains("heartbeat_timeout_ms"))timeout=f["heartbeat_timeout_ms"]==3000;require(ev["pid"]=="123"&&ev["thread_id"]=="42","PID/thread/source references");}
        require(mtu&&statistics&&timeout,"SDK MTU/statistics/timeouts");require(sdk["events"][0]["time_utc"]=="2026-10-08T22:20:54.238Z","SDK timezone conversion");
        auto w=wide(text);std::string utf16="\xff\xfe";utf16.append(reinterpret_cast<const char*>(w.data()),w.size()*2);require(parse_sdk(utf16)["events"].size()==sdk["events"].size(),"UTF16 chunk boundaries");
        std::string cp949="2026-10-09 07:20:58.901 ERROR [tid:42][CameraImpl.cpp(9) param] ";cp949+="\xc4\xab\xb8\xde\xb6\xf3";cp949+=" timeout\n";require(parse_sdk(cp949)["events"][0]["message"].get<std::string>().find("카메라")!=std::string::npos,"CP949 fallback must preserve Korean text");
        auto tail=parse_sdk("cut first line\n"+text,11,false,1000);require(tail["events"][0]["source_byte_offset"]==1015&&tail["events"][0]["source_line"]==2&&tail["truncated"]==true,"Tail source byte offsets and relative line numbers");
        auto oversized=parse_sdk(std::string(kSdkLineBytes+100,'x')+"\n"+text);require(oversized["truncated"]==true,"SDK long-line limit");
        auto limited=parse_sdk(std::string(),32);std::string repeated;for(size_t i=0;i<12000;++i)repeated+="2026-10-09 07:20:58.901 ERROR [tid:42][CameraImpl.cpp(9) param] PixelSize invalid\n";limited=parse_sdk(repeated,65536);require(limited["events"].size()<=kSdkEventCount&&limited["truncated"]==true,"Global SDK count/byte limit");size_t event_bytes=0;for(const auto& ev:limited["events"])event_bytes+=json_text(ev).size()+1;require(event_bytes<=kSdkEventBytes,"Derived SDK serialized byte cap");
        Json snapshot={{"schema_version",1},{"inputs",{{"log_utc_offset",nullptr}}},{"modules",Json::array({Json{{"task_id","log:0"},{"status","ok"},{"artifacts",Json::array({"user-log-1.log"})},{"file_metadata",{{"path","2026-10-09.123.MVSDK.log"}}}}})}};
        EvidenceFiles files={{"snapshot.json",json_text(snapshot)},{"user-log-1.log",text},{"events-Application.jsonl",json_text(app_event("Application Error",1000,1))+"\n"+json_text(app_event("Windows Error Reporting",1001,2))+"\n"}};manifest(files);
        auto report=analyze_evidence(files,event_date_filter("2026-10-09"));require(report["event_count"]==2&&report["sdk_event_count"]==0&&report["undated_sdk_count"].get<size_t>()>0,"Unknown SDK time must not enter date exports or Windows counts");
        report=analyze_evidence(files,event_date_filter("2026-10-09"),"+09:00");require(report["sdk_event_count"].get<size_t>()>0&&report["event_count"]==2,"SDK date export separated from Windows event counts");require(report["app_incidents"].size()==2&&report["app_incidents"][0]["related_records"].size()==1,"App Error and WER must remain individual linked records");require(selected_events_jsonl(report).find("\"kind\":\"sdk\"")!=std::string::npos,"SDK JSONL export kind");
        auto legacy_root=Output::create_run(root);Output legacy(legacy_root);for(const auto& [name,bytes]:files)legacy.write(name,bytes);auto legacy_stream=load_evidence(legacy_root);
        require(legacy_stream.at("user-log-1.log").empty()&&analyze_evidence(legacy_stream,event_date_filter("2026-10-09"),"+09:00")["sdk_event_count"]==report["sdk_event_count"],"Old bundle raw logs must be parsed while streaming and discarded");
        EvidenceFiles derived=files;std::string lines;for(const auto& ev:sdk["events"])lines+=json_text(ev)+"\n";auto saved=sdk;saved.erase("events");derived["sdk-events.jsonl"]=lines;derived["sdk-summary.json"]=json_text(saved);
        auto saved_snapshot=snapshot;saved_snapshot["inputs"]["log_utc_offset"]="+09:00";derived["snapshot.json"]=json_text(saved_snapshot);manifest(derived);
        auto overridden=analyze_evidence(derived,event_date_filter("2026-10-09","+00:00"),"+00:00");require(overridden["sdk"]["events"][0]["time_utc"]=="2026-10-09T07:20:54.238Z","Analyze source offset must override saved/derived timestamps");
        auto display_snapshot=snapshot;display_snapshot["modules"].push_back({{"task_id","network"},{"status","ok"},{"adapters",Json::array({Json{{"if_index",1},{"friendly_name","Unknown speed NIC"},{"description","Synthetic"},{"addresses",Json::array()}}})},{"interfaces",Json::array({Json{{"if_index",1},{"oper_status",2},{"rx_link_bps",UINT64_MAX},{"tx_link_bps",0}}})}});
        display_snapshot["modules"].push_back({{"task_id","system"},{"status","ok"},{"physical_memory",{{"total_bytes",69793218560ULL},{"available_bytes",0},{"load_percent",nullptr}}},{"memory_modules_wmi",{{"rows",Json::array({Json{{"Manufacturer","Synthetic"},{"PartNumber","PN-001"},{"Capacity","137438953472"},{"Speed",5600}}})}}}});
        auto display=files;display["snapshot.json"]=json_text(display_snapshot);manifest(display);auto html=analysis_html(analyze_evidence(display));require(html.find("NDIS_LINK_SPEED_UNKNOWN")!=std::string::npos&&html.find("1.84467e+10")==std::string::npos&&html.find("137438953472")!=std::string::npos,"Unknown speed and 64-bit memory values must be displayed correctly");
        auto source=dump_fixture(false);output.write("tiny.dmp",source);auto before=sha256(output.file("tiny.dmp"));auto meta=read_dump_metadata(output.file("tiny.dmp"));require(meta["exception_stream_present"]==false&&meta["exception_note"]=="예외 정보 없음"&&meta["os_build"]==26100&&meta["modules"][0]["file_version"]=="1.0.0.1","Bounded dump metadata without exception");
        output.write("exception.dmp",dump_fixture(true));require(read_dump_metadata(output.file("exception.dmp"))["exception"]["code"]==0xc0000005U,"Exception metadata must be explicit");
        auto broken=source;auto hdr=MINIDUMP_HEADER{};memcpy(&hdr,broken.data(),sizeof(hdr));hdr.StreamDirectoryRva=0xfffffff0;put(broken,0,hdr);output.write("bad-offset.dmp",broken);rejects([&]{read_dump_metadata(output.file("bad-offset.dmp"));},"Malformed dump offsets must fail");
        broken=source;put(broken,256,ULONG32(4097));output.write("bad-count.dmp",broken);rejects([&]{read_dump_metadata(output.file("bad-count.dmp"));},"Dump module cap");
        broken=dump_fixture(true);MINIDUMP_DIRECTORY bad_exception{};bad_exception.StreamType=ExceptionStream;bad_exception.Location={4,640};put(broken,sizeof(MINIDUMP_HEADER)+2*sizeof(MINIDUMP_DIRECTORY),bad_exception);output.write("bad-exception.dmp",broken);rejects([&]{read_dump_metadata(output.file("bad-exception.dmp"));},"Truncated exception stream must fail");
        broken=source;constexpr size_t names_at=131072;broken.resize(names_at+1024*4100);MINIDUMP_DIRECTORY many{};many.StreamType=ModuleListStream;many.Location={4+1024*sizeof(MINIDUMP_MODULE),256};put(broken,sizeof(MINIDUMP_HEADER)+sizeof(MINIDUMP_DIRECTORY),many);put(broken,256,ULONG32(1024));
        std::wstring long_name(2048,L'x');for(size_t i=0;i<1024;++i){MINIDUMP_MODULE m{};m.ModuleNameRva=ULONG32(names_at+i*4100);put(broken,260+i*sizeof(m),m);put(broken,m.ModuleNameRva,ULONG32(4096));memcpy(broken.data()+m.ModuleNameRva+4,long_name.data(),4096);}output.write("metadata-budget.dmp",broken);rejects([&]{read_dump_metadata(output.file("metadata-budget.dmp"));},"Dump metadata must respect the 4 MiB read budget");
        Json attach_input{{"dump_files",Json::array({utf8(output.file("tiny.dmp").native())})}};auto attachment=attach_dumps(attach_input,output);require(attachment["external_attachment"]["files"][0]["sha256"]==before&&sha256(output.file("tiny.dmp"))==before,"Attachment hash/source immutability");
        auto timeout_root=Output::create_run(root);Output timeout_output(timeout_root);rejects([&]{attach_dumps(attach_input,timeout_output,0);},"Attachment timeout must be enforced");
        // Unregistered sources and incomplete optional archives must never leak into diagnostics.zip.
        Json report_input{{"from_utc","2026-10-01T00:00:00Z"},{"to_utc","2026-10-10T00:00:00Z"},{"incident_time",nullptr},{"camera_mac",nullptr},{"expected_camera_ip",nullptr}};
        write_reports(output,report_input,Json::array({attachment}),utc_now(),utc_now());write_manifest(output,report_input,Json::array({attachment}),utc_now(),utc_now());create_zip(output);
        auto loaded=load_evidence(output.root());require(loaded.size()==4&&!loaded.contains("tiny.dmp")&&!loaded.contains("dump-attachments.zip"),"Core manifest must contain registered artifacts only");require(Json::parse(loaded.at("manifest.json"))["external_attachments"].size()==1,"External attachment reference");
        // Exercise the collector-to-manifest-to-analyzer path, including derived artifacts.
        output.write("2026-10-09.123.MVSDK.log",text);auto collected_root=Output::create_run(root);Output collected(collected_root);auto collect_input=report_input;
        collect_input["log_files"]=Json::array({utf8(output.file("2026-10-09.123.MVSDK.log").native())});collect_input["dump_files"]=attach_input["dump_files"];collect_input["log_utc_offset"]="+09:00";
        auto log_module=copy_user_log(0,collect_input,collected);log_module["task_id"]="log:0";collect_input["log_metadata"]=Json::array({log_module["file_metadata"]});
        auto sdk_module=collect_sdk_logs(collect_input,collected);sdk_module["task_id"]="sdk";auto dump_module=collect_dump(0,collect_input,collected);dump_module["task_id"]="dump:0";
        collect_input["dump_metadata"]=Json::array({dump_module["metadata"]});auto attached=attach_dumps(collect_input,collected);auto modules=Json::array({log_module,sdk_module,dump_module,attached});
        require(sdk_module["status"]=="ok"&&dump_module["status"]=="ok"&&attached["status"]=="ok","Collection SDK/dump/attachment integration");
        write_reports(collected,collect_input,modules,utc_now(),utc_now());write_manifest(collected,collect_input,modules,utc_now(),utc_now());create_zip(collected);
        auto folder_evidence=load_evidence(collected_root),zip_evidence=load_evidence(collected.file("diagnostics.zip"));require(folder_evidence==zip_evidence,"Streaming SDK folder/ZIP parity");
        auto integrated=analyze_evidence(zip_evidence,event_date_filter("2026-10-09"));require(integrated["sdk_event_count"].get<size_t>()>0&&integrated["dumps"].size()==1&&integrated["external_attachments"].size()==1,"Collected derived artifacts must reach analysis");
        collected.write("preview.html",analysis_html(integrated));
        require(sha256(output.file("2026-10-09.123.MVSDK.log"))==sha256_bytes(text)&&sha256(output.file("tiny.dmp"))==before,"End-to-end collection must preserve both explicit inputs");
        std::cout<<"Integrated bundle: "<<utf8(collected.file("diagnostics.zip").native())<<"\n";
        std::cout<<"Benchmark-derived synthetic tests passed. Artifacts: "<<utf8(root.native())<<"\n";return 0;
    }catch(const std::exception& e){std::cerr<<"Benchmark test failed: "<<e.what()<<"\n";return 1;}
}
