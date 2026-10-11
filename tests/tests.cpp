#include "common.hpp"
#include <iostream>
#include <stdexcept>

using namespace fnc;
namespace {
void require(bool test,const char* message){if(!test)throw std::runtime_error(message);}
template<class F> void rejects(F f,const char* message){bool thrown=false;try{f();}catch(const std::exception&){thrown=true;}require(thrown,message);}
int fixture_worker(const std::string& id) {
    std::string payload;char buf[8192];DWORD n=0;
    while(ReadFile(GetStdHandle(STD_INPUT_HANDLE),buf,sizeof(buf),&n,nullptr)&&n)payload.append(buf,n);
    if(id.starts_with("live:")) {
        Json r=result(id);
        try {auto input=Json::parse(payload);Output output(wide(input["output_dir"].get<std::string>()));r=collect_task(id.substr(5),input,output);}
        catch(const WinError& e){issue(r,error_status(e.code),e.what(),e.code);}
        catch(const std::exception& e){issue(r,"error",e.what());}
        write_all(GetStdHandle(STD_OUTPUT_HANDLE),json_text(r));return 0;
    }
    if(id=="stall"){Sleep(5000);return 0;}
    if(id=="invalid"){write_all(GetStdHandle(STD_OUTPUT_HANDLE),"not JSON");return 0;}
    if(id=="overflow"){try{write_all(GetStdHandle(STD_OUTPUT_HANDLE),std::string(kMaxWorkerBytes+1024*1024,'x'));}catch(...){}return 0;}
    if(id=="partial-file") {
        auto input=Json::parse(payload);Output output(wide(input["output_dir"].get<std::string>()));
        output.write("events-test.jsonl","{\"channel\":\"test\",\"time_utc\":\"2026-01-01T00:00:00.000Z\"}\n{incomplete");
        Sleep(5000);return 0;
    }
    write_all(GetStdHandle(STD_OUTPUT_HANDLE),json_text(result("test fixture")));return 0;
}
int live_test(const fs::path& parent,bool include_evtx=false,bool sapera_only=false) {
    auto root=Output::create_run(parent);Output output(root);auto started=utc_now();auto to=*parse_iso_time(started);
    Json input{{"output_dir",utf8(root.native())},{"days",30},{"from_utc",iso_time(to-30ULL*86400*10000000)},{"to_utc",started},
        {"incident_time",nullptr},{"camera_mac",nullptr},{"expected_camera_ip",nullptr},{"log_files",Json::array()},{"include_evtx",include_evtx},{"nic_tokens",Json::array()},{"device_ids",Json::array()}};
    Json modules=Json::array();auto began=GetTickCount64();
    for(const auto& task:collection_tasks(0,0,include_evtx)) {
        if(sapera_only&&task.id!="sapera")continue;
        if(GetTickCount64()-began>=300000)break;
        auto r=run_worker({"live:"+task.id,task.title},input,30000);r["task_id"]=task.id;
        if(task.id=="network")input["nic_tokens"]=history_nic_tokens(r);
        if(task.id=="devices"&&r.contains("devices"))for(const auto& a:r["devices"]) {input["device_ids"].push_back(a["device_id"]);if(a.contains("service")&&a["service"].is_string())input["nic_tokens"].push_back(a["service"]);}
        std::cout<<task.id<<": "<<r["status"]<<" ("<<r.value("duration_ms",0ULL)<<" ms)"<<std::endl;
        modules.push_back(r);
    }
    auto end=utc_now();write_reports(output,input,modules,started,end);write_manifest(output,input,modules,started,end);create_zip(output);
    std::cout<<"Live API test (current token; production admin gate unchanged): "<<utf8(root.native())<<std::endl;return 0;
}
void tests() {
    auto parent=Output::create_run(fs::current_path());
    auto unicode_parent=parent/L"한글-진단";require(CreateDirectoryW(unicode_parent.c_str(),nullptr)!=FALSE,"Unicode test directory must be created.");
    auto root=Output::create_run(unicode_parent);Output output(root);
    require(parse_iso_time("2026-10-09T12:34:56+09:00")==parse_iso_time("2026-10-09T03:34:56Z"),"Timezone offsets must normalize.");
    require(parse_iso_time("2024-02-29T00:00:00.125Z").has_value(),"Leap-day timestamp must be accepted.");
    require(!parse_iso_time("2025-02-29T00:00:00Z"),"Invalid calendar date must be rejected.");
    require(!parse_iso_time("2026-10-09T12:00:00"),"Timezone is required.");
    require(!parse_iso_time("2026-10-09T12:00:00+14:01"),"Invalid timezone must be rejected.");
    auto fractional=*parse_iso_time("2026-10-09T12:00:00.123Z")+4567;
    require(parse_iso_time(local_time(fractional))==parse_iso_time(iso_time(fractional)),"Sub-millisecond event timestamps must not change the timezone offset.");
    auto opts=parse_options({L"collect",L"--output",root.native(),L"--days",L"45",L"--camera-mac",L"AA-BB-CC-DD-EE-FF",L"--expected-camera-ip",L"192.168.1.10"});
    require(opts.days==45&&opts.camera_mac=="aa:bb:cc:dd:ee:ff","Valid arguments must retain their meaning.");
    auto defaults=parse_options({});
    require(defaults.days==30&&defaults.output==canonical_local_path(executable_path().parent_path()),"No arguments must collect with EXE-adjacent output and a 30-day window.");
    require(parse_options({L"collect"}).output==defaults.output,"Legacy collect command must support defaults.");
    auto direct=parse_options({L"--output",root.native(),L"--days",L"7"});
    require(direct.output==canonical_local_path(root)&&direct.days==7,"Direct optional flags must override defaults without a collect subcommand.");
    rejects([]{parse_options({L"unknown-command"});},"Unknown commands must still be rejected.");
    rejects([&]{parse_options({L"collect",L"--output",root.native(),L"--days",L"0"});},"Invalid day range must fail.");
    rejects([&]{parse_options({L"collect",L"--output",root.native(),L"--days",L"30",L"--days",L"10"});},"Duplicate arguments must fail.");
    rejects([&]{parse_options({L"collect",L"--output",root.native(),L"--expected-camera-ip",L"camera.example.com"});},"A hostname must not be accepted for address input.");
    rejects([]{ensure_local_path(L"\\\\server\\share\\results");},"UNC paths must fail without network access.");
    rejects([&]{ensure_local_path(root/L"file.txt:stream");},"Alternate streams must fail.");
    rejects([&]{ensure_local_path(root/L"COM1.log");},"Log paths must not open serial device aliases.");
    rejects([&]{ensure_local_path(root/L"folder. "/L"original.log");},"Ambiguous Windows path normalization must be rejected.");
    rejects([&]{output.create("../escape.txt");},"Traversal must fail.");
    rejects([&]{output.create("NUL.log");},"Windows device aliases must fail.");
    output.write("original.log","customer data\r\n");auto original_hash=sha256(output.file("original.log"));
    rejects([&]{output.write("original.log","overwritten");},"Existing files must never be overwritten.");
    require(sha256(output.file("original.log"))==original_hash,"Failed writes must preserve original bytes.");
    Json input{{"output_dir",utf8(root.native())},{"log_files",Json::array({utf8(output.file("original.log").native())})}};
    auto copied=copy_user_log(0,input,output);
    require(copied["status"]=="ok","Existing log should be copied.");
    require(sha256(output.file("user-log-1.log"))==original_hash&&sha256(output.file("original.log"))==original_hash,"Log collection must preserve source and copy exactly.");
    require(csv_cell("=SUM(A1:A2)").starts_with("\"'="),"CSV formula protection is required.");
    require(csv_cell("a\"b")=="\"a\"\"b\"","CSV quotes must escape correctly.");
    auto sapera_root=Output::create_run(parent);Output sapera_output(sapera_root);
    std::string sapera_bytes(28*1024*1024,'\0');sapera_bytes[0]='S';sapera_bytes.back()='\xff';
    output.write("fixture-Logs.dat",sapera_bytes);auto sapera_source=output.file("fixture-Logs.dat");
    auto sapera_hash=sha256(sapera_source);auto sapera=copy_sapera_log(sapera_source,sapera_output);
    require(sapera["status"]=="ok"&&sapera["file_metadata"]["copied_bytes"]==sapera_bytes.size(),"28 MiB Sapera file must be copied in full.");
    require(sapera["file_metadata"]["tail_only"]==false&&sapera["file_metadata"]["changed_during_read"]==false,"Unchanged Sapera copy must report full coverage.");
    require(sha256(sapera_source)==sapera_hash&&sha256(sapera_output.file("sapera-Logs.dat"))==sapera_hash,"Sapera binary bytes and source must be preserved.");
    require(copy_sapera_log(output.file("absent.dat"),sapera_output)["status"]=="missing","Absent Sapera file must report missing.");
    {Handle locked(CreateFileW(sapera_source.c_str(),GENERIC_READ,0,nullptr,OPEN_EXISTING,0,nullptr));
        require(copy_sapera_log(sapera_source,sapera_output)["status"]!="ok","Exclusive Sapera lock must be reported without stopping the service.");}
    {auto large=output.create("large-Logs.dat");LARGE_INTEGER size{};size.QuadPart=kSaperaLogBytes+1;
        require(SetFilePointerEx(large.get(),size,nullptr,FILE_BEGIN)&&SetEndOfFile(large.get()),"Create oversized Sapera fixture.");}
    auto large_root=Output::create_run(parent);Output large_output(large_root);
    require(copy_sapera_log(output.file("large-Logs.dat"),large_output)["status"]=="not_collected"&&!fs::exists(large_output.file("sapera-Logs.dat")),"Oversized binary Sapera file must not be truncated.");
    auto default_tasks=collection_tasks(0);bool has_sapera=false;for(const auto& task:default_tasks)if(task.id=="sapera")has_sapera=true;
    require(has_sapera,"Default collection must include Sapera without --log-file.");
    Json many_filters{{"adapters",Json::array()}};
    for(int i=0;i<130;++i)many_filters["adapters"].push_back({{"adapter_name","filter-"+std::to_string(i)},{"description","filter description "+std::to_string(i)},{"filter_interface",true}});
    many_filters["adapters"].push_back({{"adapter_name","camera-nic-guid"},{"description","physical NIC"},{"filter_interface",false}});
    auto tokens=history_nic_tokens(many_filters);
    require(tokens.size()==128&&tokens[0]=="camera-nic-guid","Filter-heavy NIC inventory must prioritize actual NIC history matching.");
    auto blocks=setupapi_blocks(
        ">>>  [Device Install - PCI\\VEN_1234&DEV_5678]\r\n>>>  Section start 2026/10/08 10:00:00.000\r\n<<<  Section end 2026/10/08 10:00:01.000\r\n"
        ">>>  [Device Install - USB\\UNRELATED]\r\n>>>  Section start 2026/10/08 10:00:00.000\r\n"
        ">>>  [Device Install - PCI\\VEN_1234&DEV_5678]\r\n>>>  Section start 2020/01/01 10:00:00.000\r\n",
        {"PCI\\VEN_1234&DEV_5678"},*parse_iso_time("2026-10-01T00:00:00Z"),*parse_iso_time("2026-10-09T00:00:00Z"));
    require(blocks.size()==1&&blocks[0].find("2026/10/08")!=std::string::npos,"SetupAPI must match device and history window.");
    auto undated=setupapi_blocks(">>>  [Device Install - PCI\\VEN_1234&DEV_5678]\n(no timestamp)\n",{"PCI\\VEN_1234&DEV_5678"},0,now_ticks());
    require(undated.size()==1,"Matching undated evidence must not be discarded.");
    require(run_worker({"success","fixture"},input,5000)["status"]=="ok","Valid worker response must survive isolation.");
    require(run_worker({"invalid","fixture"},input,5000)["status"]=="error","Malformed worker output must be detected.");
    auto start=GetTickCount64();require(run_worker({"stall","fixture"},input,150)["status"]=="timeout","Stalled collector must be terminated.");
    require(GetTickCount64()-start<2500,"Collector timeout must bound parent latency.");
    require(run_worker({"overflow","fixture"},input,5000)["status"]=="partial","Worker response budget must be enforced.");
    require(run_worker({"partial-file","fixture"},input,1200)["status"]=="timeout","Partial evidence test must time out.");
    require(read_local_file(output.file("events-test.jsonl"),4096).find("{incomplete")!=std::string::npos,"Interrupted evidence must be retained.");
    Json report_input{{"from_utc","2025-12-01T00:00:00.000Z"},{"to_utc","2026-01-02T00:00:00.000Z"},{"incident_time",nullptr},{"camera_mac",nullptr},{"expected_camera_ip",nullptr}};
    Json partial_module=result("Interrupted synthetic events","partial");partial_module["task_id"]="events:test";partial_module["artifacts"]={"events-test.jsonl"};
    auto report_modules=Json::array({partial_module});
    write_reports(output,report_input,report_modules,utc_now(),utc_now());
    auto snapshot=Json::parse(read_local_file(output.file("snapshot.json"),1024*1024));
    require(snapshot["report_warnings"].size()==1,"Interrupted event row must be marked and excluded.");
    require(read_local_file(output.file("timeline.csv"),8192).find("2026-01-01")!=std::string::npos,"Complete event before interruption must appear in timeline.");
    write_manifest(output,report_input,report_modules,utc_now(),utc_now());create_zip(output);
    require(fs::file_size(output.file("diagnostics.zip"))>0,"ZIP must be generated.");
    require(read_local_file(output.file("diagnostics.zip.sha256"),256).starts_with(sha256(output.file("diagnostics.zip"))),"ZIP checksum must match.");
    require(sha256(output.file("original.log"))==original_hash,"Packaging must not change source evidence.");
    std::cout<<"Behavior tests passed. Artifacts: "<<utf8(root.native())<<"\n";
}
}
int wmain(int argc,wchar_t** argv) {
    try {if(argc==3&&std::wstring_view(argv[1])==L"--worker")return fixture_worker(utf8(argv[2]));
        if(argc==3&&std::wstring_view(argv[1])==L"--live-readonly")return live_test(argv[2]);
        if(argc==3&&std::wstring_view(argv[1])==L"--live-sapera")return live_test(argv[2],false,true);
        if(argc==3&&std::wstring_view(argv[1])==L"--live-evtx")return live_test(argv[2],true);tests();return 0;}
    catch(const std::exception& e){std::cerr<<"Test failed: "<<e.what()<<"\n";return 1;}
}
