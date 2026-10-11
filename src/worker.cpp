#include "common.hpp"
#include <algorithm>
#include <iostream>

namespace fnc {
Json run_worker(const Task& task,const Json& input,DWORD timeout_ms,const fs::path& exe) {
    auto r=result(task.id);r["task_id"]=task.id;r["title"]=task.title;
    auto started=GetTickCount64();
    SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};HANDLE read_raw=nullptr,write_raw=nullptr;
    if(!CreatePipe(&read_raw,&write_raw,&sa,65536))fail_win("Create worker result pipe");
    Handle stdout_read(read_raw),stdout_write(write_raw);
    if(!SetHandleInformation(stdout_read.get(),HANDLE_FLAG_INHERIT,0))fail_win("Result pipe inheritance");
    if(!CreatePipe(&read_raw,&write_raw,&sa,65536))fail_win("Create worker input pipe");
    Handle stdin_read(read_raw),stdin_write(write_raw);
    if(!SetHandleInformation(stdin_write.get(),HANDLE_FLAG_INHERIT,0))fail_win("Input pipe inheritance");
    Handle job(CreateJobObjectW(nullptr,nullptr));if(!job)fail_win("Create collection job");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_PROCESS_MEMORY|JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    limits.ProcessMemoryLimit=192*1024*1024;limits.BasicLimitInformation.ActiveProcessLimit=1;
    if(!SetInformationJobObject(job.get(),JobObjectExtendedLimitInformation,&limits,sizeof(limits)))fail_win("Set collection limits");
    SIZE_T attribute_size=0;InitializeProcThreadAttributeList(nullptr,1,0,&attribute_size);
    std::vector<BYTE> attributes(attribute_size);auto* list=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
    if(!InitializeProcThreadAttributeList(list,1,0,&attribute_size))fail_win("Initialize process handle list");
    struct AttrGuard {LPPROC_THREAD_ATTRIBUTE_LIST list;~AttrGuard(){DeleteProcThreadAttributeList(list);}} attr_guard{list};
    HANDLE inherited[]={stdin_read.get(),stdout_write.get()};
    if(!UpdateProcThreadAttribute(list,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited,sizeof(inherited),nullptr,nullptr))fail_win("Set inherited pipe handles");
    STARTUPINFOEXW si{};si.StartupInfo.cb=sizeof(si);si.StartupInfo.dwFlags=STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput=stdin_read.get();si.StartupInfo.hStdOutput=stdout_write.get();si.StartupInfo.hStdError=stdout_write.get();si.lpAttributeList=list;
    auto command=L"\""+exe.native()+L"\" --worker \""+wide(task.id)+L"\"";
    PROCESS_INFORMATION pi{};
    if(!CreateProcessW(exe.c_str(),command.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW|CREATE_SUSPENDED|EXTENDED_STARTUPINFO_PRESENT,
        nullptr,exe.parent_path().c_str(),&si.StartupInfo,&pi))fail_win("Start isolated collector");
    Handle process(pi.hProcess),thread(pi.hThread);
    if(!AssignProcessToJobObject(job.get(),process.get())) {auto e=GetLastError();TerminateProcess(process.get(),2);WaitForSingleObject(process.get(),1000);fail_win("Isolate collection process",e);}
    if(ResumeThread(thread.get())==DWORD(-1))fail_win("Resume collector");
    thread.reset();stdin_read.reset();stdout_write.reset();
    // The worker reads this before doing any collection. Payload is bounded to a pipe buffer.
    auto payload=json_text(input);
    if(payload.size()>60000)throw std::runtime_error("Collection input exceeds 60 KiB limit.");
    write_all(stdin_write.get(),payload);stdin_write.reset();
    std::string response;response.reserve(65536);std::vector<char> buffer(65536);bool killed=false;
    while(true) {
        DWORD available=0;
        if(PeekNamedPipe(stdout_read.get(),nullptr,0,nullptr,&available,nullptr)) {
            while(available) {
                DWORD n=0;auto chunk=(std::min)(available,DWORD(buffer.size()));
                if(!ReadFile(stdout_read.get(),buffer.data(),chunk,&n,nullptr))fail_win("Read collector result");
                if(response.size()+n>kMaxWorkerBytes) {issue(r,"partial","Collector response size limit exceeded.");TerminateJobObject(job.get(),2);killed=true;break;}
                response.append(buffer.data(),n);available-=n;
            }
        } else if(GetLastError()!=ERROR_BROKEN_PIPE)fail_win("Inspect collector pipe");
        if(killed)break;
        DWORD state=WaitForSingleObject(process.get(),0);
        if(state==WAIT_OBJECT_0) {
            // One more iteration drains bytes written just before process exit.
            DWORD remaining=0;if(PeekNamedPipe(stdout_read.get(),nullptr,0,nullptr,&remaining,nullptr)&&remaining)continue;break;
        }
        if(state==WAIT_FAILED)fail_win("Wait collector");
        if(GetTickCount64()-started>=timeout_ms) {issue(r,"timeout","Collector exceeded its time budget. Only this owned process was terminated.",WAIT_TIMEOUT);TerminateJobObject(job.get(),WAIT_TIMEOUT);killed=true;break;}
        Sleep(20);
    }
    if(killed)WaitForSingleObject(process.get(),1000);
    else {
        DWORD exit_code=0;if(!GetExitCodeProcess(process.get(),&exit_code))fail_win("Collector exit status");
        try {
            auto data=Json::parse(response);
            if(!data.is_object()||!data.contains("status")||!data.contains("issues")||!data.contains("artifacts"))throw std::runtime_error("Invalid collector result shape.");
            r=std::move(data);r["task_id"]=task.id;r["title"]=task.title;
            if(exit_code!=0 && r["status"]=="ok")issue(r,"partial","Collector exited with an error.",exit_code);
        } catch(const std::exception& e) {issue(r,"error",std::string("Collector result unavailable: ")+e.what(),exit_code);}
    }
    r["duration_ms"]=GetTickCount64()-started;r["completed_at_utc"]=utc_now();return r;
}
int worker_main(std::string_view task_id) {
    Json r=result(task_id);
    try {
        std::string payload;char buffer[8192];DWORD n=0;
        while(ReadFile(GetStdHandle(STD_INPUT_HANDLE),buffer,sizeof(buffer),&n,nullptr)&&n) {
            if(payload.size()+n>60000)throw std::runtime_error("Worker input size limit exceeded.");payload.append(buffer,n);
        }
        auto input=Json::parse(payload);
        if(!elevated())throw std::runtime_error("Internal collector requires an elevated parent.");
        auto tasks=collection_tasks(input.at("log_files").size(),input.value("dump_files",Json::array()).size(),input.value("include_evtx",false));
        if(input.value("attach_dumps",false)&&!input.value("dump_files",Json::array()).empty())tasks.push_back({"dump-attachments","Original dump attachments"});
        if(std::none_of(tasks.begin(),tasks.end(),[&](const auto& t){return t.id==task_id;}))throw std::runtime_error("Invalid internal task ID.");
        if(!parse_iso_time(input.at("from_utc").get<std::string>())||!parse_iso_time(input.at("to_utc").get<std::string>()))throw std::runtime_error("Invalid collection interval.");
        Output output(fs::path(wide(input.at("output_dir").get<std::string>())));
        r=collect_task(task_id,input,output);
    } catch(const WinError& e) {issue(r,error_status(e.code),e.what(),e.code);}
    catch(const std::exception& e) {issue(r,"error",e.what());}
    auto response=json_text(r);
    if(response.size()>kMaxWorkerBytes) {r=result(task_id,"partial");issue(r,"partial","Collector result exceeded the response budget.");response=json_text(r);}
    try {write_all(GetStdHandle(STD_OUTPUT_HANDLE),response);}catch(...){return 2;}
    return r["status"]=="error"?1:0;
}
int collect(const Options& options) {
    if(!elevated()) {console_text("Administrator privileges are required. Open an elevated console and run this command again. No result directory was created.\n",true);return 3;}
    auto start=utc_now();auto end_ticks=*parse_iso_time(start);auto from_ticks=end_ticks-ULONGLONG(options.days)*86400*10000000;
    // Validate the output before any application-owned write; there is no TEMP fallback.
    fs::path root;
    try {root=Output::create_run(options.output);}
    catch(const std::exception& e) {console_text(std::string("Cannot save results: ")+e.what()+"\nUse --output <existing writable local folder> to choose another result location.\n",true);return 2;}
    Output output(root);
    Json input{{"output_dir",utf8(root.native())},{"days",options.days},{"from_utc",iso_time(from_ticks)},{"to_utc",start},
        {"incident_time",options.incident?Json(*options.incident):Json(nullptr)},
        {"camera_mac",options.camera_mac?Json(*options.camera_mac):Json(nullptr)},
        {"expected_camera_ip",options.expected_ip?Json(*options.expected_ip):Json(nullptr)},
        {"log_files",Json::array()},{"dump_files",Json::array()},{"app_names",options.app_names},
        {"log_utc_offset",options.log_utc_offset?Json(*options.log_utc_offset):Json(nullptr)},
        {"attach_dumps",options.attach_dumps},{"include_evtx",options.include_evtx},
        {"log_metadata",Json::array()},{"dump_metadata",Json::array()},{"history_remaining",100000},{"nic_tokens",Json::array()},{"device_ids",Json::array()}};
    for(const auto& p:options.log_files)input["log_files"].push_back(utf8(p.native()));
    for(const auto& p:options.dump_files)input["dump_files"].push_back(utf8(p.native()));
    Json modules=Json::array();auto tasks=collection_tasks(options.log_files.size(),options.dump_files.size(),options.include_evtx);auto began=GetTickCount64();
    for(const auto& task:tasks) {
        auto elapsed=GetTickCount64()-began;
        Json r;
        if(elapsed>=300000) {r=result(task.id,"not_collected");r["task_id"]=task.id;r["title"]=task.title;issue(r,"not_collected","Overall five-minute collection budget exhausted.");}
        else {
            std::cout<<"Collecting: "<<task.title<<"...\n";
            try {r=run_worker(task,input,DWORD((std::min)(ULONGLONG(30000),300000-elapsed)));}
            catch(const std::exception& e) {r=result(task.id,"error");r["task_id"]=task.id;r["title"]=task.title;issue(r,"error",e.what());}
        }
        if(task.id=="network")input["nic_tokens"]=history_nic_tokens(r);
        if(task.id=="devices" && r.contains("devices"))for(const auto& a:r["devices"]) {
            if(input["device_ids"].size()<256 && a.contains("device_id"))input["device_ids"].push_back(a["device_id"]);
            if(input["nic_tokens"].size()<256 && a.contains("service")&&a["service"].is_string()&&!a["service"].get<std::string>().empty())input["nic_tokens"].push_back(a["service"]);
        }
        if(task.id=="devices" && r.contains("devices") && r["devices"].size()>256)issue(r,"partial","History identifier matching is limited to the first 256 network device IDs.");
        if(task.id.starts_with("log:"))input["log_metadata"].push_back(r.value("file_metadata",Json::object()));
        if(task.id.starts_with("dump:")) {
            auto meta=r.value("metadata",Json(nullptr));
            if(meta.is_object())meta={{"source_size_bytes",meta["source_size_bytes"]},{"source_modified_utc",meta["source_modified_utc"]},{"changed_during_read",meta["changed_during_read"]}};
            input["dump_metadata"].push_back(meta);
        }
        // A killed JSONL/raw-log worker may have written usable partial evidence before replying.
        std::string partial_name;
        if(task.id.starts_with("events:")){partial_name="events-";for(char c:task.id.substr(7))partial_name+=std::isalnum(static_cast<unsigned char>(c))||c=='-'?c:'_';partial_name+=".jsonl";}
        if(task.id.starts_with("log:"))partial_name="user-log-"+std::to_string(std::stoul(task.id.substr(4))+1)+".log";
        if(task.id=="sapera")partial_name="sapera-Logs.dat";
        if(!partial_name.empty()&&fs::exists(output.file(partial_name))&&std::find(r["artifacts"].begin(),r["artifacts"].end(),Json(partial_name))==r["artifacts"].end())r["artifacts"].push_back(partial_name);
        if(task.id=="setupapi")for(auto name:{"setupapi-nic.log","setupapi-timeline.jsonl"})if(fs::exists(output.file(name))&&std::find(r["artifacts"].begin(),r["artifacts"].end(),Json(name))==r["artifacts"].end())r["artifacts"].push_back(name);
        if(task.id.starts_with("events:")||task.id=="setupapi")for(const auto& artifact:r["artifacts"])if(artifact.get<std::string>().ends_with(".jsonl")){
            std::ifstream stream(output.file(artifact.get<std::string>()),std::ios::binary);std::string line;size_t count=0;while(std::getline(stream,line))if(!line.empty())++count;
            auto remaining=input["history_remaining"].get<size_t>();input["history_remaining"]=count>remaining?0:remaining-count;
        }
        std::cout<<"  "<<r.value("status","error")<<"\n";modules.push_back(std::move(r));
    }
    if(options.attach_dumps) {
        console_text("Packaging optional original dump attachment...\n");Json r;
        try{r=run_worker({"dump-attachments","Original dump attachments"},input,300000);}
        catch(const std::exception& e){r=result("dump-attachments","partial");r["task_id"]="dump-attachments";r["title"]="Original dump attachments";issue(r,"partial",e.what());}
        modules.push_back(std::move(r));
    }
    // Optional native exports must fit the ordinary evidence budget too. Reserve
    // space for reports; the timeline uses the actual remaining budget below.
    uint64_t core_bytes=json_text(modules,2).size()+json_text(input,2).size()+16ULL*1024*1024;
    for(const auto& m:modules)for(const auto& a:m["artifacts"]){auto name=a.get<std::string>();if(!name.starts_with("user-log-"))core_bytes+=fs::file_size(output.file(name));}
    for(auto& m:modules)if(m.value("task_id","")=="evtx"){
        Json kept=Json::array();for(const auto& a:m["artifacts"]){auto name=a.get<std::string>();if(core_bytes>256ULL*1024*1024){core_bytes-=fs::file_size(output.file(name));issue(m,"partial","Optional EVTX excluded to preserve the ordinary bundle size budget.");}else kept.push_back(a);}m["artifacts"]=kept;
    }
    auto end=utc_now();
    std::cout<<"Writing reports and ZIP...\n";
    bool report_partial=false;
    try {
        report_partial=write_reports(output,input,modules,start,end);write_manifest(output,input,modules,start,end);create_zip(output);
    } catch(const std::exception& e) {console_text(std::string("Packaging failed: ")+e.what()+"\nCollected files remain in: "+utf8(root.native())+"\n",true);return 2;}
    bool partial=report_partial;for(const auto& m:modules) {auto status=m.value("status","error");if((status!="ok" && status!="empty" && status!="missing") ||
        (status=="missing" && (m.value("task_id","").starts_with("log:")||m.value("task_id","").starts_with("dump:"))))partial=true;}
    console_text("Result: "+utf8((root/L"diagnostics.zip").native())+"\n");
    std::cout<<"See summary.txt for coverage and missing evidence. No settings were changed.\n";
    return partial?1:0;
}
} // namespace fnc
