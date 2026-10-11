#include "analyzer.hpp"
#include <miniz.h>
#include <iostream>
#include <sstream>
using namespace fnc;
namespace {
void require(bool b,const char* message){if(!b)throw std::runtime_error(message);}
template<class F>void rejects(F f,const char* message){bool rejected=false;try{f();}catch(const std::exception&){rejected=true;}require(rejected,message);}
void manifest(EvidenceFiles& files){Json items=Json::array();for(const auto& [n,b]:files)if(n!="manifest.json")items.push_back({{"name",n},{"size_bytes",b.size()},{"sha256",sha256_bytes(b)}});files["manifest.json"]=json_text(Json{{"files",items}});}
Json event(int id,int record,std::string time,std::string device="NIC A") {
    auto xml="<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='e1rexpress'/><EventID>"+std::to_string(id)+"</EventID><EventRecordID>"+std::to_string(record)+"</EventRecordID><TimeCreated SystemTime='"+time+"'/></System><EventData><Data/><Data>"+device+"</Data></EventData></Event>";
    return {{"provider","e1rexpress"},{"channel","System"},{"event_id",id},{"record_id",record},{"level",id==27?3:4},{"time_utc",time},{"time_local",time},{"xml",xml},{"message","<script>alert('raw input')</script>"}};
}
EvidenceFiles fixture() {
    Json adapters=Json::array(),ifs=Json::array();unsigned index=0;
    for(auto name:{"NIC A","NIC B","NIC C"}) {
        ++index;adapters.push_back({{"if_index",index},{"adapter_name","{00000000-0000-0000-0000-00000000000"+std::to_string(index)+"}"},{"mtu",9000},{"friendly_name",name},{"description","Shared driver"},{"filter_interface",false},{"hardware_interface",true},
            {"dhcp_v4_enabled",false},{"addresses",Json::array({Json{{"address",index==1?"169.254.1.1":index==2?"169.253.1.1":"169.254.2.2"},{"prefix_length",16},{"prefix_origin",1}}})}});
        ifs.push_back({{"if_index",index},{"mtu",9000},{"filter_interface",false},{"oper_status",index==3?2:1}});
    }
    Json s={{"schema_version",1},{"modules",Json::array({Json{{"task_id","network"},{"status","ok"},{"adapters",adapters},{"interfaces",ifs}},
        Json{{"task_id","events:System"},{"status","timeout"},{"issues",Json::array({Json{{"reason","test timeout"}}})}}})},{"report_warnings",Json::array()}};
    // Setting names can be stale; shared descriptions must not cause a cross-NIC join.
    s["modules"].push_back({{"task_id","advanced"},{"status","ok"},{"queries",Json::array({Json{{"source","wmi:advanced"},{"rows",Json::array({
        Json{{"Name","Old NIC name"},{"InterfaceDescription","Shared driver"},{"InstanceID","{00000000-0000-0000-0000-000000000001}::*JumboPacket"},{"RegistryKeyword","*JumboPacket"},{"DisplayName","Jumbo Packet"},{"DisplayValue","9014 bytes"},{"RegistryValue",Json::array({"9014"})},{"Source",3}},
        Json{{"Name","NIC B"},{"InterfaceDescription","Shared driver"},{"InstanceID","{00000000-0000-0000-0000-000000000002}::JumboPacket"},{"RegistryKeyword","JumboPacket"},{"DisplayName","Jumbo Packet"},{"DisplayValue","9 KB"},{"RegistryValue",Json::array({"2"})},{"Source",3}},
        Json{{"Name","NIC A"},{"InstanceID","{00000000-0000-0000-0000-000000000001}::EEELinkAdvertisement"},{"RegistryKeyword","EEELinkAdvertisement"},{"DisplayValue","Enabled while awake"},{"RegistryValue",Json::array({"1"})},{"Source",3}}
    })}}})}});
    s["modules"].push_back({{"task_id","power"},{"status","ok"},{"queries",Json::array({Json{{"rows",Json::array({Json{{"Name","NIC A"},{"AllowComputerToTurnOffDevice",2},{"SelectiveSuspend",0},{"DeviceSleepOnDisconnect",3},{"WakeOnMagicPacket",1},{"WakeOnPattern",2},{"Source",2}}})}}})}});
    s["modules"].back()["queries"][0]["rows"][0]["InstanceID"]="{00000000-0000-0000-0000-000000000001}";
    s["modules"].push_back({{"task_id","bindings"},{"status","ok"},{"queries",Json::array({Json{{"source","wmi:bindings"},{"rows",Json::array({
        Json{{"Name","Old NIC name"},{"InstanceID","{00000000-0000-0000-0000-000000000001}::filter_a"},{"ComponentClassName","Filter"},{"ComponentID","filter_a"},{"DisplayName","Filter for A"},{"Enabled",true}},
        Json{{"Name","NIC A"},{"InstanceID","{00000000-0000-0000-0000-000000000002}::filter_b"},{"ComponentClassName","Filter"},{"ComponentID","filter_b"},{"DisplayName","Filter for B"},{"Enabled",false}},
        Json{{"Name","NIC A"},{"InstanceID","{00000000-0000-0000-0000-000000000042}::unknown"},{"InterfaceIndex",1},{"ComponentClassName","Filter"},{"ComponentID","unknown"},{"DisplayName","Unmapped filter"},{"Enabled",true}},
        Json{{"Name","Public profile"},{"InterfaceIndex",1},{"NetworkCategory",0}}
    })}}})}});
    s["modules"].push_back({{"task_id","drivers"},{"status","ok"},{"queries",Json::array({Json{{"source","wmi:drivers"},{"rows",Json::array({
        Json{{"GUID","{00000000-0000-0000-0000-000000000001}"},{"PNPDeviceID","PCI\\NIC_A"},{"Name","Shared driver"}},
        Json{{"GUID","{00000000-0000-0000-0000-000000000002}"},{"PNPDeviceID","PCI\\NIC_B"},{"Name","Shared driver"}},
        Json{{"DeviceID","pci\\nic_a"},{"DeviceName","Shared driver"},{"DriverVersion","A-only"}},
        Json{{"DeviceID","PCI\\NIC_B"},{"DeviceName","Shared driver"},{"DriverVersion","B-only"}}
    })}}})}});
    s["modules"].push_back({{"task_id","registry"},{"status","ok"},{"keys",Json::array({Json{{"source","registry:NIC/0042"},{"values",Json::array({
        Json{{"name","NetCfgInstanceId"},{"raw_value","{00000000-0000-0000-0000-000000000042}"}},Json{{"name","DriverDesc"},{"raw_value","Absent USB NIC"}},
        Json{{"name","JumboPacket"},{"raw_value","2"},{"registry_type",1}},Json{{"name","PnPCapabilities"},{"raw_value",24},{"registry_type",4}}
    })}}})}});
    EvidenceFiles files{{"snapshot.json",json_text(s)},{"events-System.jsonl",json_text(event(32,2,"2026-10-09T00:00:03.500Z","Shared driver"))+"\n"+json_text(event(27,1,"2026-10-09T00:00:00.000Z","Shared driver"))+"\n"}};
    manifest(files);return files;
}
void zip_fixture(const fs::path& p,const EvidenceFiles& files) {
    // Small in-memory archive; files are written only in this test's output directory.
    mz_zip_archive zip{};require(mz_zip_writer_init_heap(&zip,0,0)!=0,"Create test ZIP");
    try {for(const auto& [n,b]:files)require(mz_zip_writer_add_mem(&zip,n.c_str(),b.data(),b.size(),MZ_BEST_SPEED)!=0,"Add test ZIP entry");
        void* memory=nullptr;size_t size=0;require(mz_zip_writer_finalize_heap_archive(&zip,&memory,&size)!=0,"Finalize test ZIP");
        Handle file(CreateFileW(p.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr));require(bool(file),"Create test ZIP file");write_all(file.get(),std::string_view(static_cast<char*>(memory),size));mz_free(memory);mz_zip_writer_end(&zip);
    }catch(...){mz_zip_writer_end(&zip);throw;}
}
}
int wmain(int argc,wchar_t** argv) {
    try {
        if(argc==3&&std::wstring_view(argv[1])==L"--bundle") {
            auto r=analyze_evidence(load_evidence(argv[2]));Json summary={{"events",r["event_count"]},{"interfaces",r["interface_count"]},{"filters",r["filter_count"]},{"incomplete",r["incomplete"]},{"links",r["links"]},{"overlaps",r["overlaps"]}};
            console_text(json_text(summary,2)+"\n");return 0;
        }
        auto files=fixture();auto r=analyze_evidence(files);
        require(r["event_count"]==2&&r["incomplete"]==true,"Timeout must remain visible even without report warnings.");
        require(r["nics"][0]["ipv4"][0]["assignment"]=="Manual","Manual link-local addresses must not be labeled DHCP failure.");
        require(r["nics"][1]["ipv4"][0]["link_local"]==false,"169.253 is not link-local.");
        require(r["overlaps"].size()==1&&r["overlaps"][0]["both_up"]==false,"Inactive overlap must be separate from active overlap.");
        require(r["links"].size()==1&&r["links"][0]["median_s"]==3.5,"Reverse-order events must be sorted before pair analysis.");
        require(r["links"][0]["name"]=="모호한 NIC: e1rexpress"&&r["ambiguous_link_nics"]["모호한 NIC: e1rexpress"].size()==3,"Shared descriptions must not assign link history to the last NIC.");
        auto unique=files;auto unique_snapshot=Json::parse(unique["snapshot.json"]);
        unique_snapshot["modules"][0]["adapters"][1]["description"]="Different B";unique_snapshot["modules"][0]["adapters"][2]["description"]="Different C";
        unique["snapshot.json"]=json_text(unique_snapshot);manifest(unique);
        require(analyze_evidence(unique)["links"][0]["name"]=="NIC A","A unique description must still map to the correct NIC.");
        auto html=analysis_html(r);require(html.find("&lt;script&gt;alert")!=std::string::npos&&html.find("<script>alert")==std::string::npos,"HTML must escape untrusted event text.");
        const auto& settings=r["nic_settings"];
        require(settings["advanced"].size()==3&&settings["advanced"][0]["Name"]=="NIC A"&&settings["advanced"][0]["ip_mtu"]==9000,"Jumbo must map by GUID and retain separate IP MTU.");
        require(settings["advanced"][1]["Name"]=="NIC B"&&settings["advanced"][1]["RegistryValue"][0]=="2"&&settings["advanced"][1]["DisplayValue"]=="9 KB","Driver enum values must not be interpreted as byte sizes.");
        require(settings["registry"].size()==2&&settings["registry"][0]["nic_state"]=="미매핑"&&settings["registry"][0]["ip_mtu"].is_null(),"Absent NIC registry values must remain saved settings without an active MTU.");
        require(html.find("Unsupported (0)")!=std::string::npos&&html.find("Disabled (1)")!=std::string::npos&&html.find("Enabled (2)")!=std::string::npos&&html.find("Inactive (3)")!=std::string::npos,"Power settings must retain distinct enumerated states.");
        require(html.find("Jumbo Packet 설정과 IP MTU")!=std::string::npos&&html.find("EEELinkAdvertisement")!=std::string::npos&&html.find("Absent USB NIC")!=std::string::npos,"NIC setting summaries must be visible in HTML.");
        const auto& nic_a=r["nics"][0]["details"];const auto& nic_b=r["nics"][1]["details"];
        require(nic_a["bindings"].size()==1&&nic_a["bindings"][0]["ComponentID"]=="filter_a"&&nic_b["bindings"].size()==1&&nic_b["bindings"][0]["Enabled"]==false,"NIC binding groups must use GUIDs and preserve disabled filters; conflicting GUIDs must not fall back to ifIndex.");
        require(nic_a["power"].size()==1&&nic_a["advanced"].size()==2&&nic_a["profiles"].size()==1,"NIC details must group settings and profiles by GUID or recorded ifIndex.");
        require(nic_a["drivers"].size()==1&&nic_a["drivers"][0]["DriverVersion"]=="A-only"&&nic_b["drivers"][0]["DriverVersion"]=="B-only","Driver grouping must join device identities, not shared descriptions.");
        auto card_start=html.find("id=\"nic-1\"");auto card_end=html.find("id=\"nic-2\"",card_start);auto card=html.substr(card_start,card_end-card_start);
        require(card_start!=std::string::npos&&card.find("169.254.1.1")!=std::string::npos&&card.find("Filter for A")!=std::string::npos&&card.find("A-only")!=std::string::npos&&card.find("EEELinkAdvertisement")!=std::string::npos,"Each NIC card must contain its addresses, filters, driver and settings.");
        require(card.find("Filter for B")==std::string::npos&&card.find("B-only")==std::string::npos&&card.find("Unmapped filter")==std::string::npos,"Other or unmapped NIC values must not leak into a NIC card.");
        auto nullable=files;auto nullable_snapshot=Json::parse(nullable["snapshot.json"]);
        for(auto& m:nullable_snapshot["modules"]) {
            if(m["task_id"]=="bindings")m["queries"][0]["rows"][0]["Enabled"]=nullptr;
            if(m["task_id"]=="advanced")m["queries"][0]["rows"][0]["RegistryKeyword"]=nullptr;
        }
        nullable["snapshot.json"]=json_text(nullable_snapshot);manifest(nullable);auto nullable_report=analyze_evidence(nullable);auto nullable_html=analysis_html(nullable_report);
        require(nullable_report["nics"][0]["details"]["bindings"][0]["Enabled"].is_null()&&nullable_report["nics"][0]["details"]["advanced"][0]["RegistryKeyword"].is_null(),"Unknown values must remain null in the evidence model.");
        require(nullable_html.find("badge unknown")!=std::string::npos&&nullable_html.find("미확인 1")!=std::string::npos,"Unknown filter states must be displayed separately from disabled filters.");
        require(nullable_report["incomplete"]==true&&nullable_html.find("9014 bytes")!=std::string::npos,"Nullable settings must preserve other report data and indicate incomplete interpretation.");
        auto date_files=files;date_files["events-System.jsonl"].clear();
        for(const auto& ev:std::initializer_list<Json>{event(32,13,"2026-10-08T15:00:00.000Z"),event(32,12,"2026-10-08T14:59:59.9999999Z"),event(27,11,"2026-10-07T15:00:00.000Z"),event(27,10,"2026-10-07T14:59:59.9999999Z")})date_files["events-System.jsonl"]+=json_text(ev)+"\n";
        date_files["setupapi-timeline.jsonl"]=json_text(Json{{"time_utc","2026-10-08T01:00:00.000Z"},{"time_local","deliberately unrelated local date"},{"message","=SUM(1,2)"}})+"\n"+json_text(Json{{"time_utc",nullptr},{"message","Unknown date"}})+"\n";
        manifest(date_files);auto df=event_date_filter("2026-10-08");auto dated=analyze_evidence(date_files,df);
        require(dated["event_count"]==2&&dated["source_event_count"]==4&&dated["selected_events"].size()==3&&dated["undated_setupapi_count"]==1,"Date selection must use UTC with explicit offset, preserve midnight boundaries, and exclude undated SetupAPI.");
        require(dated["selected_events"][0]["record"]["record_id"]==11&&dated["selected_events"][2]["record"]["record_id"]==12,"Selected records must be ordered chronologically with source references.");
        require(dated["selected_events"][0]["source_line"]==3&&dated["selected_events"][2]["source_line"]==2&&dated["selected_events"][0]["time_selected"]=="2026-10-08T00:00:00.000+09:00","Date exports must retain original lines and explicit selected-zone timestamps.");
        auto exported=selected_events_jsonl(dated);std::istringstream exported_lines(exported);std::string first_line;std::getline(exported_lines,first_line);
        require(Json::parse(first_line)["record"]==event(27,11,"2026-10-07T15:00:00.000Z"),"Exported original event fields and XML must be unchanged.");
        require(selected_events_csv(dated).find("'=SUM(1,2)")!=std::string::npos,"CSV date export must prevent spreadsheet formula execution.");
        require(analyze_evidence(date_files,event_date_filter("2026-10-10"))["selected_events"].empty(),"A date without matching records must produce an empty selection.");
        require(iso_time(event_date_filter("2026-10-08","-05:00").from)=="2026-10-08T05:00:00.000Z","Negative timezone offsets must be applied in the correct direction.");
        require(iso_time(event_date_filter("2024-02-29").from)=="2024-02-28T15:00:00.000Z","Leap dates must be accepted.");
        rejects([&]{event_date_filter("2026-02-29");},"Invalid leap dates must be rejected.");
        rejects([&]{event_date_filter("2026-10-08","+14:01");},"Invalid offsets must be rejected.");
        require(analysis_html(dated).find("지정 날짜의 이벤트 목록")!=std::string::npos,"Dated HTML must include selected event detail.");
        auto damaged=files;damaged["snapshot.json"]+=' ';rejects([&]{analyze_evidence(damaged);},"Hash mismatch must be rejected.");
        auto partial=files;partial["events-System.jsonl"]+="{\"unfinished\":";manifest(partial);auto pr=analyze_evidence(partial);
        require(pr["event_count"]==2&&pr["event_channels"][0]["excluded"]==1,"Truncated tail must preserve valid rows and mark exclusions.");
        auto duplicate=files;duplicate["events-System.jsonl"]+=json_text(event(27,1,"2026-10-09T00:00:00.000Z"))+"\n";manifest(duplicate);
        require(analyze_evidence(duplicate)["event_count"]==2,"Duplicate identity must not inflate counts.");
        auto bad_xml=files;auto ev=event(27,1,"2026-10-09T00:00:00.000Z");ev["xml"]="<!DOCTYPE Event SYSTEM 'https://invalid.test/external'><Event/>";
        bad_xml["events-System.jsonl"]=json_text(ev)+"\n";manifest(bad_xml);require(analyze_evidence(bad_xml)["event_count"]==0,"XML DTD must be rejected without external resolution.");
        auto spoof=files;ev=event(27,1,"2026-10-09T00:00:00.000Z");ev["event_id"]=32;spoof["events-System.jsonl"]=json_text(ev)+"\n";manifest(spoof);require(analyze_evidence(spoof)["event_count"]==0,"XML identity mismatch must not be counted.");
        auto unknown=files;auto snapshot=Json::parse(unknown["snapshot.json"]);snapshot["schema_version"]=2;unknown["snapshot.json"]=json_text(snapshot);manifest(unknown);
        rejects([&]{analyze_evidence(unknown);},"Unknown schema must be rejected.");
        auto root=Output::create_run(fs::current_path(),"FetchNetworkAnalysis-");Output output(root);
        for(const auto& [n,b]:files)output.write(n,b);
        auto folder=load_evidence(root);zip_fixture(output.file("test.zip"),files);auto zipped=load_evidence(output.file("test.zip"));
        require(folder==zipped&&files==zipped,"Folder and ZIP must yield identical verified evidence.");
        auto sapera_files=files;sapera_files["sapera-Logs.dat"]=std::string(28*1024*1024,'\0');sapera_files["sapera-Logs.dat"].back()='\xff';
        manifest(sapera_files);zip_fixture(output.file("sapera.zip"),sapera_files);
        auto sapera_zip=load_evidence(output.file("sapera.zip"));
        require(sapera_zip["sapera-Logs.dat"].empty()&&sapera_zip.streamed_digests().at("sapera-Logs.dat").size_bytes==28*1024*1024,"Sapera binary must be streamed and verified beyond the 16 MiB text log limit.");
        require(analyze_evidence(sapera_zip)["event_count"]==2,"Sapera binary must not be parsed as text SDK events.");
        auto sapera_root=Output::create_run(fs::current_path(),"FetchNetworkAnalysis-");Output sapera_output(sapera_root);
        for(const auto& [name,bytes]:sapera_files)sapera_output.write(name,bytes);
        auto sapera_folder=load_evidence(sapera_root);
        require(sapera_folder.streamed_digests().at("sapera-Logs.dat").sha256==sapera_zip.streamed_digests().at("sapera-Logs.dat").sha256,"Folder and ZIP must verify identical Sapera binary bytes.");
        auto bad_sapera=sapera_files;bad_sapera["sapera-Logs.dat"][0]='X';zip_fixture(output.file("bad-sapera.zip"),bad_sapera);
        rejects([&]{load_evidence(output.file("bad-sapera.zip"));},"Damaged Sapera binary must fail manifest hash verification.");
        auto logged=files;logged["user-log-1.log"]="opaque log bytes";manifest(logged);zip_fixture(output.file("logged.zip"),logged);
        auto streamed=load_evidence(output.file("logged.zip"));require(streamed["user-log-1.log"].empty()&&streamed.streamed_digests().at("user-log-1.log").size_bytes==16,"User logs must be hashed without retaining their bodies.");
        require(analyze_evidence(streamed)["event_count"]==2,"Streamed user logs must not change structured analysis.");
        auto bad_log=logged;bad_log["user-log-1.log"][0]='X';zip_fixture(output.file("bad-log.zip"),bad_log);
        rejects([&]{load_evidence(output.file("bad-log.zip"));},"Streamed user log SHA-256 mismatch must be rejected.");
        auto oversized_log=logged;oversized_log["user-log-1.log"]=std::string(kUserLogBytes+1,'x');manifest(oversized_log);zip_fixture(output.file("large-log.zip"),oversized_log);
        rejects([&]{load_evidence(output.file("large-log.zip"));},"User log streaming must retain the collector's per-log byte limit.");
        auto before=sha256(output.file("snapshot.json"));rejects([&]{analyze_main({L"analyze",root.native(),L"--output",root.native()});},"Output must not be inside evidence.");
        auto alternate_case=root.native();for(auto& c:alternate_case)if(c>=L'a'&&c<=L'z')c-=L'a'-L'A';
        rejects([&]{analyze_main({L"analyze",root.native(),L"--output",alternate_case});},"Windows path casing must not bypass the evidence output boundary.");
        require(sha256(output.file("snapshot.json"))==before,"Analysis must not modify source evidence.");
        auto unsafe=files;unsafe["../snapshot.json"]="unsafe";zip_fixture(output.file("unsafe.zip"),unsafe);rejects([&]{load_evidence(output.file("unsafe.zip"));},"ZIP traversal entries must be rejected.");
        auto extra=files;extra["extra.txt"]="not in manifest";zip_fixture(output.file("extra.zip"),extra);rejects([&]{load_evidence(output.file("extra.zip"));},"Unmanifested ZIP entries must be rejected.");
        auto outside=Output::create_run(fs::current_path(),"FetchNetworkAnalysis-");Output outside_output(outside);
        outside_output.write("manifest.json",json_text(Json{{"files",Json::array({Json{{"name","../snapshot.json"},{"size_bytes",0},{"sha256",sha256_bytes("")}}})}}));
        auto entries=static_cast<size_t>(std::distance(fs::directory_iterator(fs::current_path()),fs::directory_iterator{}));
        rejects([&]{analyze_main({L"analyze",root.native(),L"--date",L"2026-02-30"});},"Invalid analyze dates must fail before output creation.");
        rejects([&]{analyze_main({L"analyze",root.native(),L"--utc-offset",L"+00:00"});},"An offset without a date must fail before output creation.");
        rejects([&]{analyze_main({L"analyze",root.native(),L"--date",L"2026-10-08",L"--date",L"2026-10-09"});},"Duplicate analyze options must fail before output creation.");
        rejects([&]{analyze_main({L"analyze",outside.native(),L"--output",fs::current_path().native()});},"Bad inputs must fail before creating a report directory.");
        require(entries==static_cast<size_t>(std::distance(fs::directory_iterator(fs::current_path()),fs::directory_iterator{})),"Validation failure must not create output.");
        output.write("test.zip.sha256",std::string(64,'0'));rejects([&]{load_evidence(output.file("test.zip"));},"Wrong archive sidecar checksum must be rejected.");
        console_text("Analyzer behavioral checks passed.\n");return 0;
    }catch(const std::exception& e){try{console_text(std::string(e.what())+"\n",true);}catch(...){}return 1;}
}
