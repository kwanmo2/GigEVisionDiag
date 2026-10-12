#include "analyzer.hpp"
#include "diagnostics.hpp"
#include <iostream>
#include <set>
using namespace fnc;
namespace {
void require(bool b,const std::string& message){if(!b)throw std::runtime_error(message);}
template<class F>void rejects(F f,const char* message){bool rejected=false;try{f();}catch(const std::exception&){rejected=true;}require(rejected,message);}
void manifest(EvidenceFiles& files){Json items=Json::array();for(const auto& [n,b]:files)if(n!="manifest.json")items.push_back({{"name",n},{"size_bytes",b.size()},{"sha256",sha256_bytes(b)}});files["manifest.json"]=json_text(Json{{"files",items}});}
Json system_event(int id,int record,std::string time,std::string device) {
    auto xml="<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='e1rexpress'/><EventID>"+std::to_string(id)+"</EventID><EventRecordID>"+std::to_string(record)+"</EventRecordID><TimeCreated SystemTime='"+time+"'/></System><EventData><Data/><Data>"+device+"</Data></EventData></Event>";
    return {{"provider","e1rexpress"},{"channel","System"},{"event_id",id},{"record_id",record},{"level",3},{"time_utc",time},{"time_local",time},{"xml",xml},{"message","link event"}};
}
Json boot_event(int record,std::string time) {
    auto xml="<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Kernel-General'/><EventID>12</EventID><EventRecordID>"+std::to_string(record)+"</EventRecordID><TimeCreated SystemTime='"+time+"'/></System><EventData/></Event>";
    return {{"provider","Microsoft-Windows-Kernel-General"},{"channel","System"},{"event_id",12},{"record_id",record},{"level",4},{"time_utc",time},{"time_local",time},{"xml",xml},{"message","boot"}};
}
Json crash_event(int record,std::string time) {
    auto xml="<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Application Error'/><EventID>1000</EventID><EventRecordID>"+std::to_string(record)+"</EventRecordID><TimeCreated SystemTime='"+time+"'/></System><EventData><Data Name='AppName'>CamApp.exe</Data><Data Name='ModuleName'>MVSDKmd.dll</Data><Data Name='ExceptionCode'>c0000005</Data></EventData></Event>";
    return {{"provider","Application Error"},{"channel","Application"},{"event_id",1000},{"record_id",record},{"level",2},{"time_utc",time},{"time_local",time},{"xml",xml},{"message","<script>alert(1)</script>"}};
}
Json adapter(unsigned index,std::string name,std::string description,bool hardware,std::string ip,unsigned origin,Json gateways=Json::array()) {
    return {{"if_index",index},{"adapter_name","{00000000-0000-0000-0000-00000000000"+std::to_string(index)+"}"},{"friendly_name",name},{"description",description},{"filter_interface",false},
        {"hardware_interface",hardware},{"mac","00:11:22:33:44:5"+std::to_string(index)},{"dhcp_v4_enabled",origin==3},{"gateways",gateways},{"dns_servers",Json::array({"8.8.8.8"})},
        {"addresses",Json::array({Json{{"address",ip},{"prefix_length",24},{"prefix_origin",origin}}})}};
}
Json interface_row(unsigned index,unsigned status,uint64_t speed,unsigned mtu,uint64_t errors,uint64_t discards) {
    return {{"if_index",index},{"mtu",mtu},{"filter_interface",false},{"oper_status",status},{"rx_link_bps",speed},{"tx_link_bps",speed},
        {"counters",{{"in_octets",1048576000},{"out_octets",1000},{"in_errors",errors},{"out_errors",0},{"in_discards",discards},{"out_discards",0}}}};
}
std::string guid(unsigned index){return "{00000000-0000-0000-0000-00000000000"+std::to_string(index)+"}";}
Json advanced(unsigned index,std::string keyword,std::string display,std::string value,Json extra=Json::object()) {
    Json row={{"Name","old"},{"InstanceID",guid(index)+"::"+keyword},{"RegistryKeyword",keyword},{"DisplayName",keyword},{"DisplayValue",display},{"RegistryValue",Json::array({value})},{"Source",3}};
    row.update(extra);return row;
}
Json filter(unsigned index,std::string id,std::string name,bool enabled) {
    return {{"Name","old"},{"InstanceID",guid(index)+"::"+id},{"ComponentClassName","Filter"},{"ComponentID",id},{"DisplayName",name},{"Enabled",enabled}};
}
struct Scenario {
    bool healthy=false,with_power=true;
};
EvidenceFiles fixture(Scenario sc) {
    Json adapters=Json::array({adapter(1,"Camera1","Intel(R) I210 Gigabit Network Connection",true,"192.168.10.1",1),
        adapter(2,"Office","Realtek PCIe GbE Family Controller",true,sc.healthy?"10.0.0.5":"192.168.10.50",3,Json::array({sc.healthy?"10.0.0.1":"192.168.10.254"})),
        adapter(3,"Spare","Intel(R) Ethernet I219",true,"169.254.3.3",4),adapter(4,"vEthernet (Default Switch)","Hyper-V Virtual Ethernet Adapter",false,"172.20.0.1",1)});
    Json interfaces=Json::array({interface_row(1,1,sc.healthy?1000000000ULL:100000000ULL,sc.healthy?9000:1500,sc.healthy?0:3,sc.healthy?0:120),
        interface_row(2,1,1000000000ULL,1500,0,0),interface_row(3,2,UINT64_MAX,1500,0,0),interface_row(4,1,10000000000ULL,1500,0,0)});
    Json s={{"schema_version",1},{"started_at_utc","2026-10-09T01:00:00.000Z"},{"inputs",{{"expected_camera_ip","192.168.10.20"},{"camera_mac",nullptr},{"from_utc","2026-09-09T00:00:00.000Z"},{"to_utc","2026-10-09T01:00:00.000Z"}}},
        {"modules",Json::array({Json{{"task_id","network"},{"status","ok"},{"adapters",adapters},{"interfaces",interfaces},{"neighbors",Json::array()}},
            Json{{"task_id","system"},{"status","ok"},{"computer_name","LINE-PC-07"},{"os",{{"ProductName","Windows 11 Pro"},{"CurrentBuildNumber","26200"}}}}})},{"report_warnings",Json::array()}};
    Json adv=Json::array({advanced(1,"*JumboPacket",sc.healthy?"9014 Bytes":"Disabled",sc.healthy?"9014":"1514"),
        advanced(1,"*ReceiveBuffers",sc.healthy?"2048":"256",sc.healthy?"2048":"256",{{"NumericParameterMaxValue",2048}}),
        advanced(1,"*EEE",sc.healthy?"Disabled":"Enabled",sc.healthy?"0":"1"),advanced(1,"*InterruptModeration","Enabled","1"),
        advanced(2,"JumboPacket","","2")});
    s["modules"].push_back({{"task_id","advanced"},{"status","ok"},{"queries",Json::array({Json{{"source","wmi:advanced"},{"rows",adv}}})}});
    if(sc.with_power)s["modules"].push_back({{"task_id","power"},{"status","ok"},{"queries",Json::array({Json{{"source","wmi:power"},{"rows",Json::array({
        Json{{"Name","Camera1"},{"InstanceID",guid(1)},{"AllowComputerToTurnOffDevice",sc.healthy?1:2},{"SelectiveSuspend",0},{"Source",2}}})}}})}});
    Json bindings=Json::array({filter(1,"sapera_gige","Teledyne DALSA Sapera GigE Vision Filter Driver",true),
        Json{{"Name","Camera1"},{"InterfaceIndex",1},{"NetworkCategory",0}}});
    if(!sc.healthy){bindings.push_back(filter(1,"pylon_gige","pylon GigE Vision Filter Driver",true));bindings.push_back(filter(1,"insecure_npcap","Npcap Packet Driver (NPCAP)",true));}
    s["modules"].push_back({{"task_id","bindings"},{"status","ok"},{"queries",Json::array({Json{{"source","wmi:bindings"},{"rows",bindings}}})}});
    s["modules"].push_back({{"task_id","firewall"},{"status","ok"},{"current_profile_types",4},{"profiles",Json::array({Json{{"type",4},{"enabled",!sc.healthy},{"default_inbound_action",0},{"block_all_inbound",false}}})},{"rules",Json::array()}});
    s["modules"].push_back({{"task_id","software"},{"status","ok"},{"software",Json::array({Json{{"display_name","Sapera LT 8.70"},{"display_version","8.70"},{"publisher","Teledyne DALSA"}}})}});
    if(!sc.with_power)s["modules"].push_back({{"task_id","power"},{"status","timeout"},{"issues",Json::array({Json{{"reason","test timeout"}}})}});
    EvidenceFiles files{{"snapshot.json",json_text(s)}};
    if(!sc.healthy) {
        // 00:05:00 drop: inside SDK log span, unexplained. 00:06:03: 3 s after DeviceReset (camera reboot). 02:00:10: PC boot. 03:00: no SDK log then.
        files["events-System.jsonl"]=json_text(system_event(27,1,"2026-10-09T00:05:00.000Z","Intel(R) I210 Gigabit Network Connection"))+"\n"+json_text(system_event(32,2,"2026-10-09T00:05:04.000Z","Intel(R) I210 Gigabit Network Connection"))+"\n"
            +json_text(system_event(27,3,"2026-10-09T00:06:03.000Z","Intel(R) I210 Gigabit Network Connection"))+"\n"+json_text(system_event(27,4,"2026-10-09T03:00:00.000Z","Intel(R) I210 Gigabit Network Connection"))+"\n"
            +json_text(boot_event(6,"2026-10-09T02:00:00.000Z"))+"\n"+json_text(system_event(27,7,"2026-10-09T02:00:10.000Z","Intel(R) I210 Gigabit Network Connection"))+"\n";
        files["events-Application.jsonl"]=json_text(crash_event(5,"2026-10-09T00:05:30.000Z"))+"\n";
        files["user-log-1.log"]=
            "2026-10-09 09:00:00.000 INFO [tid:100] CameraImpl MVSDK version:[2.3.5]\n"
            "2026-10-09 09:00:01.000 INFO [tid:100] CameraImpl openDevice begin. Vendor=[Huaray] Model=[A7500MG20] SerialNumber=[SN12345] Version=[1.0.2]\n"
            "2026-10-09 09:00:01.500 INFO [tid:100] CameraImpl get NIC MTU Value: 1500\n"
            "2026-10-09 09:00:01.600 INFO [tid:100] CameraImpl negotiatePacketSize: 1500\n"
            "2026-10-09 09:00:01.700 INFO [tid:100] GigEDevice testPacketSize recive data ret [1500], pktSize [1500], remote ip [192.168.10.20], dev ip [192.168.10.20]\n"
            "2026-10-09 09:00:02.000 INFO [tid:100] StreamSourceImpl startGrabbing begin.\n"
            "2026-10-09 09:05:00.000 INFO [tid:101] StreamSourceImpl statistics info: SerialNumber=[SN12345] imageReceived=[1000] fps=[30.0] lostPacket=[50] resendPacket=[20] errorImage=[30] lostPacketImage=[5]\n"
            "2026-10-09 09:05:01.000 ERROR [tid:101] CameraImpl heartbeat timeout occurred <b>\n"
            "2026-10-09 09:05:02.000 INFO [tid:100] CameraImpl disconnect begin.\n"
            "2026-10-09 09:06:00.000 INFO [tid:100] CameraImpl ParameterNodeImpl execute paramName=[DeviceReset] execute, SerialNumber=[SN12345]\n"
            "2026-10-09 09:07:00.000 INFO [tid:100] CameraImpl openDevice begin. Vendor=[Huaray] Model=[A7500MG20] SerialNumber=[SN12345] Version=[1.0.2]\n";
    }
    manifest(files);return files;
}
const Json* finding(const Json& d,std::string_view id){for(const auto& f:d["findings"])if(f["id"]==std::string(id))return &f;return nullptr;}
std::string severity(const Json& d,std::string_view id){auto f=finding(d,id);return f?(*f)["severity"].get<std::string>():"absent";}
const Json& item(const Json& d,std::string_view id){for(const auto& c:d["checklists"])for(const auto& i:c["items"])if(i["id"]==std::string(id))return i;throw std::runtime_error("missing checklist item "+std::string(id));}
}
int wmain(int argc,wchar_t** argv) {
    try {
        if(argc==3&&std::wstring_view(argv[1])==L"--write-fixture") {
            // Writes the problem-PC fixture as a result folder for manual "analyze" runs.
            auto root=Output::create_run(argv[2],"FetchNetworkConfig-");Output output(root);for(const auto& [n,b]:fixture({}))output.write(n,b);
            console_text(utf8(root.native())+"\n");return 0;
        }
        auto r=analyze_evidence(fixture({}),std::nullopt,std::string("+09:00"));const auto& d=r["diagnosis"];
        std::map<unsigned,std::string> roles;for(const auto& x:d["nic_roles"])roles[x["if_index"].get<unsigned>()]=x["role"];
        require(roles[1]=="camera"&&roles[2]=="uplink"&&roles[3]=="inactive"&&roles[4]=="virtual","NIC roles must separate camera, uplink, inactive and virtual NICs.");
        require(d["camera_nic_count"]==1&&d["hidden_nic_count"]==2&&d["checklists"].size()==1,"Only the camera NIC gets a checklist; inactive/virtual NICs are hidden.");
        require(d["overall"]=="critical","A broken camera link must make the overall verdict critical.");
        for(auto [id,sev]:std::initializer_list<std::pair<const char*,const char*>>{{"NIC-LINK","critical"},{"NIC-JUMBO","warning"},{"NIC-RXBUF","warning"},{"NIC-EEE","warning"},
            {"NIC-PWR","warning"},{"FLT-GIGE","warning"},{"FLT-3RD","warning"},{"IP-OVERLAP","critical"},{"FW-PROFILE","warning"},{"NIC-ERR","warning"},{"EVT-LINKDOWN","critical"},
            {"SDK-LOSS","critical"},{"SDK-TIMEOUT","warning"},{"SDK-PKT-SMALL","warning"},{"EVT-APPCRASH-SDK","critical"},{"CORR-LINK-SDK","critical"}})
            require(severity(d,id)==sev,std::string("Expected ")+id+" = "+sev+", got "+severity(d,id));
        require((*finding(d,"CORR-LINK-SDK"))["basis"]=="추정","Time correlation must be labeled as inference.");
        require(d["findings"][0]["severity"]=="critical","Findings must be ordered by severity.");
        require(d["cameras"].size()==1&&d["cameras"][0]["model"]=="A7500MG20","Cameras must be listed from SDK sessions.");
        require(d["timeline"].size()>=4,"Timeline must merge link, SDK and application events.");
        auto link_text=item(d,"EVT-LINKDOWN")["observed"].get<std::string>();
        require(d["sdk_reset_count"]==1&&link_text.find("1회는 앱이 카메라에 DeviceReset")!=std::string::npos&&link_text.find("1회는 SDK 로그가 보존되지 않은")!=std::string::npos
            &&link_text.find("1회는 SDK 로그 구간 안에서 원인 미확인")!=std::string::npos&&link_text.find("1회는 PC 재시작")!=std::string::npos,
            "Link drops must split into reset-induced, PC-side, no-log and unexplained: "+link_text);
        const auto& syn=d["synthesis"];const auto& link=d["checklists"][0]["link"];
        require(link["down"]==4&&link["reset"]==1&&link["pc_side"]==1&&link["no_log"]==1&&link["unexplained"]==1&&link["episodes"]==1,"Link breakdown must be stored per camera NIC: "+link.dump());
        require(!syn["conclusions"].empty()&&syn["conclusions"][0]["severity"]=="critical"&&syn["conclusions"][0]["text"].get<std::string>().find("Camera1 링크 분리 4회")!=std::string::npos,
            "Synthesis must lead with the most severe conclusion: "+syn["conclusions"].dump());
        {std::set<std::string> ids;for(const auto& a:syn["actions"])require(ids.insert(a["id"].get<std::string>()).second,"Actions must be one per rule id.");require(ids.contains("NIC-LINK"),"Actions must include critical findings.");}
        require(syn["profile"].dump().find("PC 시작")!=std::string::npos&&!syn["limits"].empty(),"Synthesis must include the operating profile and analysis limits.");
        require(severity(d,"EVT-POWER")=="info","PC boots must be reported.");
        require(item(d,"IP-CAMSUBNET")["status"]=="ok"&&d["sdk_camera_ips"][0]=="192.168.10.20","Camera IPs from SDK logs must map to the camera NIC subnet.");
        for(const auto& x:d["nic_roles"])if(x["if_index"]==1)require(x["reasons"].dump().find("SDK 로그의 카메라 IP")!=std::string::npos,"SDK camera IPs must count as camera NIC evidence.");
        require(severity(d,"NIC-JUMBO")=="warning"&&item(d,"NIC-JUMBO")["observed"]=="Disabled","Disabled jumbo must be reported from the display value.");
        auto html=analysis_html(r);
        require(html.find("종합 판정: 심각")!=std::string::npos&&html.find("id=\"appendix\"")!=std::string::npos&&html.find("카메라 NIC 체크리스트")!=std::string::npos,"HTML must lead with verdict, findings and checklist, with an appendix.");
        require(html.find("<script>alert(1)")==std::string::npos&&html.find("timeout occurred <b>")==std::string::npos,"Untrusted SDK and event text must stay escaped.");
        require(html.find("id=\"nic-1\"")!=std::string::npos,"Detailed NIC cards must remain in the appendix.");
        require(html.find("id=\"synthesis\"")<html.find("id=\"findings\"")&&html.find("링크 분리 원인 분해")!=std::string::npos,"The synthesis must come before the individual findings.");
        // Masked LLM context.
        auto context=json_text(llm_context(r));
        require(context.find("LINE-PC-07")==std::string::npos&&context.find("SN12345")==std::string::npos&&context.find("8.8.8.8")==std::string::npos,"LLM context must mask host name, serial numbers and public IPs.");
        require(context.find("192.168.10.1")!=std::string::npos&&context.find("CORR-LINK-SDK")!=std::string::npos,"LLM context must keep private subnets and finding IDs.");
        // Healthy configuration produces no camera NIC warnings.
        auto healthy=analyze_evidence(fixture({.healthy=true}));const auto& hd=healthy["diagnosis"];
        for(const auto& f:hd["findings"])require(f["severity"]!="critical"&&f["severity"]!="warning","Healthy configuration must not raise: "+f["id"].get<std::string>());
        require(item(hd,"NIC-JUMBO")["status"]=="ok"&&item(hd,"NIC-RXBUF")["status"]=="ok"&&item(hd,"FW-PROFILE")["status"]=="ok","Healthy settings must be marked ok.");
        // Missing values are unknown, never treated as disabled.
        auto missing=analyze_evidence(fixture({.with_power=false}));const auto& md=missing["diagnosis"];
        require(item(md,"NIC-PWR")["status"]=="unknown"&&severity(md,"NIC-UNKNOWN")=="unknown"&&severity(md,"COV-MODULES")=="unknown","Missing power data must be unknown and coverage must be reported.");
        // Vendor enum codes on non-standard keywords are not interpreted as bytes.
        for(const auto& x:md["nic_roles"])require(x["if_index"]!=2||x["role"]=="uplink","Gateway NIC remains uplink.");
        // AI review validation and merge.
        Json review={{"schema_version",1},{"summary","링크 단절 <script>x</script>"},{"model","codex"},{"hypotheses",Json::array({Json{{"title","케이블"},{"confidence","high"},{"reasoning","시간 일치"},{"finding_ids",Json::array({"CORR-LINK-SDK","NOPE"})}}})},
            {"actions",Json::array({Json{{"priority",1},{"action","케이블 교체"},{"finding_ids",Json::array({"EVT-LINKDOWN"})}}})},{"additional_checks",Json::array({"스위치 로그"})},{"caveats",Json::array()}};
        auto valid=validate_ai_review(review);r["ai_review"]=valid;auto merged=analysis_html(r);
        require(merged.find("AI 심층 의견")!=std::string::npos&&merged.find("<script>x")==std::string::npos&&merged.find("href=\"#f-")!=std::string::npos,"AI review must render escaped with links to known findings.");
        auto bad=review;bad["hypotheses"][0]["confidence"]="certain";rejects([&]{validate_ai_review(bad);},"Invalid confidence must be rejected.");
        bad=review;bad["schema_version"]=2;rejects([&]{validate_ai_review(bad);},"Unknown AI review schema must be rejected.");
        bad=review;bad["summary"]=std::string(9000,'x');rejects([&]{validate_ai_review(bad);},"Oversized AI text must be rejected.");
        console_text("Diagnostics checks passed.\n");return 0;
    }catch(const std::exception& e){try{console_text(std::string(e.what())+"\n",true);}catch(...){}return 1;}
}
