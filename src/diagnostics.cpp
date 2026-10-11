#include "diagnostics.hpp"
#include "analysis_util.hpp"
#include <algorithm>
#include <map>
#include <regex>

namespace fnc {
using namespace detail;
namespace {
// Thresholds are deliberately conservative and vendor-neutral. Vendor-specific advice stays "info".
constexpr uint64_t kMinCameraLinkBps=1000000000ULL;
constexpr int64_t kJumboOkBytes=8000, kStandardFrameBytes=1514;
constexpr int64_t kReceiveBuffersFallback=2048;
constexpr double kCriticalImageLossRatio=0.01;
constexpr int64_t kCorrelationBeforeTicks=60LL*10000000, kCorrelationAfterTicks=120LL*10000000;
constexpr size_t kTimelineLimit=1500;

struct Vendor {const char* token;const char* name;};
// Specific vendor tokens first; generic GigE tokens last.
constexpr Vendor kGigeFilters[]={{"sapera","Teledyne DALSA"},{"dalsa","Teledyne DALSA"},{"teledyne","Teledyne DALSA"},{"pleora","Pleora eBUS"},{"ebus","Pleora eBUS"},
    {"pylon","Basler pylon"},{"basler","Basler pylon"},{"huaray","Huaray MVSDK"},{"irayple","Huaray MVSDK"},{"mvsdk","Huaray MVSDK"},{"hikrobot","Hikrobot MVS"},
    {"hikvision","Hikrobot MVS"},{"matrox","Matrox"},{"euresys","Euresys"},{"stemmer","Stemmer CVB"},{"spinnaker","Teledyne FLIR"},{"flir","Teledyne FLIR"},
    {"lucid","LUCID Arena"},{"daheng","Daheng Galaxy"},{"vimba","Allied Vision"},{"allied vision","Allied Vision"},{"gige","GigE Vision"},{"gev","GigE Vision"}};
constexpr const char* kThirdPartyFilters[]={"npcap","winpcap","npf","vmware","virtualbox","vbox","zerotier","wireguard","wintun","openvpn","tap-windows","forti",
    "cisco","anyconnect","pangp","globalprotect","zscaler","kaspersky","eset","epfw","symantec","sophos","trend micro","mcafee","crowdstrike","sentinel",
    "check point","bitdefender","ahnlab","netlimiter"};
constexpr const char* kSdkModules[]={"mvsdk","mvcam","gige","genicam","gentl","gcbase","genapi","gev","sapera","corapi","pylon","ebus","pleora","huaray",
    "irayple","spinnaker","vimba","mvcamctrl"};
constexpr const char* kCameraSoftware[]={"sapera","teledyne","dalsa","mvsdk","huaray","irayple","pylon","basler","ebus","pleora","spinnaker","flir","vimba",
    "arena","galaxy","daheng","mvs","hikrobot","matrox","euresys","genicam","gige"};

int rank(std::string_view s){return s=="critical"?4:s=="warning"?3:s=="unknown"?2:s=="info"?1:0;}
bool contains_any(std::string_view text,std::initializer_list<const char*> tokens){for(auto t:tokens)if(text.find(t)!=std::string_view::npos)return true;return false;}
std::string key_of(const Json& row){auto k=lower(string_value(row,"RegistryKeyword"));if(k.starts_with('*'))k.erase(0,1);return k;}
bool standard_key(const Json& row){return string_value(row,"RegistryKeyword").starts_with('*');}
std::string first_registry(const Json& row) {
    if(!row.contains("RegistryValue"))return {};const auto& v=row["RegistryValue"];
    if(v.is_array()&&!v.empty())return v[0].is_string()?v[0].get<std::string>():json_text(v[0]);
    return v.is_string()?v.get<std::string>():v.is_number()?json_text(v):std::string();
}
std::optional<int64_t> integer(std::string_view s) {
    size_t i=0;while(i<s.size()&&(s[i]<'0'||s[i]>'9'))++i;if(i==s.size())return {};int64_t n=0;size_t digits=0;
    for(;i<s.size()&&s[i]>='0'&&s[i]<='9'&&digits<12;++i,++digits)n=n*10+(s[i]-'0');return n;
}
std::optional<int64_t> json_int(const Json& row,std::string_view key) {
    auto it=row.find(std::string(key));if(it==row.end())return {};
    if(it->is_number_integer()||it->is_number_unsigned())return it->get<int64_t>();if(it->is_number_float())return static_cast<int64_t>(it->get<double>());
    if(it->is_string())return integer(it->get<std::string>());return {};
}
bool says_off(std::string v){v=lower(v);return contains_any(v,{"disab","off","사용 안","사용안","끔","none"});}
bool says_on(std::string v){v=lower(v);return !says_off(v)&&(contains_any(v,{"enab","사용","켬"})||v=="on");}
// DisplayValue first; standardized (*) keywords fall back to Microsoft's documented enumerations. Vendor codes are never interpreted.
std::optional<bool> enabled_setting(const Json& row) {
    auto display=string_value(row,"DisplayValue");if(says_off(display))return false;if(says_on(display))return true;
    if(standard_key(row)){auto v=first_registry(row);if(v=="0")return false;if(v=="1")return true;}
    return {};
}
std::optional<int64_t> jumbo_bytes(const Json& row) {
    auto display=lower(string_value(row,"DisplayValue"));if(says_off(display))return kStandardFrameBytes;
    if(auto n=integer(display)){if(display.find("kb")!=std::string::npos||display.find("kib")!=std::string::npos)return *n*1024;return *n;}
    if(standard_key(row))return integer(first_registry(row));
    return {};
}
const Json* setting(const Json& nic,std::initializer_list<const char*> keys) {
    for(const auto& row:arr(obj(nic,"details"),"advanced")){auto k=key_of(row);for(auto key:keys)if(k==key)return &row;}return nullptr;
}
const Json* setting_matching(const Json& nic,std::initializer_list<const char*> tokens) {
    for(const auto& row:arr(obj(nic,"details"),"advanced"))if(contains_any(key_of(row),tokens))return &row;return nullptr;
}
std::string shown(const Json* row){if(!row)return "기록 없음";auto d=string_value(*row,"DisplayValue");return d.empty()?"저장값 "+first_registry(*row):d;}
std::string setting_ref(const Json& nic,const Json* row){return "snapshot.json → advanced · "+field(nic,"friendly_name")+" · "+(row?string_value(*row,"RegistryKeyword"):std::string("—"));}
std::string vendor_of(std::string text){text=lower(text);for(const auto& v:kGigeFilters)if(text.find(v.token)!=std::string::npos)return v.name;return {};}
bool third_party(std::string text){text=lower(text);for(auto t:kThirdPartyFilters)if(text.find(t)!=std::string::npos)return true;return false;}
std::optional<ULONGLONG> local_to_utc(std::string ts,const Json& offset) {
    if(!offset.is_string()||ts.size()<19)return {};ts[10]='T';return parse_iso_time(ts+offset.get<std::string>());
}
std::string ratio_text(double r){std::ostringstream o;o.precision(3);o<<r*100<<"%";return o.str();}
bool in_subnet(const std::string& ip,const Json& address) {
    auto target=prefix(Json{{"address",ip},{"prefix_length",32}});auto p=prefix(address);
    return target&&p&&p->second&&((target->first^p->first)&mask(p->second))==0;
}

class Builder {
public:
    Json findings=Json::array();
    void add(std::string id,std::string severity,std::string category,std::string title,std::string observed,std::string expected,std::string recommendation,
             Json evidence=Json::array(),std::string basis="확인",Json nic=nullptr) {
        if(findings.size()>=200)return;
        findings.push_back({{"id",std::move(id)},{"severity",std::move(severity)},{"category",std::move(category)},{"title",std::move(title)},{"observed",std::move(observed)},
            {"expected",std::move(expected)},{"recommendation",std::move(recommendation)},{"evidence",std::move(evidence)},{"basis",std::move(basis)},{"nic",std::move(nic)}});
    }
};

Json classify(const Json& r,const Json& nics) {
    const auto& s=obj(r,"snapshot");const auto& inputs=obj(s,"inputs");const auto& net=module(s,"network");
    auto camera_mac=lower(string_value(inputs,"camera_mac"));auto expected_ip=string_value(inputs,"expected_camera_ip");
    std::set<int64_t> sdk_mtus;for(const auto& session:arr(obj(r,"sdk"),"sessions"))if(auto m=json_int(obj(session,"fields"),"nic_mtu"))sdk_mtus.insert(*m);
    Json roles=Json::array();
    for(const auto& n:nics) {
        Json reasons=Json::array();int score=0;bool up=n.value("state","")=="Up",hardware=n.value("hardware_interface",false);
        auto lowered=lower(field(n,"description")+" "+field(n,"friendly_name"));
        bool pseudo=contains_any(lowered,{"loopback","wan miniport","bluetooth","teredo","isatap","6to4","kernel debug"});
        std::string role;
        if(n.value("state","")=="NotPresent")role="absent";
        else if(!hardware||pseudo)role=up?"virtual":"hidden";
        else if(!up)role="inactive";
        else {
            for(const auto& b:arr(obj(n,"details"),"bindings"))if(string_value(b,"ComponentClassName")=="Filter"&&boolean_value(b,"Enabled").value_or(false)) {
                auto vendor=vendor_of(field(b,"ComponentID")+" "+field(b,"DisplayName"));if(!vendor.empty()){score+=3;reasons.push_back("GigE 필터 드라이버 활성: "+field(b,"DisplayName"));break;}
            }
            if(!expected_ip.empty())for(const auto& a:arr(n,"ipv4"))if(in_subnet(expected_ip,a)){score+=3;reasons.push_back("입력한 예상 카메라 IP "+expected_ip+"와 같은 서브넷");break;}
            if(!camera_mac.empty())for(const auto& nb:arr(net,"neighbors"))if(nb.value("if_index",0U)==n.value("if_index",0U)&&lower(string_value(nb,"mac"))==camera_mac){score+=3;reasons.push_back("입력한 카메라 MAC이 이 NIC의 Neighbor 캐시에 있음");break;}
            auto mtu=json_int(obj(n,"interface"),"mtu");
            if(mtu&&sdk_mtus.contains(*mtu)&&*mtu>1500){score+=1;reasons.push_back("SDK 로그의 NIC MTU("+std::to_string(*mtu)+")와 일치");}
            if(mtu&&*mtu>1500){score+=1;reasons.push_back("IP MTU "+std::to_string(*mtu)+" (Jumbo)");}
            bool gateway=!arr(n,"gateways").empty();bool manual=false;for(const auto& a:arr(n,"ipv4"))if(a.value("prefix_origin",0U)==1)manual=true;
            if(gateway){score-=2;reasons.push_back("기본 게이트웨이 있음 (사내망/인터넷 연결 NIC 가능성)");}
            else if(manual){score+=1;reasons.push_back("게이트웨이 없는 고정 IP");}
            role=score>=2?"camera":gateway?"uplink":"other";
        }
        roles.push_back({{"if_index",n["if_index"]},{"name",n.value("friendly_name","")},{"description",n.value("description","")},{"state",n.value("state","")},
            {"role",role},{"score",score},{"reasons",reasons}});
    }
    // Without explicit camera evidence, treat gateway-less active hardware NICs as inferred candidates.
    bool any=false;for(const auto& x:roles)if(x["role"]=="camera")any=true;
    if(!any)for(auto& x:roles)if(x["role"]=="other"){x["role"]="camera";x["inferred"]=true;x["reasons"].push_back("카메라 근거는 없지만 게이트웨이 없는 활성 하드웨어 NIC — 추정 후보");}
    return roles;
}

struct NicCheck {
    Builder& b;const Json& nic;Json items=Json::array();std::vector<std::string> unknowns;
    void item(std::string id,std::string name,std::string observed,std::string expected,std::string status,std::string title={},std::string recommendation={},std::string evidence={},bool report_info=false) {
        items.push_back({{"id",id},{"item",name},{"observed",observed},{"expected",expected},{"status",status}});
        if(status=="unknown"){unknowns.push_back(name);return;}
        if(status=="critical"||status=="warning"||(status=="info"&&report_info))
            b.add(id,status,"nic_setting",field(nic,"friendly_name")+": "+title,observed,expected,recommendation,Json::array({evidence}),"확인",nic["if_index"]);
    }
};

void check_nic(Builder& b,const Json& nic,const Json& r,Json& checklists) {
    NicCheck c{b,nic};const auto& i=obj(nic,"interface");const auto& d=obj(nic,"details");auto name=field(nic,"friendly_name");
    auto ref=[&](std::string what){return "snapshot.json → "+what+" · "+name;};
    // Link speed
    if(i.contains("rx_link_bps")&&i["rx_link_bps"].is_number_unsigned()&&i["rx_link_bps"].get<uint64_t>()!=UINT64_MAX) {
        auto bps=i["rx_link_bps"].get<uint64_t>();
        c.item("NIC-LINK","링크 속도",speed_text(i,"rx_link_bps"),"1 Gbps 이상",bps<kMinCameraLinkBps?"critical":"ok","링크 속도가 1 Gbps 미만",
            "케이블(Cat5e 이상)·스위치 포트·PoE 인젝터와 NIC Speed & Duplex(자동 협상)를 확인하십시오. GigE 카메라 대역폭이 부족하면 패킷 손실·프레임 누락이 발생합니다.",ref("network.interfaces"));
    } else c.item("NIC-LINK","링크 속도",speed_text(i,"rx_link_bps"),"1 Gbps 이상","unknown");
    // Jumbo / MTU
    auto mtu=json_int(i,"mtu");const auto* jumbo=setting_matching(nic,{"jumbo"});auto bytes=jumbo?jumbo_bytes(*jumbo):std::nullopt;
    if(jumbo&&bytes) {
        auto status=*bytes>=kJumboOkBytes?"ok":*bytes<=kStandardFrameBytes?"warning":"info";
        c.item("NIC-JUMBO","Jumbo Packet",shown(jumbo),"9014 bytes 이상 (카메라 패킷 크기 이하로 설정)",status,
            *bytes<=kStandardFrameBytes?"Jumbo Packet 비활성":"Jumbo Packet이 최대값보다 작음",
            "NIC 고급 설정에서 Jumbo Packet을 9014 bytes(또는 지원 최대값)로 설정하고 카메라 GevSCPS(Packet Size)를 그 이하로 맞추십시오. 표준 1500 MTU는 패킷 수와 CPU 부하를 크게 늘립니다.",setting_ref(nic,jumbo));
    } else if(mtu) {
        c.item("NIC-JUMBO","Jumbo Packet",jumbo?shown(jumbo)+" (해석 불가)":"설정 항목 없음 — IP MTU로 판단",
            "9014 bytes 이상",*mtu>1500?"ok":"warning","Jumbo 미사용 (IP MTU "+std::to_string(*mtu)+")",
            "NIC가 Jumbo Frame을 지원하면 활성화하십시오. 미지원 NIC(일부 USB/내장 NIC)는 GigE 카메라 전용 NIC로 교체를 검토하십시오.",ref("network.interfaces"));
    } else c.item("NIC-JUMBO","Jumbo Packet","미수집","9014 bytes 이상","unknown");
    if(mtu)c.item("NIC-MTU","IP MTU",std::to_string(*mtu)+" bytes","Jumbo 사용 시 9000 이상",*mtu>1500?"ok":(bytes&&*bytes>=kJumboOkBytes?"warning":"info"),
        "Jumbo Packet은 켜져 있으나 IP MTU가 1500","드라이버 Jumbo 설정 후 링크 재협상(케이블 재연결/NIC 재시작)이 되지 않았거나 다른 계층에서 MTU를 제한하고 있습니다. netsh interface ipv4 show subinterfaces로 확인하십시오.",ref("network.interfaces"));
    else c.item("NIC-MTU","IP MTU","미수집","Jumbo 사용 시 9000 이상","unknown");
    // Receive buffers
    if(const auto* rx=setting(nic,{"receivebuffers","numrxbuffers","rxbuffers"})) {
        auto value=integer(string_value(*rx,"DisplayValue"));if(!value&&standard_key(*rx))value=integer(first_registry(*rx));
        auto max=json_int(*rx,"NumericParameterMaxValue");auto target=max.value_or(kReceiveBuffersFallback);
        if(value)c.item("NIC-RXBUF","Receive Buffers",std::to_string(*value)+(max?" / 최대 "+std::to_string(*max):""),max?"최대값 ("+std::to_string(*max)+")":"2048 이상 (드라이버 최대값 권장)",
            *value>=target?"ok":"warning","Receive Buffers가 최대값보다 작음","NIC 고급 설정에서 Receive Buffers(수신 버퍼)를 최대값으로 늘리십시오. 버퍼가 작으면 버스트 수신 시 패킷이 버려집니다.",setting_ref(nic,rx));
        else c.item("NIC-RXBUF","Receive Buffers",shown(rx),"최대값","unknown");
    } else c.item("NIC-RXBUF","Receive Buffers","설정 항목 없음","최대값","unknown");
    // Interrupt moderation / flow control (vendor-dependent, informational)
    if(const auto* irq=setting(nic,{"interruptmoderation"})) {auto on=enabled_setting(*irq);
        c.item("NIC-IRQ","Interrupt Moderation",shown(irq),"활성 (대부분의 GigE SDK 권장)",!on?"unknown":*on?"ok":"info","Interrupt Moderation 비활성",
            "비활성 상태는 지연을 줄이지만 CPU 부하를 높여 고프레임 수신 시 손실 원인이 될 수 있습니다. 사용 SDK의 권장값을 확인하십시오.",setting_ref(nic,irq),true);}
    if(const auto* flow=setting(nic,{"flowcontrol"}))c.item("NIC-FLOW","Flow Control",shown(flow),"카메라·스위치 권장값과 일치","info");
    // EEE / green ethernet
    bool eee_seen=false;
    for(const auto& row:arr(d,"advanced")) {
        auto k=key_of(row);if(!contains_any(k,{"eee","greenethernet","powersavingmode","energy","ulp","gigalite","reducespeedonpowerdown","autodisablegigabit","sipsenabled"}))continue;
        eee_seen=true;auto on=enabled_setting(row);
        c.item("NIC-EEE",string_value(row,"DisplayName").empty()?string_value(row,"RegistryKeyword"):string_value(row,"DisplayName"),shown(&row),"비활성",
            !on?"unknown":*on?"warning":"ok","절전 이더넷(EEE/Green) 기능 활성: "+string_value(row,"RegistryKeyword"),
            "EEE·Green Ethernet·절전 시 속도 저하 기능은 링크 지연·순간 단절을 일으킬 수 있습니다. 카메라 NIC에서는 비활성화하십시오.",setting_ref(nic,&row));
    }
    if(!eee_seen)c.item("NIC-EEE","EEE / Green Ethernet","설정 항목 없음","비활성","info");
    // Power management
    const auto& power=arr(d,"power");
    if(!power.empty()) {
        const auto& p=power[0];
        for(auto [key,label]:std::initializer_list<std::pair<const char*,const char*>>{{"AllowComputerToTurnOffDevice","장치 전원 차단 허용"},{"SelectiveSuspend","Selective Suspend"}}) {
            auto v=json_int(p,key);std::string status=!v?"unknown":*v==2?"warning":"ok";
            c.item("NIC-PWR",label,power_value(p,key),"Disabled",status,std::string(label)+" 활성",
                "장치 관리자 → NIC 속성 → 전원 관리에서 '전원을 절약하기 위해 컴퓨터가 이 장치를 끌 수 있음'을 해제하고, Windows 전원 계획을 '고성능'으로 설정하십시오.",ref("power"));
        }
    } else c.item("NIC-PWR","전원 관리","조회값 없음","Disabled","unknown");
    // Filters
    std::set<std::string> vendors;std::vector<std::string> others,gige_names;size_t unknown_filters=0;
    for(const auto& f:arr(d,"bindings"))if(string_value(f,"ComponentClassName")=="Filter") {
        auto enabled=boolean_value(f,"Enabled");if(!enabled){++unknown_filters;continue;}if(!*enabled)continue;
        auto text=field(f,"ComponentID")+" "+field(f,"DisplayName");auto vendor=vendor_of(text);
        if(!vendor.empty()){vendors.insert(vendor);gige_names.push_back(field(f,"DisplayName"));}
        else if(third_party(text))others.push_back(field(f,"DisplayName"));
    }
    auto join=[](const std::vector<std::string>& v){std::string o;for(const auto& x:v){if(!o.empty())o+=", ";o+=x;}return o;};
    std::set<std::string> specific=vendors;specific.erase("GigE Vision");
    if(specific.size()>1)c.item("FLT-GIGE","GigE 필터 드라이버",join(gige_names),"사용하는 SDK의 필터 1개만 활성","warning","서로 다른 벤더의 GigE 필터 드라이버가 동시에 활성",
        "여러 SDK의 GigE 필터(Sapera/pylon/eBUS/MVSDK 등)가 같은 NIC에 동시에 바인딩되면 스트림 패킷을 가로채 손실·연결 실패가 날 수 있습니다. 실제 사용하는 SDK의 필터만 남기고 나머지는 NIC 속성에서 해제하십시오.",ref("bindings"));
    else if(vendors.empty())c.item("FLT-GIGE","GigE 필터 드라이버",unknown_filters?"활성 여부 미확인 필터 "+std::to_string(unknown_filters)+"개":"활성 GigE 필터 없음",
        "사용 SDK의 GigE 필터 드라이버 활성 (권장)",unknown_filters?"unknown":"info","GigE 필터 드라이버가 바인딩되지 않음",
        "필터 드라이버 없이도 동작하지만 CPU 부하가 커지고 고해상도·고프레임에서 손실 가능성이 높아집니다. SDK 설치 시 제공하는 GigE 필터(Performance Driver)를 이 NIC에 바인딩하는 것을 검토하십시오.",ref("bindings"),true);
    else c.item("FLT-GIGE","GigE 필터 드라이버",join(gige_names),"사용 SDK의 필터 1개만 활성","ok");
    if(!others.empty())c.item("FLT-3RD","보안·VPN·캡처 필터",join(others),"카메라 NIC에서는 해제 권장","warning","카메라 NIC에 타사 필터 드라이버 활성",
        "백신·VPN·패킷 캡처 필터는 모든 수신 패킷을 검사해 GigE 스트림 지연·손실을 유발할 수 있습니다. 카메라 전용 NIC에서는 바인딩 해제 또는 예외 처리를 검토하십시오.",ref("bindings"));
    else c.item("FLT-3RD","보안·VPN·캡처 필터","없음","없음","ok");
    // IP addressing
    const auto& ipv4=arr(nic,"ipv4");
    if(ipv4.empty())c.item("IP-ADDR","IPv4 주소","없음","카메라와 같은 서브넷의 고정 IP","critical","IPv4 주소 없음","카메라 NIC에 고정 IPv4(예: 192.168.x.1/24)를 지정하십시오.",ref("network.adapters"));
    else {
        std::string text;bool apipa_dhcp=false;for(const auto& a:ipv4){if(!text.empty())text+=", ";text+=field(a,"address")+"/"+field(a,"prefix_length")+" ("+assignment_text(a)+")";
            if(a.value("link_local",false)&&nic.value("dhcp_v4_enabled",false))apipa_dhcp=true;}
        c.item("IP-ADDR","IPv4 주소",text,"카메라와 같은 서브넷의 고정 IP",apipa_dhcp?"warning":"ok","DHCP 실패로 169.254.x.x 자동 할당 상태",
            "카메라 전용 NIC는 DHCP 서버가 없으므로 고정 IP를 지정하십시오. 169.254 대역은 카메라 LLA와 통신은 되지만 재시작 때마다 주소가 바뀔 수 있습니다.",ref("network.adapters"));
    }
    auto gateways=arr(nic,"gateways");
    c.item("IP-GW","기본 게이트웨이",gateways.empty()?"없음":json_text(gateways),"없음",gateways.empty()?"ok":"info","카메라 NIC에 기본 게이트웨이 설정",
        "카메라 NIC에 게이트웨이가 있으면 기본 경로가 둘이 되어 사내망 트래픽이 카메라 NIC로 나갈 수 있습니다. 카메라 NIC의 게이트웨이는 비워 두십시오.",ref("network.adapters"),true);
    // Firewall profile
    const auto& fw=module(obj(r,"snapshot"),"firewall");std::string profile_text="미수집";std::string fw_status="unknown";
    for(const auto& p:arr(d,"profiles")) {
        auto category=json_int(p,"NetworkCategory");if(!category)continue;int type=*category==0?4:*category==1?2:1;
        profile_text=std::string(*category==0?"Public":*category==1?"Private":"Domain");
        for(const auto& fp:arr(fw,"profiles"))if(json_int(fp,"type")==type) {
            auto enabled=boolean_value(fp,"enabled");if(!enabled)break;profile_text+=*enabled?" · 방화벽 켜짐":" · 방화벽 꺼짐";
            if(!*enabled){fw_status="ok";break;}
            size_t allows=0;for(const auto& rule:arr(fw,"rules")) {
                if(rule.value("enabled",false)!=true||json_int(rule,"direction")!=1||json_int(rule,"action")!=1)continue;
                auto profiles=json_int(rule,"profiles");if(profiles&&!(*profiles&type))continue;
                auto t=lower(field(rule,"name")+" "+field(rule,"application_name"));for(auto k:kCameraSoftware)if(t.find(k)!=std::string::npos){++allows;break;}
            }
            profile_text+=" · 카메라 관련 허용 규칙 "+std::to_string(allows)+"개";fw_status=allows?"ok":"warning";break;
        }
    }
    c.item("FW-PROFILE","네트워크 프로필 / 방화벽",profile_text,"방화벽 꺼짐 또는 카메라 앱 인바운드 허용 규칙",fw_status,"방화벽이 켜져 있고 카메라 관련 허용 규칙이 없음",
        "GigE Vision 스트림(GVSP)과 제어 응답(GVCP, UDP 3956)이 인바운드 UDP로 들어옵니다. 카메라 애플리케이션 실행 파일에 대한 인바운드 허용 규칙을 추가하거나 카메라 NIC의 방화벽 정책을 확인하십시오.",ref("firewall / bindings"));
    // Error counters
    const auto& counters=obj(i,"counters");auto errors=json_int(counters,"in_errors"),discards=json_int(counters,"in_discards"),octets=json_int(counters,"in_octets");
    if(errors&&discards) {
        auto bad=*errors+*discards;std::string text="수신 오류 "+std::to_string(*errors)+" / 폐기 "+std::to_string(*discards);
        if(octets&&*octets>0)text+=" (수신 "+std::to_string(*octets/1048576)+" MiB, 부팅/링크 이후 누적)";
        c.item("NIC-ERR","수신 오류·폐기 카운터",text,"0",bad==0?"ok":"warning","NIC 수신 오류/폐기 패킷 누적",
            "수신 폐기는 버퍼 부족·CPU 지연, 수신 오류는 케이블·커넥터·EMI 문제를 의미하는 경우가 많습니다. Receive Buffers 증대, 케이블 교체, 카메라 패킷 지연(GevSCPD) 조정을 검토하십시오.",ref("network.interfaces.counters"));
    } else c.item("NIC-ERR","수신 오류·폐기 카운터","미수집","0","unknown");
    // Link history
    for(const auto& link:arr(r,"links"))if(field(link,"name")==name) {
        auto down=link.value("down",size_t(0));
        c.item("EVT-LINKDOWN","링크 분리 이력",std::to_string(down)+"회 (수집 기간)","0회",down?"critical":"ok","수집 기간 중 링크 분리 "+std::to_string(down)+"회",
            "카메라 NIC 링크가 끊긴 기록입니다. 케이블·커넥터·PoE 전원·스위치 포트·NIC 절전 설정을 순서대로 점검하십시오. 시각은 '상관 타임라인'에서 SDK 오류와 비교할 수 있습니다.","events-System.jsonl (NIC 드라이버 이벤트)");
    }
    if(!c.unknowns.empty()) {std::string list;for(const auto& u:c.unknowns){if(!list.empty())list+=", ";list+=u;}
        b.add("NIC-UNKNOWN","unknown","coverage",name+": 판단 불가 항목 "+std::to_string(c.unknowns.size())+"개",list,"값 수집",
            "해당 값이 미수집·미지원·매핑 실패입니다. 비활성으로 해석하지 마십시오. NIC 속성 창에서 직접 확인하거나 관리자 권한으로 다시 수집하십시오.",Json::array({"snapshot.json → modules 수집 상태"}),"확인",nic["if_index"]);}
    checklists.push_back({{"if_index",nic["if_index"]},{"name",name},{"description",field(nic,"description")},{"items",c.items}});
}

Json session_summary(const Json& s,const Json& offset) {
    Json stats=Json::object();
    for(const auto& st:arr(s,"statistics"))for(const auto& [k,v]:obj(st,"fields").items())if(v.is_number()) {
        if(k=="fps"){stats[k]=v;continue;}
        if(!stats.contains(k)||stats[k].get<double>()<v.get<double>())stats[k]=v;  // Counters are treated as cumulative within a session.
    }
    Json out={{"id",s["id"]},{"source_file",s["source_file"]},{"pid",s["pid"]},{"first_timestamp",s["first_timestamp"]},{"last_timestamp",s["last_timestamp"]},
        {"event_count",s["event_count"]},{"error_count",s["error_count"]},{"warning_count",s["warning_count"]},{"families",s["families"]},{"ended_by",s.value("ended_by",Json(nullptr))},
        {"fields",s["fields"]},{"stats",stats}};
    if(auto t=local_to_utc(string_value(s,"first_timestamp"),offset))out["first_utc"]=iso_time(*t);
    if(auto t=local_to_utc(string_value(s,"last_timestamp"),offset))out["last_utc"]=iso_time(*t);
    auto received=stats.value("imageReceived",0.0),bad=stats.value("errorImage",0.0)+stats.value("lostPacketImage",0.0);
    out["image_loss_ratio"]=received>0?Json(bad/(received+bad)):Json(nullptr);
    return out;
}
} // namespace

Json diagnose(const Json& r) {
    Builder b;const auto& s=obj(r,"snapshot");const auto& nics=arr(r,"nics");const auto& sdk=obj(r,"sdk");
    auto roles=classify(r,nics);std::set<unsigned> camera;std::map<unsigned,std::string> role_of;size_t hidden=0;
    for(const auto& x:roles){auto index=x.value("if_index",0U);role_of[index]=x.value("role","");if(x["role"]=="camera")camera.insert(index);if(x["role"]!="camera"&&x["role"]!="uplink")++hidden;}
    Json checklists=Json::array();
    for(const auto& n:nics)if(camera.contains(n.value("if_index",0U)))check_nic(b,n,r,checklists);
    if(camera.empty())b.add("NIC-NONE","unknown","coverage","카메라 연결 NIC를 특정하지 못함","활성(Up) 하드웨어 NIC 중 카메라 근거가 있는 NIC 없음","카메라 전용 NIC 1개 이상",
        "카메라가 연결된 상태에서 다시 수집하거나 --camera-mac / --expected-camera-ip를 지정하십시오. 아래 부록에서 전체 NIC를 확인할 수 있습니다.",Json::array({"snapshot.json → network"}));
    // Subnet overlap between active NICs
    for(const auto& o:arr(r,"overlaps"))if(o.value("both_up",false))
        b.add("IP-OVERLAP","critical","ip","활성 NIC 간 서브넷 중복: "+field(o,"a")+" ↔ "+field(o,"b"),"두 NIC가 같은 IPv4 서브넷","카메라 NIC마다 서로 다른 서브넷",
            "같은 서브넷의 NIC가 둘 이상이면 Windows가 응답 패킷을 다른 NIC로 보내 카메라 검색 실패·제어 타임아웃이 발생합니다. 카메라 NIC마다 고유 서브넷(예: 192.168.1.x, 192.168.2.x)을 지정하십시오.",
            Json::array({"snapshot.json → network.adapters"}));
    // Link history for non-camera or unresolved NICs
    for(const auto& link:arr(r,"links")) {
        auto name=field(link,"name");auto down=link.value("down",size_t(0));if(!down)continue;bool known=false;
        for(const auto& n:nics)if(field(n,"friendly_name")==name){known=true;break;}
        if(!known)b.add("EVT-LINKDOWN-UNMAPPED","warning","event","NIC를 특정할 수 없는 링크 분리 "+std::to_string(down)+"회 ("+name+")","드라이버 이벤트의 장치 이름이 NIC와 1:1로 매핑되지 않음",
            "0회","같은 드라이버를 쓰는 NIC가 여러 개이면 어느 포트인지 확정할 수 없습니다. 부록의 '기존 이력 집계'에서 후보 NIC를 확인하십시오.",Json::array({"events-System.jsonl"}),"추정");
        else if(!camera.contains([&]{for(const auto& n:nics)if(field(n,"friendly_name")==name)return n.value("if_index",0U);return 0U;}()))
            b.add("EVT-LINKDOWN-OTHER","info","event",name+": 링크 분리 "+std::to_string(down)+"회 (카메라 NIC 아님)","카메라 NIC로 분류되지 않은 NIC","—","카메라와 무관하면 무시해도 됩니다.",Json::array({"events-System.jsonl"}));
    }
    // SDK sessions
    const auto& offset=sdk.contains("utc_offset")?sdk["utc_offset"]:Json(nullptr);Json sessions=Json::array(),cameras=Json::array();std::set<std::string> camera_keys;
    for(const auto& raw:arr(sdk,"sessions")) {
        auto x=session_summary(raw,offset);const auto& f=obj(x,"fields");
        auto key=field(f,"serial_number")+"|"+field(f,"model");
        if((f.contains("model")||f.contains("serial_number"))&&camera_keys.insert(key).second&&cameras.size()<64)
            cameras.push_back({{"vendor",f.value("vendor",Json(nullptr))},{"model",f.value("model",Json(nullptr))},{"serial_number",f.value("serial_number",Json(nullptr))},{"firmware_version",f.value("firmware_version",Json(nullptr))},{"source_file",x["source_file"]}});
        if(sessions.size()<500)sessions.push_back(std::move(x));
    }
    {
        Json loss=Json::array(),resend=Json::array(),timeout=Json::array();double worst=0;
        for(const auto& x:sessions) {
            const auto& st=obj(x,"stats");auto ref=field(x,"source_file")+" / PID "+field(x,"pid")+" / "+field(x,"first_timestamp");
            double lost=st.value("lostPacket",0.0)+st.value("errorImage",0.0)+st.value("lostPacketImage",0.0)+st.value("missingBlock",0.0);
            if(lost>0){loss.push_back(ref+" — lostPacket "+field(st,"lostPacket")+", errorImage "+field(st,"errorImage")+", lostPacketImage "+field(st,"lostPacketImage")+", imageReceived "+field(st,"imageReceived"));
                if(x["image_loss_ratio"].is_number())worst=(std::max)(worst,x["image_loss_ratio"].get<double>());}
            else if(st.value("resendPacket",0.0)>0)resend.push_back(ref+" — resendPacket "+field(st,"resendPacket"));
            if(obj(x,"families").value("timeout",0)>0)timeout.push_back(ref+" — timeout "+field(obj(x,"families"),"timeout")+"회");
        }
        auto first=[](Json v){if(v.size()>10)v.erase(v.begin()+10,v.end());return v;};
        if(!loss.empty())b.add("SDK-LOSS",worst>=kCriticalImageLossRatio?"critical":"warning","sdk","SDK 통계에서 패킷/이미지 손실 기록 ("+std::to_string(loss.size())+"개 세션)",
            "최대 이미지 손실률 "+ratio_text(worst),"lostPacket·errorImage 0","패킷 손실은 NIC 수신 버퍼·Jumbo·필터 드라이버·CPU 부하·케이블 문제에서 주로 발생합니다. 카메라 NIC 체크리스트의 경고 항목을 먼저 해결하고, 다중 카메라라면 GevSCPD(패킷 지연)로 대역폭을 분산하십시오.",first(loss));
        if(!resend.empty())b.add("SDK-RESEND","info","sdk","재전송(resend)은 있었으나 최종 손실은 없음 ("+std::to_string(resend.size())+"개 세션)","resendPacket > 0","0",
            "재전송으로 복구된 손실입니다. 빈도가 늘면 손실로 이어질 수 있으므로 NIC 버퍼·대역폭 여유를 확인하십시오.",first(resend));
        if(!timeout.empty())b.add("SDK-TIMEOUT","warning","sdk","SDK 로그에 timeout 오류 ("+std::to_string(timeout.size())+"개 세션)","heartbeat/응답 timeout","0",
            "제어 채널(GVCP) 응답 지연입니다. 링크 분리·방화벽·서브넷 중복·CPU 과부하를 확인하고, 디버깅 중이라면 heartbeat timeout을 늘리십시오.",first(timeout));
    }
    // Packet size vs NIC MTU
    {
        Json mismatch=Json::array(),standard_frames=Json::array();
        for(const auto& x:sessions){const auto& f=obj(x,"fields");auto packet=json_int(f,"packet_size"),mtu=json_int(f,"nic_mtu");if(!packet)continue;
            auto ref=field(x,"source_file")+" / "+field(x,"first_timestamp")+" — packet "+std::to_string(*packet)+(mtu?", NIC MTU "+std::to_string(*mtu):"");
            if(mtu&&*packet>*mtu)mismatch.push_back(ref);else if(*packet<=1500)standard_frames.push_back(ref);}
        if(!mismatch.empty())b.add("SDK-PKT-MTU","critical","sdk","카메라 패킷 크기가 NIC MTU보다 큼","SDK 협상 패킷 크기 > NIC MTU","패킷 크기 ≤ NIC MTU",
            "큰 패킷은 NIC에서 버려져 이미지가 전혀 들어오지 않거나 불완전해집니다. NIC Jumbo Packet을 늘리거나 카메라 GevSCPS를 줄이십시오.",mismatch);
        if(!standard_frames.empty())b.add("SDK-PKT-SMALL","warning","sdk","카메라 패킷 크기가 1500 이하","표준 프레임 크기로 스트리밍","Jumbo NIC에서는 8000~9000",
            "Jumbo를 쓰지 않으면 초당 패킷 수가 6배가량 늘어 CPU 부하와 손실 위험이 커집니다. NIC Jumbo 활성 후 카메라 패킷 크기를 늘리십시오.",standard_frames);
    }
    // Application crashes
    {
        Json sdk_crash=Json::array(),other=Json::array();
        for(const auto& a:arr(r,"app_incidents")){auto text=lower(field(a,"module_name")+" "+field(a,"module_path"));
            auto ref=field(a,"time_utc")+" "+field(a,"provider")+" / "+field(a,"app_name")+" / "+field(a,"module_name")+" ("+reference(a)+")";
            bool sdk_module=false;for(auto k:kSdkModules)if(text.find(k)!=std::string::npos)sdk_module=true;(sdk_module?sdk_crash:other).push_back(ref);}
        auto first=[](Json v){if(v.size()>10)v.erase(v.begin()+10,v.end());return v;};
        if(!sdk_crash.empty())b.add("EVT-APPCRASH-SDK","critical","event","카메라 SDK 모듈에서 애플리케이션 오류 "+std::to_string(sdk_crash.size())+"건","오류 모듈이 SDK/GigE 관련 DLL","0건",
            "SDK 버전과 애플리케이션 빌드의 호환성, 콜백 내 예외 처리, 메모리 부족을 확인하십시오. 덤프가 있으면 --dump-file로 함께 수집하십시오.",first(sdk_crash));
        if(!other.empty())b.add("EVT-APPCRASH","warning","event","애플리케이션 오류·응답 없음 "+std::to_string(other.size())+"건","Application Error / Hang / WER","0건",
            "카메라 애플리케이션이면 오류 시각을 SDK 로그·링크 이력과 비교하십시오.",first(other));
    }
    // Timeline and correlation
    Json timeline=Json::array();
    auto push=[&](std::string time,std::string kind,std::string label,std::string ref){if(time.empty()||!parse_iso_time(time))return;timeline.push_back({{"time_utc",time},{"kind",kind},{"label",label},{"ref",ref}});};
    for(const auto& link:arr(r,"links"))for(const auto& t:arr(link,"times"))push(field(t,"time_utc"),t.value("action","")=="down"?"link_down":"link_up",field(link,"name"),"events-System.jsonl");
    for(const auto& a:arr(r,"app_incidents"))push(field(a,"time_utc"),"app_crash",field(a,"app_name")+" / "+field(a,"module_name"),reference(a));
    for(const auto& e:arr(sdk,"events")) {
        auto level=string_value(e,"level"),kind=string_value(e,"kind");bool error=level=="ERROR"||level=="WARN"||level=="WARNING";
        if(!error&&kind!="connect"&&kind!="disconnect")continue;if(e["time_utc"].is_null())continue;
        auto message=string_value(e,"message");if(message.size()>200)message.resize(200);
        push(string_value(e,"time_utc"),error?(obj(e,"fields").value("family","")=="timeout"?"sdk_timeout":"sdk_error"):"sdk_"+kind,message,field(e,"source_file")+":"+field(e,"source_line"));
    }
    std::sort(timeline.begin(),timeline.end(),[](const Json& a,const Json& b){return a["time_utc"].get<std::string>()<b["time_utc"].get<std::string>();});
    bool timeline_truncated=timeline.size()>kTimelineLimit;
    {
        Json hits=Json::array();
        for(const auto& down:timeline) {
            if(down["kind"]!="link_down")continue;auto t=*parse_iso_time(down["time_utc"].get<std::string>());
            for(const auto& other:timeline) {
                auto k=other["kind"].get<std::string>();if(k!="sdk_error"&&k!="sdk_timeout"&&k!="sdk_disconnect"&&k!="app_crash")continue;
                auto o=*parse_iso_time(other["time_utc"].get<std::string>());auto delta=static_cast<int64_t>(o)-static_cast<int64_t>(t);
                if(delta>=-kCorrelationBeforeTicks&&delta<=kCorrelationAfterTicks){if(hits.size()<10)hits.push_back(field(down,"time_utc")+" 링크 분리("+field(down,"label")+") ↔ "+std::to_string(delta/10000000)+"초 후 "+k+": "+field(other,"label"));break;}
            }
        }
        if(!hits.empty())b.add("CORR-LINK-SDK","critical","correlation","링크 분리 직후 SDK 오류·연결 해제·앱 오류 발생","링크 분리 시각 기준 -60초~+120초 이내 동시 발생","—",
            "시간상 일치하므로 물리 링크 단절이 카메라 오류의 직접 원인일 가능성이 높습니다. 케이블·PoE·스위치·NIC 절전 설정부터 점검하십시오. (시간 일치는 인과관계의 증명이 아닙니다.)",hits,"추정");
        else if(!arr(sdk,"events").empty()&&offset.is_null())b.add("CORR-UNKNOWN","unknown","correlation","SDK 로그 시간대가 지정되지 않아 이벤트와의 상관 분석 불가","SDK 로그 UTC 오프셋 미지정","--log-utc-offset 지정",
            "analyze 실행 시 --log-utc-offset +09:00 처럼 SDK 로그의 시간대를 지정하면 링크 이력과 비교할 수 있습니다.",Json::array({"sdk-summary.json"}));
    }
    if(timeline_truncated)timeline.erase(timeline.begin(),timeline.end()-static_cast<std::ptrdiff_t>(kTimelineLimit));
    // Coverage
    {
        Json missing=Json::array();
        for(const auto& m:arr(s,"modules")){auto status=string_value(m,"status");if(status!="ok"&&status!="empty")missing.push_back(field(m,"task_id")+": "+status);}
        if(!missing.empty())b.add("COV-MODULES","unknown","coverage","일부 수집 모듈 누락·부분 수집 ("+std::to_string(missing.size())+"개)","수집 실패·시간 초과·권한 부족","모든 모듈 ok",
            "이 모듈과 관련된 판정은 '판단 불가'입니다. 관리자 권한으로 다시 수집하거나 부록의 수집 범위를 확인하십시오.",missing);
    }
    // Software inventory (context only)
    Json software=Json::array();
    for(const auto& a:arr(module(s,"software"),"software")){auto t=lower(field(a,"display_name")+" "+field(a,"publisher"));
        for(auto k:kCameraSoftware)if(t.find(k)!=std::string::npos){if(software.size()<64)software.push_back({{"name",a.value("display_name",Json(nullptr))},{"version",a.value("display_version",Json(nullptr))},{"publisher",a.value("publisher",Json(nullptr))}});break;}}
    auto& findings=b.findings;
    std::stable_sort(findings.begin(),findings.end(),[](const Json& a,const Json& b){return rank(a["severity"].get<std::string>())>rank(b["severity"].get<std::string>());});
    Json counts={{"critical",0},{"warning",0},{"unknown",0},{"info",0}};std::string overall="ok";
    for(const auto& f:findings){auto sev=f["severity"].get<std::string>();counts[sev]=counts[sev].get<int>()+1;if(rank(sev)>rank(overall))overall=sev;}
    for(auto& f:findings)if(f["nic"].is_number()){auto index=f["nic"].get<unsigned>();for(const auto& n:nics)if(n.value("if_index",0U)==index)f["nic_name"]=n.value("friendly_name","");}
    std::string headline=overall=="critical"?"카메라 운용에 직접 영향을 줄 수 있는 문제가 있습니다.":overall=="warning"?"권장 설정과 다른 항목이 있습니다. 성능·안정성 저하 원인이 될 수 있습니다.":
        overall=="unknown"?"치명적 문제는 확인되지 않았으나 판단할 수 없는 항목이 있습니다.":"확인 가능한 범위에서 GigE Vision 권장 구성과 일치합니다.";
    return {{"schema_version",1},{"overall",overall},{"headline",headline},{"counts",counts},{"nic_roles",roles},{"camera_nic_count",camera.size()},{"hidden_nic_count",hidden},
        {"checklists",checklists},{"findings",findings},{"cameras",cameras},{"sessions",sessions},{"timeline",timeline},{"timeline_truncated",timeline_truncated},
        {"sdk_versions",arr(sdk,"versions")},{"camera_software",software},{"sdk_utc_offset",offset},
        {"note","규칙 기반 판정입니다. '확인'은 수집값에서 직접 관찰한 사실, '추정'은 시간·이름 일치에 근거한 추론입니다. 판단 불가 항목은 비활성으로 해석하지 않습니다."}};
}

namespace {
struct Masker {
    std::string computer;std::vector<std::pair<std::string,std::string>> serials;
    std::regex user{R"(([A-Za-z]:[\\/]+Users[\\/]+)[^\\/\s"]+)",std::regex::icase};
    std::regex mac{R"(\b([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}\b)"};
    std::regex ipv4{R"(\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b)"};
    std::string text(std::string s) const {
        if(!computer.empty())for(size_t at;(at=lower(s).find(lower(computer)))!=std::string::npos;)s.replace(at,computer.size(),"<PC>");
        for(const auto& [serial,alias]:serials)for(size_t at;(at=s.find(serial))!=std::string::npos;)s.replace(at,serial.size(),alias);
        s=std::regex_replace(s,user,"$1<user>");s=std::regex_replace(s,mac,"$1:xx:xx:xx");
        std::string out;auto begin=std::sregex_iterator(s.begin(),s.end(),ipv4);size_t last=0;
        for(auto it=begin;it!=std::sregex_iterator();++it) {
            int a=std::stoi((*it)[1]),b=std::stoi((*it)[2]);bool local=a==10||a==127||(a==169&&b==254)||(a==172&&b>=16&&b<=31)||(a==192&&b==168)||a==0||a==255||a>=224;
            out+=s.substr(last,it->position()-last);out+=local?it->str():"<public-ip>";last=it->position()+it->length();
        }
        return out+s.substr(last);
    }
    void walk(Json& j) const {
        if(j.is_string())j=text(j.get<std::string>());
        else if(j.is_array()||j.is_object())for(auto& v:j)walk(v);
    }
};
Json clip(Json v,size_t n){if(v.is_array()&&v.size()>n)v.erase(v.begin()+static_cast<std::ptrdiff_t>(n),v.end());return v;}
std::string cut(std::string s,size_t n){if(s.size()<=n)return s;while(n&&(static_cast<unsigned char>(s[n])&0xc0)==0x80)--n;s.resize(n);return s+" …";}
} // namespace

Json llm_context(const Json& r) {
    const auto& s=obj(r,"snapshot");const auto& sys=module(s,"system");const auto& d=obj(r,"diagnosis");const auto& sdk=obj(r,"sdk");
    Json diagnosis=d;diagnosis["timeline"]=clip(arr(d,"timeline"),300);diagnosis["sessions"]=clip(arr(d,"sessions"),80);
    for(auto& role:diagnosis["nic_roles"])role.erase("description");
    Json sdk_errors=Json::array();
    for(const auto& e:arr(sdk,"events")){auto level=string_value(e,"level");if(level!="ERROR"&&level!="WARN"&&level!="WARNING")continue;if(sdk_errors.size()>=80)break;
        sdk_errors.push_back({{"time",e.value("original_timestamp","")},{"time_utc",e.value("time_utc",Json(nullptr))},{"level",level},{"family",obj(e,"fields").value("family","")},{"message",cut(string_value(e,"message"),400)},{"ref",field(e,"source_file")+":"+field(e,"source_line")}});}
    Json groups=Json::array();
    for(const auto& g:arr(r,"event_groups")){if(groups.size()>=40)break;groups.push_back({{"provider",g["provider"]},{"id",g["id"]},{"level",g["level"]},{"count",g["count"]},{"oldest",g["oldest"]},{"newest",g["newest"]},{"message",cut(field(obj(g,"example"),"message"),300)}});}
    Json incidents=Json::array();
    for(const auto& a:arr(r,"app_incidents")){if(incidents.size()>=30)break;incidents.push_back({{"time_utc",a["time_utc"]},{"provider",a["provider"]},{"event_id",a["event_id"]},{"app",a["app_name"]},{"app_version",a["app_version"]},{"module",a["module_name"]},{"exception_code",a["exception_code"]}});}
    Json links=Json::array();for(const auto& l:arr(r,"links"))links.push_back({{"nic",l["name"]},{"down",l["down"]},{"up",l["up"]},{"median_down_s",l["median_s"]}});
    std::string os=field(obj(sys,"os"),"ProductName");const auto& wmi=arr(obj(sys,"operating_system_wmi"),"rows");if(!wmi.empty())os=field(wmi[0],"Caption");
    Json context={{"schema_version",1},
        {"purpose","GigE Vision camera PC diagnostics. Rule findings are authoritative observations; propose root-cause hypotheses only from this data and cite finding ids."},
        {"system",{{"os",os},{"build",field(obj(sys,"os"),"CurrentBuildNumber")},{"collected_utc",field(s,"started_at_utc")},{"history_from_utc",field(obj(s,"inputs"),"from_utc")},{"history_to_utc",field(obj(s,"inputs"),"to_utc")}}},
        {"diagnosis",diagnosis},{"links",links},{"sdk_error_samples",sdk_errors},{"event_groups",groups},{"app_incidents",incidents},{"notices",clip(arr(r,"notices"),30)},
        {"masking","Computer name, user profile names, camera serial numbers, MAC address lower 3 bytes and public IPv4 addresses are masked. Private IPv4 addresses are kept for subnet analysis."}};
    Masker m;m.computer=string_value(sys,"computer_name");size_t n=0;
    for(const auto& c:arr(d,"cameras")){auto serial=string_value(c,"serial_number");if(serial.size()>=3)m.serials.push_back({serial,"<serial-"+std::to_string(++n)+">"});}
    m.walk(context);
    while(json_text(context).size()>400*1024&&context["diagnosis"]["timeline"].size()>20){auto& t=context["diagnosis"]["timeline"];t.erase(t.begin()+static_cast<std::ptrdiff_t>(t.size()/2),t.end());}
    return context;
}

Json validate_ai_review(const Json& v) {
    need(v.is_object()&&v.value("schema_version",0)==1,"ai-review: schema_version 1 object required.");
    auto text=[&](const Json& o,const char* key,size_t limit,bool required)->Json{
        auto it=o.find(key);if(it==o.end()||it->is_null()){need(!required,std::string("ai-review: missing ")+key);return nullptr;}
        need(it->is_string()&&it->get<std::string>().size()<=limit,std::string("ai-review: invalid ")+key);return *it;};
    auto ids=[&](const Json& o){Json out=Json::array();for(const auto& id:arr(o,"finding_ids")){need(id.is_string()&&id.get<std::string>().size()<=64,"ai-review: invalid finding id");out.push_back(id);}need(out.size()<=20,"ai-review: too many finding ids");return out;};
    auto list=[&](const char* key,size_t limit){const auto& a=arr(v,key);need(a.size()<=limit,std::string("ai-review: too many ")+key);return std::cref(a);};
    Json out={{"schema_version",1},{"summary",text(v,"summary",8000,true)},{"model",text(v,"model",100,false)},{"generated_at",text(v,"generated_at",64,false)},
        {"hypotheses",Json::array()},{"actions",Json::array()},{"additional_checks",Json::array()},{"caveats",Json::array()}};
    for(const auto& h:list("hypotheses",20).get()){need(h.is_object(),"ai-review: hypothesis must be an object.");auto c=h.value("confidence","");
        need(c=="high"||c=="medium"||c=="low","ai-review: confidence must be high/medium/low.");
        out["hypotheses"].push_back({{"title",text(h,"title",500,true)},{"confidence",c},{"reasoning",text(h,"reasoning",4000,true)},{"finding_ids",ids(h)}});}
    for(const auto& a:list("actions",30).get()){need(a.is_object(),"ai-review: action must be an object.");auto p=a.value("priority",0);need(p>=1&&p<=99,"ai-review: priority must be 1..99.");
        out["actions"].push_back({{"priority",p},{"action",text(a,"action",2000,true)},{"finding_ids",ids(a)}});}
    for(auto key:{"additional_checks","caveats"})for(const auto& t:list(key,30).get()){need(t.is_string()&&t.get<std::string>().size()<=1000,std::string("ai-review: invalid ")+key);out[key].push_back(t);}
    return out;
}
} // namespace fnc
