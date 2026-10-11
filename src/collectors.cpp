#include "common.hpp"
#include "sdk_logs.hpp"
#include <setupapi.h>
#include <netfw.h>
#include <memory>
#include <sstream>
#include <algorithm>
#include <map>

namespace fnc {
namespace {
struct RegKey {
    HKEY key=nullptr;
    ~RegKey(){if(key) RegCloseKey(key);}
};
Json reg_values(HKEY parent,const std::wstring& path,REGSAM view=0) {
    auto r=result("registry:"+utf8(path)); RegKey k;
    LSTATUS rc=RegOpenKeyExW(parent,path.c_str(),0,KEY_READ|view,&k.key);
    if(rc!=ERROR_SUCCESS) { issue(r,rc==ERROR_ACCESS_DENIED?"access_denied":rc==ERROR_FILE_NOT_FOUND?"missing":"error",win_error(rc),rc); return r; }
    r["values"]=Json::array();
    for(DWORD i=0;i<2048;++i) {
        std::vector<wchar_t> name(16384); std::vector<BYTE> data(65536); DWORD nn=DWORD(name.size()),dn=DWORD(data.size()),type=0;
        rc=RegEnumValueW(k.key,i,name.data(),&nn,nullptr,&type,data.data(),&dn);
        if(rc==ERROR_NO_MORE_ITEMS) break;
        if(rc!=ERROR_SUCCESS) { issue(r,"partial",win_error(rc),rc); continue; }
        Json value;
        if(type==REG_SZ || type==REG_EXPAND_SZ || type==REG_MULTI_SZ) {
            // Do not expand environment variables or resolve any registry paths.
            size_t n=dn/sizeof(wchar_t); std::wstring text(n,L'\0'); if(n) memcpy(text.data(),data.data(),n*sizeof(wchar_t));
            if(type==REG_MULTI_SZ) {
                value=Json::array(); size_t pos=0;
                while(pos<n && text[pos]) { size_t end=text.find(L'\0',pos); if(end==std::wstring::npos) end=n; value.push_back(utf8(std::wstring_view(text).substr(pos,end-pos))); pos=end+1; }
            } else { while(!text.empty() && text.back()==L'\0') text.pop_back(); value=utf8(text); }
        } else if(type==REG_DWORD && dn==4) { DWORD v; memcpy(&v,data.data(),4); value=v; }
        else if(type==REG_QWORD && dn==8) { ULONGLONG v; memcpy(&v,data.data(),8); value=v; }
        else { std::string hex; static const char* digits="0123456789abcdef"; for(DWORD j=0;j<dn;++j){hex+=digits[data[j]>>4];hex+=digits[data[j]&15];} value=hex; }
        r["values"].push_back({{"name",utf8(std::wstring_view(name.data(),nn))},{"registry_type",type},{"raw_value",value}});
        if(i==2047) issue(r,"partial","Registry value limit reached.");
    }
    return r;
}
std::vector<std::wstring> subkeys(HKEY parent,const std::wstring& path,REGSAM view=0) {
    RegKey k; LSTATUS rc=RegOpenKeyExW(parent,path.c_str(),0,KEY_READ|view,&k.key);
    if(rc!=ERROR_SUCCESS) fail_win("Open registry for enumeration",rc);
    std::vector<std::wstring> names;
    for(DWORD i=0;i<10000;++i) { wchar_t name[256]; DWORD n=256; rc=RegEnumKeyExW(k.key,i,name,&n,nullptr,nullptr,nullptr,nullptr);
        if(rc==ERROR_NO_MORE_ITEMS) return names; if(rc!=ERROR_SUCCESS) fail_win("Enumerate registry",rc); names.emplace_back(name,n); }
    throw std::runtime_error("Registry subkey limit exceeded.");
}
Json reg_scalar(const Json& r,std::string_view name) {
    if(r.contains("values")) for(const auto& v:r["values"]) if(lower(v["name"].get<std::string>())==lower(std::string(name))) return v["raw_value"];
    return nullptr;
}
Json variant_json(const VARIANT& v,unsigned depth=0) {
    if(depth>4) return Json{{"unavailable","Nested WMI value depth limit"}};
    if(v.vt&VT_ARRAY) {
        if(!v.parray || SafeArrayGetDim(v.parray)!=1) return Json{{"unavailable","Non-vector WMI array"}};
        LONG lo=0,hi=-1; check_hr(SafeArrayGetLBound(v.parray,1,&lo),"Array lower bound"); check_hr(SafeArrayGetUBound(v.parray,1,&hi),"Array upper bound");
        if(static_cast<LONGLONG>(hi)-lo>65535) return Json{{"unavailable","WMI array size limit"}};
        Json a=Json::array();
        for(LONG i=lo;i<=hi;++i) {
            VARIANT item; VariantInit(&item); item.vt=v.vt&VT_TYPEMASK;
            HRESULT hr=SafeArrayGetElement(v.parray,&i,item.vt==VT_VARIANT?static_cast<void*>(&item):static_cast<void*>(&item.lVal));
            if(FAILED(hr)) { VariantClear(&item); check_hr(hr,"Array element"); }
            try { a.push_back(variant_json(item,depth+1)); } catch(...) { VariantClear(&item); throw; }
            VariantClear(&item);
        }
        return a;
    }
    switch(v.vt) {
    case VT_EMPTY: case VT_NULL: return nullptr;
    case VT_BSTR: return v.bstrVal?utf8(std::wstring_view(v.bstrVal,SysStringLen(v.bstrVal))):std::string();
    case VT_BOOL: return v.boolVal!=VARIANT_FALSE;
    case VT_I1: return v.cVal; case VT_UI1: return v.bVal;
    case VT_I2: return v.iVal; case VT_UI2: return v.uiVal;
    case VT_I4: case VT_INT: return v.lVal; case VT_UI4: case VT_UINT: return v.ulVal;
    case VT_I8: return v.llVal; case VT_UI8: return v.ullVal;
    case VT_R4: return v.fltVal; case VT_R8: return v.dblVal;
    default: return Json{{"unavailable_variant_type",v.vt}};
    }
}
std::string address(const SOCKADDR* a) {
    if(!a) return {}; wchar_t buf[INET6_ADDRSTRLEN]{};
    if(a->sa_family==AF_INET) { auto s=reinterpret_cast<const SOCKADDR_IN*>(a); if(!InetNtopW(AF_INET,const_cast<IN_ADDR*>(&s->sin_addr),buf,INET6_ADDRSTRLEN)) fail_win("Format IPv4"); }
    else if(a->sa_family==AF_INET6) { auto s=reinterpret_cast<const SOCKADDR_IN6*>(a); if(!InetNtopW(AF_INET6,const_cast<IN6_ADDR*>(&s->sin6_addr),buf,INET6_ADDRSTRLEN)) fail_win("Format IPv6"); auto out=utf8(buf); if(s->sin6_scope_id) out+="%"+std::to_string(s->sin6_scope_id); return out; }
    return utf8(buf);
}
std::string address(const SOCKADDR_INET& a) {return address(reinterpret_cast<const SOCKADDR*>(&a));}
template<class T> using MibPtr=std::unique_ptr<T,decltype(&FreeMibTable)>;
Json network() {
    auto r=result("Windows IP Helper (local tables)");
    r["interfaces"]=Json::array(); r["adapters"]=Json::array(); r["unicast_addresses"]=Json::array(); r["routes"]=Json::array(); r["neighbors"]=Json::array();
    PMIB_IF_TABLE2 table=nullptr; auto rc=GetIfTable2(&table); MibPtr<MIB_IF_TABLE2> owner(table,FreeMibTable);
    if(rc==NO_ERROR) for(ULONG i=0;i<table->NumEntries;++i) {
        const auto& a=table->Table[i]; wchar_t g[40]{}; StringFromGUID2(a.InterfaceGuid,g,40);
        r["interfaces"].push_back({{"interface_guid",utf8(g)},{"if_index",a.InterfaceIndex},{"luid",a.InterfaceLuid.Value},
            {"alias",utf8(a.Alias)},{"description",utf8(a.Description)},{"mac",mac_text(a.PhysicalAddress,a.PhysicalAddressLength)},
            {"permanent_mac",mac_text(a.PermanentPhysicalAddress,a.PhysicalAddressLength)},{"mtu",a.Mtu},{"type",a.Type},
            {"physical_medium_type",a.PhysicalMediumType},{"admin_status",a.AdminStatus},{"oper_status",a.OperStatus},{"media_connect_state",a.MediaConnectState},
            {"hardware_interface",a.InterfaceAndOperStatusFlags.HardwareInterface!=0},
            {"filter_interface",a.InterfaceAndOperStatusFlags.FilterInterface!=0},
            {"connector_present",a.InterfaceAndOperStatusFlags.ConnectorPresent!=0},
            {"tx_link_bps",a.TransmitLinkSpeed},{"rx_link_bps",a.ReceiveLinkSpeed},
            {"counters",{{"in_octets",a.InOctets},{"out_octets",a.OutOctets},{"in_errors",a.InErrors},{"out_errors",a.OutErrors},
                {"in_discards",a.InDiscards},{"out_discards",a.OutDiscards}}}});
    } else issue(r,"partial","GetIfTable2: "+win_error(rc),rc);
    ULONG size=15000; std::vector<BYTE> buf(size);
    for(int tries=0;tries<3;++tries) {
        rc=GetAdaptersAddresses(AF_UNSPEC,GAA_FLAG_INCLUDE_ALL_INTERFACES|GAA_FLAG_INCLUDE_GATEWAYS|GAA_FLAG_INCLUDE_PREFIX,nullptr,
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()),&size);
        if(rc!=ERROR_BUFFER_OVERFLOW) break;
        if(size>4*1024*1024) throw std::runtime_error("Adapter table size limit exceeded."); buf.resize(size);
    }
    std::map<ULONGLONG,std::pair<bool,bool>> kinds;
    for(const auto& item:r["interfaces"])kinds[item["luid"].get<ULONGLONG>()]={item["filter_interface"].get<bool>(),item["hardware_interface"].get<bool>()};
    if(rc==NO_ERROR) for(auto* a=reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());a;a=a->Next) {
        Json ips=Json::array(),dns=Json::array(),gws=Json::array();
        for(auto* u=a->FirstUnicastAddress;u;u=u->Next) ips.push_back({{"address",address(u->Address.lpSockaddr)},
            {"prefix_length",u->OnLinkPrefixLength},{"prefix_origin",u->PrefixOrigin},{"suffix_origin",u->SuffixOrigin},
            {"dad_state",u->DadState},{"valid_lifetime_s",u->ValidLifetime},{"preferred_lifetime_s",u->PreferredLifetime}});
        for(auto* d=a->FirstDnsServerAddress;d;d=d->Next) dns.push_back(address(d->Address.lpSockaddr));
        for(auto* g=a->FirstGatewayAddress;g;g=g->Next) gws.push_back(address(g->Address.lpSockaddr));
        r["adapters"].push_back({{"adapter_name",a->AdapterName?a->AdapterName:""},{"if_index",a->IfIndex},{"ipv6_if_index",a->Ipv6IfIndex},
            {"luid",a->Luid.Value},{"filter_interface",kinds.contains(a->Luid.Value)?Json(kinds[a->Luid.Value].first):Json(nullptr)},
            {"hardware_interface",kinds.contains(a->Luid.Value)?Json(kinds[a->Luid.Value].second):Json(nullptr)},
            {"friendly_name",utf8(a->FriendlyName?a->FriendlyName:L"")},
            {"description",utf8(a->Description?a->Description:L"")},{"dns_suffix",utf8(a->DnsSuffix?a->DnsSuffix:L"")},
            {"mac",mac_text(a->PhysicalAddress,a->PhysicalAddressLength)},{"dhcp_v4_enabled",a->Dhcpv4Enabled!=0},
            {"ipv6_managed_address_configuration_supported",a->Ipv6ManagedAddressConfigurationSupported!=0},
            {"ipv6_other_stateful_config",a->Ipv6OtherStatefulConfig!=0},{"dhcp_v4_server",address(a->Dhcpv4Server.lpSockaddr)},
            {"dhcp_v6_server",address(a->Dhcpv6Server.lpSockaddr)},{"ipv4_metric",a->Ipv4Metric},{"ipv6_metric",a->Ipv6Metric},
            {"mtu",a->Mtu},{"addresses",ips},{"dns_servers",dns},{"gateways",gws}});
    } else if(rc!=ERROR_NO_DATA) issue(r,"partial","GetAdaptersAddresses: "+win_error(rc),rc);
    PMIB_UNICASTIPADDRESS_TABLE ut=nullptr; rc=GetUnicastIpAddressTable(AF_UNSPEC,&ut); MibPtr<MIB_UNICASTIPADDRESS_TABLE> uowner(ut,FreeMibTable);
    if(rc==NO_ERROR) for(ULONG i=0;i<ut->NumEntries;++i) { const auto& a=ut->Table[i];
        r["unicast_addresses"].push_back({{"if_index",a.InterfaceIndex},{"luid",a.InterfaceLuid.Value},{"address",address(a.Address)},
            {"prefix_length",a.OnLinkPrefixLength},{"prefix_origin",a.PrefixOrigin},{"suffix_origin",a.SuffixOrigin},
            {"dad_state",a.DadState},{"valid_lifetime_s",a.ValidLifetime},{"preferred_lifetime_s",a.PreferredLifetime}});
    } else issue(r,"partial","GetUnicastIpAddressTable: "+win_error(rc),rc);
    PMIB_IPFORWARD_TABLE2 rt=nullptr; rc=GetIpForwardTable2(AF_UNSPEC,&rt); MibPtr<MIB_IPFORWARD_TABLE2> rowner(rt,FreeMibTable);
    if(rc==NO_ERROR) for(ULONG i=0;i<rt->NumEntries;++i) { const auto& a=rt->Table[i];
        MIB_IPINTERFACE_ROW iface{}; InitializeIpInterfaceEntry(&iface); iface.Family=a.DestinationPrefix.Prefix.si_family; iface.InterfaceLuid=a.InterfaceLuid;
        auto ir=GetIpInterfaceEntry(&iface);
        r["routes"].push_back({{"if_index",a.InterfaceIndex},{"luid",a.InterfaceLuid.Value},{"destination",address(a.DestinationPrefix.Prefix)},
            {"prefix_length",a.DestinationPrefix.PrefixLength},{"next_hop",address(a.NextHop)},{"route_metric",a.Metric},
            {"interface_metric",ir==NO_ERROR?Json(iface.Metric):Json(nullptr)},{"protocol",a.Protocol},{"origin",a.Origin},
            {"age_s",a.Age},{"valid_lifetime_s",a.ValidLifetime},{"immortal",a.Immortal!=0}});
    } else issue(r,"partial","GetIpForwardTable2: "+win_error(rc),rc);
    PMIB_IPNET_TABLE2 nt=nullptr; rc=GetIpNetTable2(AF_UNSPEC,&nt); MibPtr<MIB_IPNET_TABLE2> nowner(nt,FreeMibTable);
    if(rc==NO_ERROR) for(ULONG i=0;i<nt->NumEntries;++i) { const auto& a=nt->Table[i];
        r["neighbors"].push_back({{"if_index",a.InterfaceIndex},{"luid",a.InterfaceLuid.Value},{"address",address(a.Address)},
            {"mac",mac_text(a.PhysicalAddress,a.PhysicalAddressLength)},{"state",a.State},{"is_router",a.IsRouter!=0},
            {"is_unreachable",a.IsUnreachable!=0},{"cache_snapshot_only",true}});
    } else if(rc!=ERROR_NOT_FOUND && rc!=ERROR_NO_DATA) issue(r,"partial","GetIpNetTable2: "+win_error(rc),rc);
    r["routing_compartment_id"]=GetCurrentThreadCompartmentId();
    r["coverage_note"]="IP/route/neighbor tables are for the current routing compartment. Hidden and non-IP NICs are additionally covered by WMI/SetupAPI. Counters are cumulative, not measured camera packet loss.";
    return r;
}
Json system_information() {
    auto r=result("Local Windows system information");
    wchar_t name[256]{}; DWORD n=256; if(!GetComputerNameW(name,&n)) fail_win("GetComputerNameW"); r["computer_name"]=utf8(std::wstring_view(name,n));
    r["os_registry"]=reg_values(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
    // Only expose selected OS values; avoid unrelated registration/owner information.
    Json os=Json::object(); for(auto field:{"ProductName","DisplayVersion","CurrentBuildNumber","UBR","EditionID","InstallationType"}) os[field]=reg_scalar(r["os_registry"],field);
    auto osStatus=r["os_registry"]["status"]; r.erase("os_registry"); r["os"]=os;
    if(osStatus!="ok") issue(r,"partial","Windows version registry values could not be read.");
    DYNAMIC_TIME_ZONE_INFORMATION tz{}; DWORD tzstate=GetDynamicTimeZoneInformation(&tz);
    if(tzstate==TIME_ZONE_ID_INVALID) issue(r,"partial","Time zone query failed.",GetLastError());
    else r["time_zone"]={{"key_name",utf8(tz.TimeZoneKeyName)},{"standard_name",utf8(tz.StandardName)},
        {"bias_minutes",tz.Bias},{"standard_bias_minutes",tz.StandardBias},{"daylight_bias_minutes",tz.DaylightBias},
        {"dynamic_daylight_disabled",tz.DynamicDaylightTimeDisabled!=0},{"state",tzstate}};
    r["local_time"]=local_time(now_ticks()); r["uptime_ms"]=GetTickCount64();
    r["operating_system_wmi"]=query_wmi(L"ROOT\\CIMV2",L"Win32_OperatingSystem");
    MEMORYSTATUSEX memory{};memory.dwLength=sizeof(memory);
    r["physical_memory"]={{"observed_at_utc",utc_now()},{"total_bytes",nullptr},{"available_bytes",nullptr},{"load_percent",nullptr}};
    if(GlobalMemoryStatusEx(&memory)){r["physical_memory"]["total_bytes"]=memory.ullTotalPhys;r["physical_memory"]["available_bytes"]=memory.ullAvailPhys;r["physical_memory"]["load_percent"]=memory.dwMemoryLoad;}
    else issue(r,"partial","Physical memory status unavailable.",GetLastError());
    r["memory_modules_wmi"]=query_wmi(L"ROOT\\CIMV2",L"Win32_PhysicalMemory");
    r["memory_modules_observed_at_utc"]=utc_now();
    if(r["memory_modules_wmi"]["status"]!="ok"&&r["memory_modules_wmi"]["status"]!="empty")issue(r,"partial","Physical memory hardware query incomplete.");
    if(r["operating_system_wmi"]["status"]!="ok") issue(r,"partial","Boot time / operating system WMI query incomplete.");
    r["admin_elevated"]=elevated(); return r;
}
Json devices() {
    auto r=result("SetupAPI present and non-present network device inventory"); r["devices"]=Json::array();
    const GUID net={0x4d36e972,0xe325,0x11ce,{0xbf,0xc1,0x08,0x00,0x2b,0xe1,0x03,0x18}};
    HDEVINFO set=SetupDiGetClassDevsW(&net,nullptr,nullptr,0); if(set==INVALID_HANDLE_VALUE) fail_win("SetupDiGetClassDevsW");
    try {
        for(DWORD i=0;i<4096;++i) {
            SP_DEVINFO_DATA dev{}; dev.cbSize=sizeof(dev);
            if(!SetupDiEnumDeviceInfo(set,i,&dev)) { auto e=GetLastError(); if(e==ERROR_NO_MORE_ITEMS) break; fail_win("SetupDiEnumDeviceInfo",e); }
            wchar_t id[4096]{}; if(!SetupDiGetDeviceInstanceIdW(set,&dev,id,4096,nullptr)) {issue(r,"partial","Device ID unavailable.",GetLastError());continue;}
            Json item{{"device_id",utf8(id)}};
            const std::pair<const char*,DWORD> props[]={{"description",SPDRP_DEVICEDESC},{"friendly_name",SPDRP_FRIENDLYNAME},{"manufacturer",SPDRP_MFG},
                {"service",SPDRP_SERVICE},{"driver_key",SPDRP_DRIVER},{"hardware_ids",SPDRP_HARDWAREID}};
            for(const auto& [key,prop]:props) {
                DWORD type=0,required=0; std::vector<BYTE> buf(65536);
                if(!SetupDiGetDeviceRegistryPropertyW(set,&dev,prop,&type,buf.data(),DWORD(buf.size()),&required)) { item[key]=nullptr; continue; }
                std::wstring text(required/2,L'\0'); if(required) memcpy(text.data(),buf.data(),required);
                if(type==REG_MULTI_SZ) {Json a=Json::array();size_t p=0;while(p<text.size()&&text[p]) {auto e=text.find(L'\0',p);if(e==std::wstring::npos)e=text.size();a.push_back(utf8(std::wstring_view(text).substr(p,e-p)));p=e+1;}item[key]=a;}
                else {while(!text.empty()&&text.back()==L'\0')text.pop_back();item[key]=utf8(text);}
            }
            r["devices"].push_back(item); if(i==4095) issue(r,"partial","Device count limit reached.");
        }
        SetupDiDestroyDeviceInfoList(set); return r;
    } catch(...) {SetupDiDestroyDeviceInfoList(set);throw;}
}
Json registry_network() {
    auto r=result("Read-only NIC/TCP-IP registry values"); r["keys"]=Json::array();
    const std::wstring base=L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}";
    for(const auto& sub:subkeys(HKEY_LOCAL_MACHINE,base)) if(sub.size()==4 && std::all_of(sub.begin(),sub.end(),[](wchar_t c){return c>=L'0'&&c<=L'9';})) r["keys"].push_back(reg_values(HKEY_LOCAL_MACHINE,base+L"\\"+sub));
    const std::wstring interfaces=L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces";
    for(const auto& sub:subkeys(HKEY_LOCAL_MACHINE,interfaces)) r["keys"].push_back(reg_values(HKEY_LOCAL_MACHINE,interfaces+L"\\"+sub));
    r["keys"].push_back(reg_values(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\PersistentRoutes"));
    for(const auto& k:r["keys"]) if(k["status"]!="ok" && k["status"]!="missing") issue(r,"partial",k["source"].get<std::string>()+": unavailable values");
    return r;
}
Json wmi_group(std::string_view label,const std::vector<std::wstring>& classes,std::wstring_view ns=L"ROOT\\StandardCimv2") {
    auto r=result(label); r["queries"]=Json::array();
    for(const auto& c:classes) { auto q=query_wmi(ns,c,c==L"Win32_PnPSignedDriver"?L"DeviceClass = 'NET'":L"");
        if(q["status"]!="ok" && q["status"]!="empty") issue(r,"partial",q["source"].get<std::string>()+": "+q["status"].get<std::string>());
        r["queries"].push_back(std::move(q)); }
    return r;
}
Json installed_tools() {
    auto r=result("Uninstall registry (machine x64/x86 and current user only)"); r["software"]=Json::array();
    const std::wstring base=L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    const char* words[]={"camera","gige","genicam","pylon","basler","arena","lucid","baumer","vimba","allied vision","spinnaker","flir","teledyne","dalsa","jai ","hikrobot","ebus","pleora","mvimpact","imperx","stemmer","sapera","ids imaging"};
    for(auto [hive,view]:std::vector<std::pair<HKEY,REGSAM>>{{HKEY_LOCAL_MACHINE,KEY_WOW64_64KEY},{HKEY_LOCAL_MACHINE,KEY_WOW64_32KEY},{HKEY_CURRENT_USER,KEY_WOW64_64KEY},{HKEY_CURRENT_USER,KEY_WOW64_32KEY}}) {
        try {
            for(const auto& sub:subkeys(hive,base,view)) {auto v=reg_values(hive,base+L"\\"+sub,view);auto name=reg_scalar(v,"DisplayName");
                if(!name.is_string()) continue; auto text=lower(name.get<std::string>());auto publisher=reg_scalar(v,"Publisher");if(publisher.is_string())text+=" "+lower(publisher.get<std::string>());bool match=text.find("huaray")!=std::string::npos||text.find("mvsdk")!=std::string::npos;for(auto w:words) if(text.find(w)!=std::string::npos)match=true;
                if(!match) continue;
                r["software"].push_back({{"display_name",name},{"display_version",reg_scalar(v,"DisplayVersion")},{"publisher",reg_scalar(v,"Publisher")},
                    {"install_date_reported",reg_scalar(v,"InstallDate")},{"registry_key",utf8(base+L"\\"+sub)},
                    {"scope",hive==HKEY_LOCAL_MACHINE?"machine":"current_user"},{"view",view==KEY_WOW64_64KEY?64:32}});
            }
        } catch(const std::exception& e) {issue(r,"partial",e.what());}
    }
    r["coverage_note"]="DisplayName/Publisher registry inventory only. No MSI provider calls, process opening, software launch or SDK loading. Other users' private installations are not enumerated.";
    return r;
}
Json firewall() {
    auto r=result("INetFwPolicy2 local firewall policy"); ComPtr<INetFwPolicy2> policy;
    check_hr(CoCreateInstance(__uuidof(NetFwPolicy2),nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&policy)),"Local firewall policy");
    long current=0;check_hr(policy->get_CurrentProfileTypes(&current),"Current firewall profiles");r["current_profile_types"]=current;r["profiles"]=Json::array();
    for(auto type:{NET_FW_PROFILE2_DOMAIN,NET_FW_PROFILE2_PRIVATE,NET_FW_PROFILE2_PUBLIC}) {
        Json p{{"type",static_cast<int>(type)}};VARIANT_BOOL enabled=VARIANT_FALSE,block=VARIANT_FALSE,notifications=VARIANT_FALSE;NET_FW_ACTION inbound{},outbound{};
        auto get=[&](HRESULT h,const char* name,Json val){if(SUCCEEDED(h))p[name]=val;else {p[name]=nullptr;issue(r,"partial",std::string("Firewall profile: ")+name,static_cast<DWORD>(h));}};
        auto h=policy->get_FirewallEnabled(type,&enabled);get(h,"enabled",enabled!=VARIANT_FALSE);
        h=policy->get_BlockAllInboundTraffic(type,&block);get(h,"block_all_inbound",block!=VARIANT_FALSE);
        h=policy->get_NotificationsDisabled(type,&notifications);get(h,"notifications_disabled",notifications!=VARIANT_FALSE);
        h=policy->get_DefaultInboundAction(type,&inbound);get(h,"default_inbound_action",static_cast<int>(inbound));
        h=policy->get_DefaultOutboundAction(type,&outbound);get(h,"default_outbound_action",static_cast<int>(outbound));r["profiles"].push_back(p);
    }
    ComPtr<INetFwRules> rules;check_hr(policy->get_Rules(&rules),"Firewall rules");ComPtr<IUnknown> unknown;
    check_hr(rules->get__NewEnum(&unknown),"Enumerate firewall rules");ComPtr<IEnumVARIANT> iter;check_hr(unknown.As(&iter),"Firewall rule enumerator");
    r["rules"]=Json::array();
    for(size_t i=0;i<10000;++i) {
        VARIANT v;VariantInit(&v);ULONG n=0;auto h=iter->Next(1,&v,&n);if(h==S_FALSE||!n) {VariantClear(&v);break;} check_hr(h,"Next firewall rule");
        ComPtr<INetFwRule> rule; if(v.vt==VT_DISPATCH && v.pdispVal) h=v.pdispVal->QueryInterface(IID_PPV_ARGS(&rule)); else h=E_NOINTERFACE;
        VariantClear(&v);if(FAILED(h)){issue(r,"partial","Firewall rule interface unavailable",static_cast<DWORD>(h));continue;}
        Json item=Json::object();
        auto str=[&](const char* key,auto getter){BSTR b=nullptr;HRESULT hr=(rule.Get()->*getter)(&b);if(SUCCEEDED(hr))item[key]=b?utf8(std::wstring_view(b,SysStringLen(b))):"";else {item[key]=nullptr;issue(r,"partial",std::string("Firewall rule property unavailable: ")+key,static_cast<DWORD>(hr));}if(b)SysFreeString(b);};
        str("name",&INetFwRule::get_Name);str("description",&INetFwRule::get_Description);str("application_name",&INetFwRule::get_ApplicationName);
        str("service_name",&INetFwRule::get_ServiceName);str("local_ports",&INetFwRule::get_LocalPorts);str("remote_ports",&INetFwRule::get_RemotePorts);
        str("local_addresses",&INetFwRule::get_LocalAddresses);str("remote_addresses",&INetFwRule::get_RemoteAddresses);str("interface_types",&INetFwRule::get_InterfaceTypes);
        long profiles=0,protocol=0;VARIANT_BOOL enabled=VARIANT_FALSE;NET_FW_RULE_DIRECTION direction{};NET_FW_ACTION action{};
        auto scalar=[&](HRESULT hr,const char* key,Json val){if(SUCCEEDED(hr))item[key]=val;else {item[key]=nullptr;issue(r,"partial",std::string("Firewall rule property unavailable: ")+key,static_cast<DWORD>(hr));}};
        h=rule->get_Profiles(&profiles);scalar(h,"profiles",profiles);h=rule->get_Protocol(&protocol);scalar(h,"protocol",protocol);
        h=rule->get_Enabled(&enabled);scalar(h,"enabled",enabled!=VARIANT_FALSE);h=rule->get_Direction(&direction);scalar(h,"direction",static_cast<int>(direction));
        h=rule->get_Action(&action);scalar(h,"action",static_cast<int>(action));
        item["enabled_for_current_profile"]=item["enabled"].is_boolean()&&item["enabled"].get<bool>()&&item["profiles"].is_number_integer()?Json((profiles&current)!=0):Json(nullptr);
        r["rules"].push_back(std::move(item));if(i==9999)issue(r,"partial","Firewall rule count limit reached.");
    }
    r["coverage_note"]="Enumerated Windows Firewall policy rules and current profile applicability. A rule's presence is not proof of packet acceptance: precedence, group policy merging, IPsec and third-party WFP filters are not fully evaluated.";
    return r;
}
} // namespace

Json history_nic_tokens(const Json& network) {
    Json tokens=Json::array();std::set<std::string> seen;
    if(!network.contains("adapters"))return tokens;
    // Interface tables can contain many NDIS filter pseudo-interfaces. Prioritize real
    // NIC identifiers so a filter-heavy customer machine cannot exhaust the limit first.
    for(bool filters:{false,true})for(const auto& a:network["adapters"]) {
        bool filter=a.contains("filter_interface")&&a["filter_interface"].is_boolean()&&a["filter_interface"].get<bool>();
        if(filter!=filters)continue;
        for(const char* key:{"adapter_name","description"})if(a.contains(key)&&a[key].is_string()) {
            auto text=a[key].get<std::string>();if(!text.empty()&&tokens.size()<128&&seen.insert(lower(text)).second)tokens.push_back(text);
        }
    }
    return tokens;
}

Json query_wmi(std::wstring_view ns,std::wstring_view class_name,std::wstring_view where) {
    // Fixed local read queries only. No remote server, class methods or arbitrary WQL input.
    auto r=result("WMI:"+utf8(ns)+":"+utf8(class_name));r["rows"]=Json::array();
    try {
        ComPtr<IWbemLocator> locator;check_hr(CoCreateInstance(CLSID_WbemLocator,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&locator)),"Local WMI locator");
        ComPtr<IWbemServices> services;BSTR namespace_b=SysAllocStringLen(ns.data(),UINT(ns.size()));
        auto hr=locator->ConnectServer(namespace_b,nullptr,nullptr,nullptr,WBEM_FLAG_CONNECT_USE_MAX_WAIT,nullptr,nullptr,&services);SysFreeString(namespace_b);
        check_hr(hr,"Connect local WMI namespace");
        check_hr(CoSetProxyBlanket(services.Get(),RPC_C_AUTHN_WINNT,RPC_C_AUTHZ_NONE,nullptr,RPC_C_AUTHN_LEVEL_CALL,RPC_C_IMP_LEVEL_IMPERSONATE,nullptr,EOAC_NONE),"WMI proxy blanket");
        auto query=(class_name==L"Win32_PhysicalMemory"?std::wstring(L"SELECT Manufacturer,PartNumber,Capacity,Speed,ConfiguredClockSpeed FROM "):std::wstring(L"SELECT * FROM "))+std::wstring(class_name);if(!where.empty()) query+=L" WHERE "+std::wstring(where);
        BSTR language=SysAllocString(L"WQL"),q=SysAllocString(query.c_str());ComPtr<IEnumWbemClassObject> iter;
        hr=services->ExecQuery(language,q,WBEM_FLAG_FORWARD_ONLY|WBEM_FLAG_RETURN_IMMEDIATELY,nullptr,&iter);SysFreeString(language);SysFreeString(q);
        if(hr==WBEM_E_INVALID_CLASS||hr==WBEM_E_INVALID_NAMESPACE) {issue(r,"unsupported",win_error(static_cast<DWORD>(hr)),static_cast<DWORD>(hr));return r;}
        check_hr(hr,"WMI read query");size_t bytes=0;
        for(size_t i=0;i<4096;++i) {
            ComPtr<IWbemClassObject> obj;ULONG n=0;hr=iter->Next(1000,1,&obj,&n);
            if(hr==WBEM_S_TIMEDOUT && !n) {--i;continue;} // Parent process enforces the 30-second deadline.
            check_hr(hr,"WMI next row");if(!n)break;
            Json row=Json::object(),types=Json::object();check_hr(obj->BeginEnumeration(WBEM_FLAG_NONSYSTEM_ONLY),"WMI property enumeration");
            while(true) {
                BSTR name=nullptr;VARIANT value;VariantInit(&value);CIMTYPE type=0;
                hr=obj->Next(0,&name,&value,&type,nullptr);
                if(hr==WBEM_S_NO_MORE_DATA) {if(name)SysFreeString(name);VariantClear(&value);break;}
                if(FAILED(hr)){if(name)SysFreeString(name);VariantClear(&value);check_hr(hr,"WMI property");}
                auto key=name?utf8(std::wstring_view(name,SysStringLen(name))):std::string();
                try {row[key]=variant_json(value);types[key]=type;}catch(...){if(name)SysFreeString(name);VariantClear(&value);throw;}
                if(name)SysFreeString(name);VariantClear(&value);
            }
            obj->EndEnumeration();row["_cim_types"]=types;bytes+=json_text(row).size();
            if(bytes>3*1024*1024){issue(r,"partial","WMI query byte limit reached.");break;}
            r["rows"].push_back(std::move(row));if(i==4095)issue(r,"partial","WMI row count limit reached.");
        }
        if(r["rows"].empty()&&r["status"]=="ok")r["status"]="empty";
    } catch(const WinError& e) {issue(r,r["rows"].empty()?error_status(e.code):"partial",e.what(),e.code);}
    catch(const std::exception& e) {issue(r,"error",e.what());}
    return r;
}
std::vector<Task> collection_tasks(size_t log_count,size_t dump_count,bool include_evtx) {
    std::vector<Task> tasks={{"system","PC and time zone"},{"sapera","Existing Sapera Log Server file"},{"mvsdk","Existing MVSDK application logs"},{"network","NIC, IP, routes and existing neighbor cache"},
        {"devices","Network devices"},{"drivers","NIC drivers and DHCP leases"},{"advanced","NIC advanced settings"},
        {"power","NIC power management"},{"offload","RSS and offload settings"},{"bindings","Bindings and network profiles"},
        {"registry","NIC and persistent TCP/IP values"},{"firewall","Windows Firewall policy"},{"software","Camera software inventory"},{"setupapi","Existing NIC installation history"},
        {"events:System","System history"},{"events:Application","Application incidents and installation history"},
        {"events:Microsoft-Windows-Dhcp-Client/Admin","DHCP admin history"},{"events:Microsoft-Windows-Dhcp-Client/Operational","DHCP operational history"},
        {"events:Microsoft-Windows-NetworkProfile/Operational","Network profile history"},
        {"events:Microsoft-Windows-Kernel-PnP/Configuration","Device configuration history"},
        {"events:Microsoft-Windows-DriverFrameworks-UserMode/Operational","Driver framework history"},
        {"events:Security","Existing NIC/TCP-IP registry audit events"},
        {"events:mvGenICamForEthernet","Separate GigE camera driver history"}};
    for(size_t i=0;i<log_count;++i)tasks.push_back({"log:"+std::to_string(i),"User-specified existing log "+std::to_string(i+1)});
    tasks.push_back({"sdk","Structured SDK log analysis"});
    for(size_t i=0;i<dump_count;++i)tasks.push_back({"dump:"+std::to_string(i),"User-specified dump metadata "+std::to_string(i+1)});
    if(include_evtx)tasks.push_back({"evtx","Optional selected System/Application EVTX"});
    return tasks;
}
Json collect_task(std::string_view id,const Json& input,const Output& output) {
    ComScope com;
    if(id=="system")return system_information();
    if(id=="network")return network();
    if(id=="devices")return devices();
    if(id=="drivers")return wmi_group("NIC driver and lease properties",{L"Win32_NetworkAdapter",L"Win32_NetworkAdapterConfiguration",L"Win32_PnPSignedDriver"},L"ROOT\\CIMV2");
    if(id=="advanced")return wmi_group("NIC advanced properties",{L"MSFT_NetAdapterAdvancedPropertySettingData"});
    if(id=="power")return wmi_group("NIC power settings",{L"MSFT_NetAdapterPowerManagementSettingData"});
    if(id=="offload")return wmi_group("NIC RSS/offload settings",{L"MSFT_NetAdapterRssSettingData",L"MSFT_NetAdapterLsoSettingData",L"MSFT_NetAdapterChecksumOffloadSettingData"});
    if(id=="bindings")return wmi_group("NIC bindings and profiles",{L"MSFT_NetAdapterBindingSettingData",L"MSFT_NetConnectionProfile",L"MSFT_NetIPInterface"});
    if(id=="registry")return registry_network();
    if(id=="firewall")return firewall();
    if(id=="software")return installed_tools();
    if(id=="setupapi")return collect_setupapi(input,output);
    if(id=="sdk")return collect_sdk_logs(input,output);
    if(id=="sapera")return collect_sapera_log(output);
    if(id=="mvsdk")return collect_mvsdk_logs(output);
    if(id=="evtx")return export_selected_evtx(input,output);
    if(id=="dump-attachments")return attach_dumps(input,output);
    if(id.starts_with("dump:"))return collect_dump(static_cast<size_t>(std::stoul(std::string(id.substr(5)))),input,output);
    if(id.starts_with("events:"))return collect_events(id.substr(7),input,output);
    if(id.starts_with("log:"))return copy_user_log(static_cast<size_t>(std::stoul(std::string(id.substr(4)))),input,output);
    throw std::runtime_error("Unknown internal collection task.");
}
} // namespace fnc
