#pragma once
// Shared evidence-model accessors and display helpers for analyze, HTML and diagnostics.
#include "common.hpp"
#include <sstream>
namespace fnc::detail {
inline const Json empty_array=Json::array(), empty_object=Json::object();
inline void need(bool condition,std::string_view message) {if(!condition)throw std::runtime_error(std::string(message));}
inline std::string string_value(const Json& row,std::string_view key,std::string fallback={}) {
    auto it=row.find(std::string(key));return it!=row.end()&&it->is_string()?it->get<std::string>():fallback;
}
inline std::optional<bool> boolean_value(const Json& row,std::string_view key) {
    auto it=row.find(std::string(key));if(it!=row.end()&&it->is_boolean())return it->get<bool>();return {};
}
inline std::string str(const Json& v) {return v.is_null()?"—":v.is_string()?v.get<std::string>():json_text(v);}
inline std::string field(const Json& v,std::string_view key) {
    auto it=v.find(std::string(key));return it==v.end()?"—":str(*it);
}
inline const Json& arr(const Json& v,std::string_view key) {
    auto it=v.find(std::string(key));return it!=v.end()&&it->is_array()?*it:empty_array;
}
inline const Json& obj(const Json& v,std::string_view key) {
    auto it=v.find(std::string(key));return it!=v.end()&&it->is_object()?*it:empty_object;
}
inline const Json& module(const Json& snapshot,std::string_view id) {
    for(const auto& m:arr(snapshot,"modules"))if(string_value(m,"task_id")==id)return m;return empty_object;
}
inline std::string esc(std::string_view text) {
    std::string out;out.reserve(text.size());
    for(char c:text)switch(c){case '&':out+="&amp;";break;case '<':out+="&lt;";break;case '>':out+="&gt;";break;case '"':out+="&quot;";break;case '\'':out+="&#39;";break;default:out+=c;}
    return out;
}
inline std::string state(const Json& i) {
    static const char* names[]={"Unknown","Up","Down","Testing","Unknown","Dormant","NotPresent","LowerLayerDown"};
    auto n=i.value("oper_status",0U);return n<8?names[n]:"Unknown";
}
inline std::optional<std::pair<uint32_t,unsigned>> prefix(const Json& a) {
    if(!a.contains("address")||!a["address"].is_string())return {};
    auto n=a.value("prefix_length",255U);if(n>32)return {};IN_ADDR ip{};auto s=wide(a["address"].get<std::string>());
    if(InetPtonW(AF_INET,s.c_str(),&ip)!=1)return {};return std::pair{ntohl(ip.S_un.S_addr),n};
}
inline uint32_t mask(unsigned n){return n?0xffffffffU<<(32-n):0;}
inline std::string power_value(const Json& row,const char* key) {
    if(!row.contains(key)||row[key].is_null())return "미수집";
    if(!row[key].is_number_unsigned()&&!row[key].is_number_integer())return "미해석 ("+str(row[key])+")";
    auto n=row[key].get<int64_t>();return n==0?"Unsupported (0)":n==1?"Disabled (1)":n==2?"Enabled (2)":n==3&&std::string_view(key)=="DeviceSleepOnDisconnect"?"Inactive (3)":"미해석 ("+std::to_string(n)+")";
}
inline std::string setting_kind(std::string keyword) {
    keyword=lower(keyword);
    if(keyword.find("jumbo")!=std::string::npos)return "Jumbo Packet";
    if(keyword=="pnpcapabilities")return "전원·EEE·Wake";
    for(auto term:{"eee","energy","greenethernet","power","suspend","sleep","wake","dmac","autodisablegigabit"})
        if(keyword.find(term)!=std::string::npos)return "전원·EEE·Wake";
    return {};
}
inline std::string list_text(const Json& row,const char* key) {
    const auto& values=arr(row,key);if(values.empty())return "기록 없음";std::string out;
    for(const auto& v:values){if(!out.empty())out+='\n';out+=str(v);}return out;
}
inline std::string speed_text(const Json& row,const char* key) {
    if(!row.contains(key)||!row[key].is_number())return "미수집";
    auto n=row[key].get<uint64_t>();std::ostringstream out;
    if(n==UINT64_MAX)return "미확인 (NDIS_LINK_SPEED_UNKNOWN)";
    if(n>=1000000000ULL)out<<double(n)/1000000000.0<<" Gbps";
    else if(n>=1000000ULL)out<<double(n)/1000000.0<<" Mbps";
    else out<<n<<" bps";return out.str();
}
inline std::string mask_text(const Json& address) {
    auto p=prefix(address);if(!p)return "—";auto m=mask(p->second);
    return std::to_string(m>>24)+"."+std::to_string((m>>16)&255)+"."+std::to_string((m>>8)&255)+"."+std::to_string(m&255);
}
inline std::string assignment_text(const Json& address) {
    auto n=address.value("prefix_origin",0U);return n==1?"수동 (Manual)":n==3?"DHCP":n==2?"WellKnown":"미판정";
}
struct FilterCounts {size_t enabled=0,total=0,unknown=0;};
inline FilterCounts filter_counts(const Json& nic) {
    FilterCounts counts;
    for(const auto& a:arr(obj(nic,"details"),"bindings"))if(string_value(a,"ComponentClassName")=="Filter") {
        ++counts.total;auto enabled=boolean_value(a,"Enabled");if(!enabled)++counts.unknown;else if(*enabled)++counts.enabled;
    }
    return counts;
}
inline bool core_setting(const Json& row) {
    auto key=lower(string_value(row,"RegistryKeyword"));if(!setting_kind(key).empty())return true;
    if(key.starts_with('*'))key.erase(0,1);
    for(auto k:{"speedduplex","receivebuffers","transmitbuffers","interruptmoderation","rss","numrssqueues","flowcontrol"})if(key==k)return true;
    return false;
}
inline std::string setting_value(const Json& row) {
    if(!row.contains("RegistryValue"))return "—";
    const auto& values=row["RegistryValue"];if(!values.is_array())return str(values);
    std::string out;for(const auto& v:values){if(!out.empty())out+=", ";out+=str(v);}return out.empty()?"—":out;
}
inline std::string driver_date(const Json& row) {
    auto date=field(row,"DriverDate");if(date.size()<8)return date;
    for(size_t i=0;i<8;++i)if(date[i]<'0'||date[i]>'9')return date;
    return date.substr(0,4)+"-"+date.substr(4,2)+"-"+date.substr(6,2);
}
inline std::string reference(const Json& e) {return field(e,"file")+":"+field(e,"line");}
} // namespace fnc::detail
