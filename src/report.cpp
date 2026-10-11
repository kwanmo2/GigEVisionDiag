#include "common.hpp"
#include <miniz.h>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace fnc {
namespace {
const Json* module(const Json& modules,std::string_view id) {
    for(const auto& m:modules)if(m.value("task_id","")==id)return &m;return nullptr;
}
std::optional<std::pair<DWORD,unsigned>> ipv4_prefix(const Json& a) {
    if(!a.contains("address")||!a["address"].is_string())return {};
    auto text=wide(a["address"].get<std::string>());IN_ADDR address{};
    if(InetPtonW(AF_INET,text.c_str(),&address)!=1)return {};
    auto prefix=a.value("prefix_length",255U);if(prefix>32)return {};
    return std::pair<DWORD,unsigned>{ntohl(address.S_un.S_addr),prefix};
}
DWORD mask(unsigned prefix) {return prefix?0xffffffffU<<(32-prefix):0;}
Json findings(const Json& input,const Json& modules) {
    Json out=Json::array();auto add=[&](const char* category,std::string text,Json evidence=Json::object()) {out.push_back({{"category",category},{"text",text},{"evidence",evidence}});};
    const auto* net=module(modules,"network");
    if(!net || !net->contains("adapters")) {add("unknown","현재 NIC/IP 정보를 충분히 수집하지 못했습니다.");return out;}
    for(const auto& a:(*net)["adapters"]) {
        auto name=a.value("friendly_name","");
        if(a.value("dhcp_v4_enabled",false))add("fact",name+": PC NIC의 IPv4 DHCP가 활성화되어 있습니다. 카메라의 DHCP 설정을 의미하지 않습니다.",{{"task_id","network"},{"if_index",a["if_index"]},{"dhcp_server",a["dhcp_v4_server"]}});
        for(const auto& ip:a["addresses"]) {auto p=ipv4_prefix(ip);if(p && (p->first&0xffff0000)==0xa9fe0000)
            add("fact",name+": 169.254/16 링크 로컬 주소가 관찰되었습니다. 주소만으로 DHCP 실패를 확정하지 않습니다.",{{"task_id","network"},{"if_index",a["if_index"]},{"address",ip["address"]}});}
    }
    const auto& adapters=(*net)["adapters"];
    for(size_t i=0;i<adapters.size();++i)for(size_t j=i+1;j<adapters.size();++j) {
        if(adapters[i]["if_index"]==adapters[j]["if_index"])continue;
        bool overlap=false;
        for(const auto& x:adapters[i]["addresses"])for(const auto& y:adapters[j]["addresses"]) {
            auto px=ipv4_prefix(x),py=ipv4_prefix(y);
            if(px&&py&&px->second&&py->second&&((px->first^py->first)&mask((std::min)(px->second,py->second)))==0)overlap=true;
        }
        if(overlap)add("candidate","서로 다른 NIC의 IPv4 서브넷이 겹칩니다. 장애 당시 경로와 메트릭을 대조할 조사 항목입니다.",
            {{"task_id","network"},{"if_indices",Json::array({adapters[i]["if_index"],adapters[j]["if_index"]})}});
    }
    if(!input["camera_mac"].is_null()) {
        auto mac=input["camera_mac"].get<std::string>();Json matches=Json::array();
        for(const auto& n:(*net)["neighbors"])if(lower(n.value("mac",""))==mac)matches.push_back(n);
        if(matches.empty())add("unknown","사용자가 지정한 카메라 MAC과 일치하는 기존 Neighbor 캐시 항목이 없습니다. 카메라 부재 또는 현재 IP를 판정할 수 없습니다.");
        else add("fact","사용자가 지정한 카메라 MAC과 일치하는 기존 캐시 항목입니다. 오래된 항목일 수 있으며 카메라의 실제 현재 IP를 검증한 결과가 아닙니다.",{{"task_id","network"},{"neighbor_entries",matches}});
    }
    if(!input["expected_camera_ip"].is_null()) {
        auto text=wide(input["expected_camera_ip"].get<std::string>());IN_ADDR ip{};InetPtonW(AF_INET,text.c_str(),&ip);DWORD value=ntohl(ip.S_un.S_addr);
        Json same=Json::array();for(const auto& a:adapters)for(const auto& addr:a["addresses"]) {auto p=ipv4_prefix(addr);if(p&&((p->first^value)&mask(p->second))==0)same.push_back({{"if_index",a["if_index"]},{"nic_address",addr["address"]},{"prefix_length",p->second}});}
        if(same.empty())add("candidate","입력한 예상 카메라 IP와 같은 IPv4 서브넷의 PC NIC를 찾지 못했습니다. 경로가 있는 다른 서브넷 통신 가능성은 별도로 검토해야 합니다.",{{"expected_camera_ip",input["expected_camera_ip"]}});
        else add("fact","사용자가 입력한 예상 카메라 IP와 같은 서브넷의 NIC 후보입니다. 입력 주소의 실제 사용 여부는 조회하지 않았습니다.",{{"expected_camera_ip",input["expected_camera_ip"]},{"matching_nic_addresses",same}});
    }
    add("unknown","PC 정보만으로 카메라의 실제 현재 IP, Persistent IP 설정, IP 변경 주체 또는 장애 원인을 확정할 수 없습니다.");
    return out;
}
struct TimelineRow {
    std::string time,local,channel,provider,id,record,message,file,tokens;
    size_t line=0;
};
std::string scalar_text(const Json& j) {return j.is_null()?std::string():j.is_string()?j.get<std::string>():json_text(j);}
std::vector<TimelineRow> timeline(const Output& output,const Json& modules,Json& warnings) {
    std::vector<TimelineRow> rows;
    std::set<std::string> sources;for(const auto& m:modules)for(const auto& artifact:m.value("artifacts",Json::array()))sources.insert(artifact.get<std::string>());
    for(const auto& name:sources) {
        if(!(name.starts_with("events-")&&name.ends_with(".jsonl"))&&name!="setupapi-timeline.jsonl"&&name!="sdk-events.jsonl")continue;
        auto path=output.file(name);ensure_local_path(path);std::ifstream file(path,std::ios::binary);if(!file)throw std::runtime_error("Unable to read event evidence for timeline.");
        std::string line;size_t n=0;
        while(std::getline(file,line)) {
            ++n;if(line.empty())continue;
            try {
                auto j=Json::parse(line);
                TimelineRow row;row.time=scalar_text(j.value("time_utc",Json(nullptr)));row.local=scalar_text(j.value("time_local",Json(nullptr)));
                row.channel=j.value("channel","");row.provider=j.value("provider","");row.id=scalar_text(j.value("event_id",Json(nullptr)));row.record=scalar_text(j.value("record_id",Json(nullptr)));
                if(name=="sdk-events.jsonl"){row.local=j.value("original_timestamp","");row.channel="SDK";row.provider=j.value("kind","");}
                row.message=scalar_text(j.value("message",Json(nullptr)));if(row.message.size()>2048) {size_t end=2048;while(end && (static_cast<unsigned char>(row.message[end])&0xc0)==0x80)--end;row.message.resize(end);row.message+=" [excerpt; see evidence]";}
                row.file=name;row.line=n;row.tokens=scalar_text(j.value("matched_identifier_tokens",Json::array()));rows.push_back(std::move(row));
            } catch(const std::exception&) {warnings.push_back("Malformed/incomplete evidence row kept in "+name+":"+std::to_string(n)+"; excluded from timeline.");if(warnings.size()>100)throw std::runtime_error("Excessive malformed evidence rows.");}
        }
    }
    std::stable_sort(rows.begin(),rows.end(),[](const auto& a,const auto& b){if(a.time.empty()!=b.time.empty())return !a.time.empty();return a.time<b.time;});return rows;
}
size_t zip_write(void* opaque,mz_uint64 offset,const void* bytes,size_t n) {
    auto h=static_cast<HANDLE>(opaque);LARGE_INTEGER pos{};pos.QuadPart=static_cast<LONGLONG>(offset);
    if(!SetFilePointerEx(h,pos,nullptr,FILE_BEGIN))return 0;
    try {write_all(h,std::string_view(static_cast<const char*>(bytes),n));return n;}catch(...){return 0;}
}
size_t zip_read(void* opaque,mz_uint64 offset,void* bytes,size_t n) {
    auto h=static_cast<HANDLE>(opaque);LARGE_INTEGER pos{};pos.QuadPart=static_cast<LONGLONG>(offset);
    if(!SetFilePointerEx(h,pos,nullptr,FILE_BEGIN))return 0;
    DWORD read=0;if(n>MAXDWORD||!ReadFile(h,bytes,DWORD(n),&read,nullptr))return 0;return read;
}
} // namespace

bool write_reports(const Output& output,const Json& input,const Json& modules,const std::string& start,const std::string& end) {
    Json warnings=Json::array();auto rows=timeline(output,modules,warnings);auto facts=findings(input,modules);
    auto incident=input["incident_time"].is_string()?parse_iso_time(input["incident_time"].get<std::string>()):std::optional<ULONGLONG>();
    if(incident && (*incident<*parse_iso_time(input["from_utc"].get<std::string>()) || *incident>*parse_iso_time(input["to_utc"].get<std::string>())))warnings.push_back("Incident marker is outside the collected history window. The marker does not widen --days.");
    Json snapshot{{"schema_version",1},{"tool",{{"name","FetchNetworkConfig"},{"version",FNC_VERSION}}},
        {"started_at_utc",start},{"completed_at_utc",end},{"inputs",input},{"modules",modules},{"findings",facts},{"report_warnings",warnings},
        {"consistency_note","Sequential observations, not an atomic snapshot. Every module has its own observation time. Natural DHCP/cache/counter/log changes can happen during collection."}};
    uint64_t retained=json_text(snapshot,2).size()+2ULL*1024*1024;std::set<std::string> registered;
    for(const auto& m:modules)for(const auto& a:m.value("artifacts",Json::array()))registered.insert(a.get<std::string>());
    for(const auto& name:registered)if(!name.starts_with("user-log-"))retained+=fs::file_size(output.file(name));
    auto csv_limit=static_cast<size_t>((std::min)(64ULL*1024*1024,retained<256ULL*1024*1024?256ULL*1024*1024-retained:0));
    auto csv=output.create("timeline.csv");std::string header="\xef\xbb\xbf" "time_utc,time_local,channel,provider,event_id,record_id,message_excerpt,evidence_file,evidence_line,matched_identifier_tokens,incident_offset_seconds\r\n";write_all(csv.get(),header);size_t csv_bytes=header.size();
    if(incident)rows.push_back({iso_time(*incident),local_time(*incident),"User input","Incident marker","","","사용자가 입력한 장애 발생 시각","","",0});
    std::stable_sort(rows.begin(),rows.end(),[](const auto& a,const auto& b){if(a.time.empty()!=b.time.empty())return !a.time.empty();return a.time<b.time;});
    for(const auto& row:rows) {
        std::string delta;auto t=parse_iso_time(row.time);if(incident&&t)delta=std::to_string((static_cast<LONGLONG>(*t)-static_cast<LONGLONG>(*incident))/10000000LL);
        std::vector<std::string> cells={row.time,row.local,row.channel,row.provider,row.id,row.record,row.message,row.file,row.line?std::to_string(row.line):"",row.tokens,delta};
        std::string line;for(size_t i=0;i<cells.size();++i){if(i)line+=',';line+=csv_cell(cells[i]);}line+="\r\n";
        if(csv_bytes>=csv_limit||line.size()>csv_limit-csv_bytes){warnings.push_back("timeline.csv reached its file/ordinary bundle size budget; full registered JSONL evidence remains available.");break;}write_all(csv.get(),line);csv_bytes+=line.size();
    }
    snapshot["report_warnings"]=warnings;output.write("snapshot.json",json_text(snapshot,2)+"\n");
    std::ostringstream summary;
    summary<<"\xef\xbb\xbf" "FetchNetworkConfig " FNC_VERSION " 진단 수집 보고서\r\n\r\n";
    summary<<"수집 시작(UTC): "<<start<<"\r\n수집 종료(UTC): "<<end<<"\r\n기존 이력 범위: "<<input["from_utc"].get<std::string>()<<" ~ "<<input["to_utc"].get<std::string>()<<"\r\n";
    if(input["incident_time"].is_string())summary<<"사용자 입력 장애 시각: "<<input["incident_time"].get<std::string>()<<"\r\n";
    summary<<"\r\n수집 범위 및 한계\r\n"
        "- PC 내부의 현재 설정, 기존 캐시와 남아 있는 로그만 읽었습니다.\r\n"
        "- PC/카메라 설정 변경, 카메라 검색/접속, ping, 로그 활성화, 패킷 캡처, 외부 전송을 수행하지 않습니다.\r\n"
        "- 프로그램이 의도적으로 생성한 파일은 지정한 결과 폴더 안에 있습니다. Windows 자체 실행 흔적은 남을 수 있습니다.\r\n"
        "- 모든 자료가 같은 순간의 상태인 것은 아닙니다. 각 모듈의 관찰 시각을 확인하십시오.\r\n"
        "- 기록 없음은 변경 없음의 증거가 아닙니다. 보존 기간, 로그 비활성, 권한, 미지원과 제한을 확인하십시오.\r\n"
        "- 4657 레지스트리 변경 기록은 당시 감사가 설정되어 있어야 존재합니다. 이 도구는 감사 설정을 추가하지 않습니다.\r\n"
        "- SetupAPI는 장치/드라이버 설치 기록입니다. 모든 NIC 설정 변경을 기록하는 이력이 아닙니다.\r\n"
        "- 카메라의 DHCP 임대/설정 변경은 PC NIC의 DHCP 정보와 별개의 증거가 필요합니다.\r\n"
        "- 설정값은 원래 키, 값과 CIM/레지스트리 형식을 보존합니다. 미지원 값을 기본값으로 대체하지 않습니다.\r\n"
        "- 방화벽 규칙의 현재 프로필 적용 가능성과 실제 패킷 허용 판정은 다릅니다. 타사 필터/정책 우선순위는 추가 조사가 필요합니다.\r\n"
        "\r\n확인된 사실과 조사 항목\r\n";
    for(const auto& f:facts) {auto c=f["category"].get<std::string>();summary<<"["<<(c=="fact"?"확인된 사실":c=="candidate"?"원인 후보/조사 항목":"확인 불가")<<"] "<<f["text"].get<std::string>()<<"\r\n";}
    summary<<"\r\n수집 모듈 상태\r\n";
    for(const auto& m:modules) {
        summary<<m.value("task_id","")<<": "<<m.value("status","error")<<"\r\n";
        for(const auto& i:m["issues"])summary<<"  - "<<i.value("reason","")<<"\r\n";
        if(m.contains("metadata")) {
            const auto& metadata=m["metadata"];if(metadata.contains("enabled"))summary<<"  channel enabled: "<<json_text(metadata["enabled"])<<"\r\n";
            if(metadata.contains("oldest_retained_event"))summary<<"  oldest retained UTC: "<<scalar_text(metadata["oldest_retained_event"].value("time_utc",Json(nullptr)))<<"\r\n";
        }
        if(m.contains("queries"))for(const auto& q:m["queries"])if(q["status"]!="ok"&&q["status"]!="empty") {
            summary<<"  "<<q["source"].get<std::string>()<<": "<<q["status"].get<std::string>()<<"\r\n";
            for(const auto& i:q["issues"])summary<<"    "<<i.value("reason","")<<"\r\n";
        }
    }
    summary<<"\r\n타임라인: "<<rows.size()<<"개 행 (사용자 시각 표식 포함 가능). CSV의 증거 파일/행 번호를 원본과 대조하십시오.\r\n";
    if(incident) {
        std::vector<const TimelineRow*> nearest;for(const auto& row:rows)if(row.channel!="User input" && !row.time.empty())nearest.push_back(&row);
        auto distance=[&](const auto* row){auto ticks=*parse_iso_time(row->time);return ticks>*incident?ticks-*incident:*incident-ticks;};
        std::stable_sort(nearest.begin(),nearest.end(),[&](auto* a,auto* b){return distance(a)<distance(b);});
        summary<<"장애 시각과 가장 가까운 기존 기록 (시간상 근접은 인과관계의 증거가 아닙니다):\r\n";
        for(size_t i=0;i<(std::min)(nearest.size(),size_t(5));++i)summary<<"  "<<nearest[i]->time<<" "<<nearest[i]->provider<<" ID="<<nearest[i]->id<<" "<<nearest[i]->file<<":"<<nearest[i]->line<<"\r\n";
    }
    for(const auto& warning:warnings)summary<<"주의: "<<warning.get<std::string>()<<"\r\n";
    summary<<"\r\n전달 파일: diagnostics.zip\r\n"
        "snapshot.json: 현재 상태, 수집 조건, 출처, 누락 사유\r\n"
        "events-*.jsonl: 이벤트별 원본 XML 및 식별 정보 (xml 문자열을 디코딩하면 원본 XML)\r\n"
        "setupapi-nic.log / user-log-*.log: 관련 기존 로그 증거\r\n"
        "sapera-Logs.dat: Sapera Log Server 원본 바이트 (최대 64 MiB, 날짜 필터/텍스트 분석 없음)\r\n"
        "manifest.json: 파일 SHA-256 (manifest 자체와 ZIP은 순환 해시를 피하기 위해 제외)\r\n"
        "diagnostics.zip.sha256: 완성된 ZIP의 SHA-256\r\n";
    output.write("summary.txt",summary.str());
    return !warnings.empty();
}
void write_manifest(const Output& output,const Json& input,const Json& modules,const std::string& start,const std::string& end) {
    Json files=Json::array(),coverage=Json::array(),external=Json::array();
    std::set<std::string> registered={"snapshot.json","timeline.csv","summary.txt"};
    for(const auto& m:modules){for(const auto& name:m.value("artifacts",Json::array()))registered.insert(name.get<std::string>());if(m.contains("external_attachment")&&m.value("status","")=="ok")external.push_back(m["external_attachment"]);}
    uint64_t retained=0,logs=0;
    for(const auto& name:registered) {if(name.starts_with("dump-attachments")||name=="diagnostics.zip"||name=="manifest.json")throw std::runtime_error("Invalid core artifact registration.");auto p=output.file(name);ensure_local_path(p);auto size=fs::file_size(p);
        if(name.starts_with("user-log-")){if(size>kUserLogBytes||size>kUserLogBytes*kUserLogCount-logs)throw std::runtime_error("Registered user log byte budget exceeded.");logs+=size;}
        else{if(size>64ULL*1024*1024||size>256ULL*1024*1024-retained)throw std::runtime_error("Registered core evidence byte budget exceeded.");retained+=size;}
        files.push_back({{"name",name},{"size_bytes",size},{"sha256",sha256(p)}});}
    for(const auto& m:modules)coverage.push_back({{"task_id",m["task_id"]},{"status",m["status"]},{"issues",m["issues"]},{"artifacts",m["artifacts"]}});
    Json manifest{{"schema_version",1},{"tool_version",FNC_VERSION},{"started_at_utc",start},{"completed_at_utc",end},
        {"inputs",input},{"coverage",coverage},{"files",files},{"external_attachments",external},{"hash_note","Hashes detect accidental content changes; they are not a digital signature. The manifest and final archive are excluded from this internal file list. External dump archives are referenced but excluded from diagnostics.zip."}};
    output.write("manifest.json",json_text(manifest,2)+"\n");
}
void create_zip(const Output& output) {
    auto manifest=Json::parse(read_local_file(output.file("manifest.json"),1024*1024));std::vector<fs::path> files={output.file("manifest.json")};
    for(const auto& item:manifest.at("files"))files.push_back(output.file(item.at("name").get<std::string>()));
    auto zip_file=output.create("diagnostics.zip");mz_zip_archive zip{};zip.m_pWrite=zip_write;zip.m_pIO_opaque=zip_file.get();
    if(!mz_zip_writer_init(&zip,0))throw std::runtime_error("Cannot initialize ZIP writer.");
    try {
        for(const auto& p:files) {
            ensure_local_path(p);Handle h(CreateFileW(p.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,nullptr));if(!h)fail_win("Read ZIP source");
            LARGE_INTEGER n{};if(!GetFileSizeEx(h.get(),&n))fail_win("ZIP source size");auto name=utf8(p.filename().native());
            if(!mz_zip_writer_add_read_buf_callback(&zip,name.c_str(),zip_read,h.get(),static_cast<mz_uint64>(n.QuadPart),
                nullptr,nullptr,0,MZ_BEST_SPEED,nullptr,0,nullptr,0))throw std::runtime_error(std::string("ZIP input failed: ")+mz_zip_get_error_string(mz_zip_get_last_error(&zip)));
        }
        if(!mz_zip_writer_finalize_archive(&zip))throw std::runtime_error("ZIP finalization failed.");
        mz_zip_writer_end(&zip);zip_file.reset();auto digest=sha256(output.file("diagnostics.zip"));output.write("diagnostics.zip.sha256",digest+"  diagnostics.zip\r\n");
    } catch(...) {if(zip.m_pState)mz_zip_writer_end(&zip);throw;}
}
} // namespace fnc
