#include "analyzer.hpp"
#include "analysis_util.hpp"
#include <map>

namespace fnc {
using namespace detail;
namespace {
const char* severity_label(std::string_view s){return s=="critical"?"심각":s=="warning"?"주의":s=="unknown"?"판단 불가":s=="info"?"참고":"정상";}
const char* status_icon(std::string_view s){return s=="critical"?"✗":s=="warning"?"⚠":s=="unknown"?"?":s=="info"?"i":"✓";}
const char* role_label(std::string_view s){return s=="camera"?"카메라 NIC":s=="uplink"?"사내망·인터넷 NIC":s=="other"?"기타 활성 NIC":s=="inactive"?"연결 안 됨":s=="virtual"?"가상 NIC":s=="absent"?"장치 없음":"숨김";}
const char* event_label(std::string_view s){return s=="link_down"?"링크 분리":s=="link_up"?"링크 연결":s=="sdk_error"?"SDK 오류":s=="sdk_timeout"?"SDK timeout":s=="sdk_connect"?"카메라 연결":s=="sdk_disconnect"?"카메라 연결 해제":s=="app_crash"?"앱 오류":s=="sdk_reset"?"카메라 리셋 (DeviceReset)":"기타";}
std::string number_text(const Json& v){if(!v.is_number())return "—";std::ostringstream o;if(v.is_number_float()){o.precision(4);o<<v.get<double>();}else o<<json_text(v);return o.str();}
void diagnosis_sections(std::ostringstream& h,const Json& r) {
    const auto& d=obj(r,"diagnosis");if(d.empty())return;auto text=[](std::string_view t){return esc(t);};
    auto overall=string_value(d,"overall","unknown");const auto& counts=obj(d,"counts");
    std::map<std::string,size_t> first_finding;size_t index=0;for(const auto& f:arr(d,"findings")){first_finding.emplace(string_value(f,"id"),index);++index;}
    h<<"<section class=\"card verdict sev-"<<text(overall)<<"\" id=\"verdict\"><div class=\"light\" aria-hidden=\"true\">"<<status_icon(overall)<<"</div><div><h2>종합 판정: "<<severity_label(overall)<<"</h2><p>"<<text(string_value(d,"headline"))
     <<"</p><p class=\"counts\"><span class=\"pill sev-critical\">심각 "<<field(counts,"critical")<<"</span><span class=\"pill sev-warning\">주의 "<<field(counts,"warning")
     <<"</span><span class=\"pill sev-unknown\">판단 불가 "<<field(counts,"unknown")<<"</span><span class=\"pill sev-info\">참고 "<<field(counts,"info")<<"</span></p><p class=\"muted\">카메라 NIC "
     <<field(d,"camera_nic_count")<<"개를 분석했습니다. 연결되지 않았거나 가상·장치 없는 NIC "<<field(d,"hidden_nic_count")<<"개는 숨기고 부록에만 표시합니다.</p></div></section>";
    if(const auto& syn=obj(d,"synthesis");!syn.empty()) {
        auto cite=[&](const Json& ids){std::string out;for(const auto& id:ids){auto it=first_finding.find(str(id));if(it!=first_finding.end())out+=" <a href=\"#f-"+std::to_string(it->second)+"\"><code>"+text(str(id))+"</code></a>";}return out;};
        h<<"<h2 id=\"synthesis\">종합 분석</h2><section class=\"card synthesis\"><h3>결론</h3><ol class=\"conclusions\">";
        for(const auto& c:arr(syn,"conclusions")){auto sev=string_value(c,"severity");
            h<<"<li><span class=\"pill sev-"<<text(sev)<<"\">"<<severity_label(sev)<<"</span>"<<text(field(c,"text"))<<cite(arr(c,"finding_ids"))<<"</li>";}
        h<<"</ol>";
        bool header=false;
        for(const auto& c:arr(d,"checklists")) {
            const auto& l=c.contains("link")?c["link"]:Json(nullptr);if(!l.is_object()||!l.value("down",size_t(0)))continue;
            if(!header){h<<"<h3>링크 분리 원인 분해</h3>";header=true;}
            auto down=static_cast<double>(l.value("down",size_t(0)));
            h<<"<p><strong>"<<text(field(c,"name"))<<"</strong> · 총 "<<field(l,"down")<<"회</p><div class=\"stack\" role=\"img\" aria-label=\""<<text(field(c,"name"))<<" 링크 분리 원인 비율\">";
            static const std::pair<const char*,const char*> segments[]={{"reset","seg-reset"},{"pc_side","seg-pc"},{"no_log","seg-nolog"},{"unexplained","seg-unexplained"}};
            for(const auto& [key,cls]:segments){auto n=l.value(key,size_t(0));if(n)h<<"<i class=\""<<cls<<"\" style=\"width:"<<(std::max)(100.0*n/down,0.8)<<"%\" title=\""<<n<<"\"></i>";}
            h<<"</div><p class=\"legend\"><span class=\"dot seg-reset\"></span>DeviceReset 직후 "<<field(l,"reset")<<" <span class=\"dot seg-pc\"></span>PC 측 "<<field(l,"pc_side")
             <<" <span class=\"dot seg-nolog\"></span>SDK 로그 없음 "<<field(l,"no_log")<<" <span class=\"dot seg-unexplained\"></span>원인 미확인 "<<field(l,"unexplained")<<" ("<<field(l,"episodes")<<"개 구간)</p>";
        }
        if(!arr(syn,"actions").empty()) {
            h<<"<h3>조치 순서</h3><ol class=\"actions\">";
            for(const auto& a:arr(syn,"actions")){auto sev=string_value(a,"severity");std::string nics;for(const auto& n:arr(a,"nics")){if(!nics.empty())nics+=", ";nics+=str(n);}
                h<<"<li><span class=\"pill sev-"<<text(sev)<<"\">"<<severity_label(sev)<<"</span><strong>"<<text(field(a,"title"))<<"</strong>"<<(nics.empty()?std::string():" <small>"+text(nics)+"</small>")
                 <<cite(Json::array({a["id"]}))<<"<br><small>"<<text(field(a,"action"))<<"</small></li>";}
            h<<"</ol>";
        }
        if(!arr(syn,"profile").empty()){h<<"<h3>운용 현황</h3><dl class=\"facts\">";for(const auto& p:arr(syn,"profile"))h<<"<dt>"<<text(field(p,"label"))<<"</dt><dd>"<<text(field(p,"value"))<<"</dd>";h<<"</dl>";}
        if(!arr(syn,"limits").empty()){h<<"<h3>분석의 한계</h3><ul>";for(const auto& x:arr(syn,"limits"))h<<"<li>"<<text(str(x))<<"</li>";h<<"</ul>";}
        h<<"</section>";
    }
    h<<"<section class=\"card\"><h3>NIC 역할 판별</h3><div class=\"roles\">";
    for(const auto& x:arr(d,"nic_roles")) {
        auto role=string_value(x,"role");if(role!="camera"&&role!="uplink"&&role!="other")continue;
        h<<"<div class=\"role role-"<<text(role)<<"\"><strong>"<<text(field(x,"name"))<<"</strong> <span class=\"badge\">"<<role_label(role)<<(x.value("inferred",false)?" (추정)":"")<<"</span><br><small>"<<text(field(x,"description"))<<"</small><ul>";
        for(const auto& reason:arr(x,"reasons"))h<<"<li>"<<text(str(reason))<<"</li>";
        h<<"</ul></div>";
    }
    h<<"</div><p class=\"muted\">카메라 NIC는 GigE 필터 드라이버·입력한 카메라 IP/MAC·SDK 로그 MTU·Jumbo·게이트웨이 유무로 판별합니다. 판별이 틀리면 --camera-mac / --expected-camera-ip로 다시 수집하십시오.</p></section>";
    h<<"<h2 id=\"findings\">주요 문제와 권장 조치</h2>";
    if(arr(d,"findings").empty())h<<"<p class=\"card\">규칙에 해당하는 문제가 없습니다.</p>";
    index=0;
    for(const auto& f:arr(d,"findings")) {
        auto sev=string_value(f,"severity");
        h<<"<article class=\"finding sev-"<<text(sev)<<"\" id=\"f-"<<index++<<"\" data-sev=\""<<text(sev)<<"\"><header><span class=\"pill sev-"<<text(sev)<<"\">"<<severity_label(sev)<<"</span><strong>"<<text(field(f,"title"))
         <<"</strong><span class=\"badge\">"<<text(field(f,"basis"))<<"</span><code>"<<text(field(f,"id"))<<"</code></header><dl class=\"facts\"><dt>관찰값</dt><dd>"<<text(field(f,"observed"))<<"</dd><dt>기대값</dt><dd>"<<text(field(f,"expected"))
         <<"</dd><dt>권장 조치</dt><dd>"<<text(field(f,"recommendation"))<<"</dd></dl>";
        if(!arr(f,"evidence").empty()){h<<"<details><summary>근거 ("<<arr(f,"evidence").size()<<")</summary><ul>";for(const auto& e:arr(f,"evidence"))h<<"<li>"<<text(str(e))<<"</li>";h<<"</ul></details>";}
        h<<"</article>";
    }
    h<<"<p class=\"muted\">"<<text(string_value(d,"note"))<<"</p>";
    h<<"<h2 id=\"checklist\">카메라 NIC 체크리스트</h2>";
    if(arr(d,"checklists").empty())h<<"<p class=\"card\">카메라 NIC를 특정하지 못해 체크리스트를 만들 수 없습니다. 부록의 NIC 목록을 확인하십시오.</p>";
    for(const auto& c:arr(d,"checklists")) {
        h<<"<section class=\"card checklist\"><h3>"<<text(field(c,"name"))<<" <small>"<<text(field(c,"description"))<<"</small></h3><div class=\"scroll\"><table><thead><tr><th scope=\"col\">판정</th><th scope=\"col\">항목</th><th scope=\"col\">현재값</th><th scope=\"col\">권장값</th></tr></thead><tbody>";
        for(const auto& i:arr(c,"items")){auto st=string_value(i,"status");
            h<<"<tr data-status=\""<<text(st)<<"\"><td><span class=\"pill sev-"<<text(st)<<"\">"<<status_icon(st)<<" "<<severity_label(st)<<"</span></td><td>"<<text(field(i,"item"))<<"</td><td>"<<text(field(i,"observed"))<<"</td><td>"<<text(field(i,"expected"))<<"</td></tr>";}
        h<<"</tbody></table></div></section>";
    }
    h<<"<h2 id=\"sdk-summary\">카메라와 SDK 세션</h2>";
    const auto& cameras=arr(d,"cameras");const auto& sessions=arr(d,"sessions");
    if(cameras.empty()&&sessions.empty()&&arr(d,"camera_software").empty())h<<"<p class=\"card\">구조화된 SDK 로그(MVSDK/CamClient)와 카메라 SDK 설치 기록이 없습니다. Sapera 로그는 원본만 보존하며 Sapera Log Viewer로 확인하십시오.</p>";
    if(!cameras.empty()){h<<"<section class=\"card\"><h3>로그에서 확인된 카메라</h3><div class=\"scroll\"><table><thead><tr><th>Vendor</th><th>Model</th><th>Serial</th><th>Firmware</th><th>원본</th></tr></thead><tbody>";
        for(const auto& c:cameras)h<<"<tr><td>"<<text(field(c,"vendor"))<<"</td><td>"<<text(field(c,"model"))<<"</td><td>"<<text(field(c,"serial_number"))<<"</td><td>"<<text(field(c,"firmware_version"))<<"</td><td>"<<text(field(c,"source_file"))<<"</td></tr>";
        h<<"</tbody></table></div></section>";}
    if(!arr(d,"sdk_versions").empty()||!arr(d,"camera_software").empty()){h<<"<section class=\"card\"><h3>SDK 버전과 설치된 카메라 소프트웨어</h3><ul>";
        std::set<std::string> seen;for(const auto& v:arr(d,"sdk_versions")){auto t=json_text(obj(v,"fields"));if(seen.insert(t).second&&seen.size()<=20)h<<"<li>실행 중 SDK (로그): "<<text(t)<<"</li>";}
        for(const auto& s:arr(d,"camera_software"))h<<"<li>설치 목록: "<<text(field(s,"name"))<<" "<<text(field(s,"version"))<<" · "<<text(field(s,"publisher"))<<"</li>";
        h<<"</ul></section>";}
    if(!sessions.empty()) {
        h<<"<section class=\"card\"><h3>세션별 수신 품질</h3><div class=\"scroll\"><table><thead><tr><th>원본 / PID</th><th>시간 범위 (로그 원래 시각)</th><th>카메라</th><th>Packet / NIC MTU</th><th>FPS</th><th>수신 이미지</th><th>손실 이미지 비율</th><th>lost / resend packet</th><th>ERROR / WARN</th><th>종료</th></tr></thead><tbody>";
        size_t shown=0;
        for(const auto& x:sessions) {
            const auto& st=obj(x,"stats");const auto& f=obj(x,"fields");
            if(st.empty()&&x.value("error_count",0)==0&&x.value("warning_count",0)==0)continue;  // Version/connect-only fragments add no quality information.
            if(shown++>=200)break;auto ratio=x.value("image_loss_ratio",Json(nullptr));
            double pct=ratio.is_number()?ratio.get<double>()*100:0;auto sev=!ratio.is_number()?"unknown":pct>=1?"critical":pct>0?"warning":"ok";
            std::ostringstream p;p.precision(3);p<<pct;
            h<<"<tr data-status=\""<<sev<<"\"><td>"<<text(field(x,"source_file")+" / "+field(x,"pid"))<<"</td><td>"<<text(field(x,"first_timestamp")+" ~ "+field(x,"last_timestamp"))<<"</td><td>"<<text(field(f,"model")+" "+field(f,"serial_number"))
             <<"</td><td>"<<text(field(f,"packet_size")+" / "+field(f,"nic_mtu"))<<"</td><td>"<<text(number_text(st.value("fps",Json(nullptr))))<<"</td><td>"<<text(number_text(st.value("imageReceived",Json(nullptr))))<<"</td><td>";
            if(ratio.is_number())h<<"<span class=\"bar\"><i class=\"sev-"<<sev<<"\" style=\"width:"<<(std::min)(100.0,(std::max)(pct*10,pct>0?2.0:0.0))<<"%\"></i></span> "<<p.str()<<"%";else h<<"통계 없음";
            h<<"</td><td>"<<text(number_text(st.value("lostPacket",Json(nullptr)))+" / "+number_text(st.value("resendPacket",Json(nullptr))))<<"</td><td>"<<text(field(x,"error_count")+" / "+field(x,"warning_count"))
             <<"</td><td>"<<text(x["ended_by"].is_null()?"기록 없음":field(x,"ended_by"))<<"</td></tr>";
        }
        h<<"</tbody></table></div><p class=\"muted\">통계 값은 세션 안에서 누적값으로 보고 최대값을 표시합니다. 막대는 손실률 10%를 가득 찬 길이로 그립니다. 통계·경고가 없는 세션 조각은 생략하며 최대 200개 세션을 표시합니다.</p></section>";
    }
    h<<"<h2 id=\"timeline\">상관 타임라인</h2>";const auto& timeline=arr(d,"timeline");
    if(timeline.empty())h<<"<p class=\"card\">UTC 시각이 확정된 링크·SDK·앱 오류 기록이 없습니다."<<(d.value("sdk_utc_offset",Json(nullptr)).is_null()?" SDK 로그는 --log-utc-offset을 지정해야 타임라인에 표시됩니다.":"")<<"</p>";
    else {
        auto t0=*parse_iso_time(timeline.front()["time_utc"].get<std::string>()),t1=*parse_iso_time(timeline.back()["time_utc"].get<std::string>());if(t1<=t0)t1=t0+10000000;
        static const std::pair<const char*,int> lanes[]={{"link_down",0},{"link_up",0},{"sdk_error",1},{"sdk_timeout",1},{"sdk_connect",2},{"sdk_disconnect",2},{"sdk_reset",2},{"app_crash",3}};
        static const char* names[]={"NIC 링크","SDK 오류","카메라 연결","앱 오류"};
        h<<"<section class=\"card\"><svg class=\"timeline\" viewBox=\"0 0 1000 170\" role=\"img\" aria-label=\"링크·SDK·앱 오류 타임라인\">";
        for(int i=0;i<4;++i)h<<"<text x=\"0\" y=\""<<28+i*32<<"\" class=\"lane\">"<<names[i]<<"</text><line x1=\"110\" x2=\"990\" y1=\""<<24+i*32<<"\" y2=\""<<24+i*32<<"\" class=\"grid\"/>";
        for(const auto& e:timeline) {
            auto kind=string_value(e,"kind");int lane=-1;for(const auto& [k,l]:lanes)if(kind==k)lane=l;if(lane<0)continue;
            auto t=*parse_iso_time(e["time_utc"].get<std::string>());double x=110+880.0*double(t-t0)/double(t1-t0);
            h<<"<circle cx=\""<<x<<"\" cy=\""<<24+lane*32<<"\" r=\"5\" class=\"ev-"<<text(kind)<<"\"><title>"<<text(field(e,"time_utc")+" · "+event_label(kind)+" · "+field(e,"label"))<<"</title></circle>";
        }
        h<<"<text x=\"110\" y=\"160\" class=\"lane\">"<<text(iso_time(t0))<<"</text><text x=\"990\" y=\"160\" text-anchor=\"end\" class=\"lane\">"<<text(iso_time(t1))<<"</text></svg>"
         <<"<p class=\"legend\"><span class=\"dot ev-link_down\"></span>링크 분리 <span class=\"dot ev-link_up\"></span>링크 연결 <span class=\"dot ev-sdk_error\"></span>SDK 오류 <span class=\"dot ev-sdk_timeout\"></span>SDK timeout <span class=\"dot ev-sdk_disconnect\"></span>카메라 연결/해제 <span class=\"dot ev-sdk_reset\"></span>카메라 리셋 <span class=\"dot ev-app_crash\"></span>앱 오류 · 점에 마우스를 올리면 내용이 보입니다. 시각은 UTC입니다.</p>";
        h<<"<details><summary>타임라인 이벤트 목록 (최근 300개)</summary><div class=\"scroll\"><table><thead><tr><th>시각(UTC)</th><th>종류</th><th>내용</th><th>근거</th></tr></thead><tbody>";
        size_t start=timeline.size()>300?timeline.size()-300:0;
        for(size_t i=start;i<timeline.size();++i){const auto& e=timeline[i];h<<"<tr><td>"<<text(field(e,"time_utc"))<<"</td><td>"<<event_label(string_value(e,"kind"))<<"</td><td>"<<text(field(e,"label"))<<"</td><td>"<<text(field(e,"ref"))<<"</td></tr>";}
        h<<"</tbody></table></div></details>";if(d.value("timeline_truncated",false))h<<"<p class=\"muted\">이벤트가 많아 최근 기록만 표시합니다.</p>";
        h<<"</section>";
    }
    const auto& ai=obj(r,"ai_review");
    if(!ai.empty()) {
        auto link=[&](const Json& ids){std::string out;for(const auto& id:ids){auto it=first_finding.find(id.get<std::string>());out+=it==first_finding.end()?" <code>"+text(id.get<std::string>())+"</code>":" <a href=\"#f-"+std::to_string(it->second)+"\"><code>"+text(id.get<std::string>())+"</code></a>";}return out;};
        h<<"<h2 id=\"ai-review\">AI 심층 의견</h2><section class=\"card ai\"><p><span class=\"pill sev-unknown\">LLM 생성 · 검증 필요</span> "<<text(string_value(ai,"model"))<<" "<<text(string_value(ai,"generated_at"))
         <<"</p><p class=\"pre\">"<<text(field(ai,"summary"))<<"</p>";
        if(!arr(ai,"hypotheses").empty()){h<<"<h3>원인 가설</h3><ol>";for(const auto& x:arr(ai,"hypotheses"))h<<"<li><strong>"<<text(field(x,"title"))<<"</strong> <span class=\"badge\">신뢰도 "<<text(field(x,"confidence"))<<"</span>"<<link(arr(x,"finding_ids"))<<"<p class=\"pre\">"<<text(field(x,"reasoning"))<<"</p></li>";h<<"</ol>";}
        if(!arr(ai,"actions").empty()){h<<"<h3>권장 조치 순서</h3><ol>";for(const auto& x:arr(ai,"actions"))h<<"<li>[P"<<field(x,"priority")<<"] "<<text(field(x,"action"))<<link(arr(x,"finding_ids"))<<"</li>";h<<"</ol>";}
        if(!arr(ai,"additional_checks").empty()){h<<"<h3>추가 확인 항목</h3><ul>";for(const auto& x:arr(ai,"additional_checks"))h<<"<li>"<<text(str(x))<<"</li>";h<<"</ul>";}
        if(!arr(ai,"caveats").empty()){h<<"<h3>한계</h3><ul>";for(const auto& x:arr(ai,"caveats"))h<<"<li>"<<text(str(x))<<"</li>";h<<"</ul>";}
        h<<"<p class=\"muted\">tools/ai-review.ps1이 마스킹된 llm-context.json만 외부 LLM에 보내 생성한 의견입니다. 규칙 판정과 원본 근거를 우선하십시오.</p></section>";
    }
}
} // namespace
std::string analysis_html(const Json& r) {
    const auto& s=r.at("snapshot");const auto& net=module(s,"network");std::ostringstream h;
    h<<R"(<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-fnc-analyze'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>GigE Vision 진단 리포트</title><style>
body{font:15px/1.6 system-ui,sans-serif;color:#172635;background:#f3f6f9;margin:0}main{max-width:1280px;margin:auto;padding:28px}
h1{font-size:28px;margin-bottom:4px}h2{margin:32px 0 12px;font-size:21px}h3{margin-bottom:8px}p{margin:8px 0}.muted{color:#526576}
.card{background:white;border:1px solid #dbe4eb;border-radius:12px;padding:18px;margin:12px 0}.alert{border-left:5px solid #b35c00;background:#fff7e8}
.scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;vertical-align:top;padding:9px 12px;border-bottom:1px solid #e2e8ee;white-space:pre-wrap;overflow-wrap:anywhere}
th{background:#eaf0f5}td{min-width:70px;max-width:420px}.controls{position:sticky;top:0;background:#f3f6f9;padding:12px 0;z-index:1;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
input{padding:10px 14px;border:1px solid #abbaca;border-radius:8px;min-width:270px;font:inherit}button{padding:10px 16px;border:1px solid #abbaca;border-radius:8px;background:white;cursor:pointer}
details{margin:14px 0}summary{cursor:pointer;font-weight:600}nav a{color:#13598a;margin-right:15px}a{color:#13598a}small{color:#526576}
.nic-card{background:white;border:1px solid #dbe4eb;border-radius:12px;overflow:hidden;scroll-margin-top:100px}.nic-card>summary{padding:18px 22px;list-style:none;display:flex;align-items:center;gap:16px;flex-wrap:wrap;background:#f9fbfd}.nic-card>summary::-webkit-details-marker{display:none}.nic-card>summary:before{content:'+';font-size:22px;color:#13598a}.nic-card[open]>summary:before{content:'−'}.nic-title{font-size:19px}.nic-summary{font-weight:400;color:#526576;flex:1;min-width:230px}.nic-body{padding:8px 22px 22px}.nic-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px 28px}.nic-grid>section{min-width:0}.nic-body h3{font-size:16px;margin:20px 0 10px}.facts{display:grid;grid-template-columns:140px 1fr;gap:7px 12px;margin:12px 0}.facts dt{color:#526576}.facts dd{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}.badge{font-size:12px;white-space:nowrap;border-radius:20px;padding:3px 10px;background:#e8edf2;color:#46596a}.badge.up,.badge.enabled{background:#e1f3ec;color:#126749}.badge.disabled{background:#f0f2f4;color:#65717c}.addresses td:first-child,.ip-summary{font-family:Consolas,monospace;font-weight:600}.ip-summary{white-space:pre-line}.nic-empty{font-size:13px;color:#687b8b}.nic-group{margin-top:28px}.nic-group>summary{font-size:17px;padding:10px 0;border-bottom:1px solid #dbe4eb}.technical>summary{padding:12px;border-radius:8px;background:#eaf0f5}summary:focus-visible,a:focus-visible,button:focus-visible{outline:3px solid #227dbe;outline-offset:3px}[hidden]{display:none!important}
@media(max-width:780px){main{padding:14px}.nic-grid{grid-template-columns:1fr}.facts{grid-template-columns:110px 1fr}.nic-card>summary,.nic-body{padding:14px}.controls{position:static}input{min-width:180px}td,th{padding:8px}}
.addresses td:first-child{white-space:nowrap;min-width:115px}
.verdict{display:flex;gap:20px;align-items:center;border-left:8px solid var(--sev)}.verdict h2{margin:0}.light{width:64px;height:64px;border-radius:50%;background:var(--sev);color:white;font-size:32px;display:flex;align-items:center;justify-content:center;flex:none}.sev-critical{--sev:#c0392b}.sev-warning{--sev:#b35c00}.sev-unknown{--sev:#6b7785}.sev-info{--sev:#13598a}.sev-ok{--sev:#1e7d4f}.pill{display:inline-block;border-radius:20px;padding:2px 10px;font-size:12px;font-weight:600;color:white;background:var(--sev,#6b7785);margin-right:6px;white-space:nowrap}.counts .pill{font-size:14px}.finding{background:white;border:1px solid #dbe4eb;border-left:6px solid var(--sev);border-radius:10px;padding:14px 18px;margin:12px 0;scroll-margin-top:90px}.finding header{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.finding code{color:#526576;font-size:12px}.finding .facts{grid-template-columns:110px 1fr}.roles{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}.role{border:1px solid #dbe4eb;border-radius:10px;padding:12px}.role ul{margin:6px 0 0;padding-left:18px;font-size:13px}.role-camera{border-color:#1e7d4f}.bar{display:inline-block;width:80px;height:8px;background:#e8edf2;border-radius:4px;vertical-align:middle;overflow:hidden}.bar i{display:block;height:100%;background:var(--sev)}svg.timeline{width:100%;height:auto}svg .lane{font-size:12px;fill:#526576}svg .grid{stroke:#dbe4eb}circle,.dot{fill:#6b7785;background:#6b7785}.ev-link_down{fill:#c0392b;background:#c0392b}.ev-link_up{fill:#1e7d4f;background:#1e7d4f}.ev-sdk_error{fill:#b35c00;background:#b35c00}.ev-sdk_timeout{fill:#8e44ad;background:#8e44ad}.ev-sdk_connect,.ev-sdk_disconnect{fill:#13598a;background:#13598a}.ev-app_crash{fill:#000;background:#000}.ev-sdk_reset{fill:#e67e22;background:#e67e22}.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin:0 4px 0 10px}.legend{font-size:13px;color:#526576}.pre{white-space:pre-wrap}.ai{border-left:6px solid #6b7785}.stack{display:flex;height:16px;border-radius:8px;overflow:hidden;background:#e8edf2;margin:4px 0}.stack i{display:block;height:100%}.seg-reset{background:#e67e22}.seg-pc{background:#6b7785}.seg-nolog{background:#b8c4cf}.seg-unexplained{background:#c0392b}.conclusions li,.actions li{margin:10px 0}.synthesis{border-left:6px solid #13598a}.appendix>summary{font-size:20px;padding:14px;background:#eaf0f5;border-radius:10px}@media(max-width:780px){.verdict{flex-direction:column;align-items:flex-start}}
@media print{body{background:white}main{padding:0}.controls,nav{display:none}.scroll{overflow:visible}.card{break-inside:avoid}.nic-card{break-inside:auto}.nic-card>summary{break-after:avoid}.nic-grid{grid-template-columns:1fr}tr{break-inside:avoid}th{background:#eee}}
</style></head><body><main><h1>GigE Vision 진단 리포트</h1><p class="muted">FetchNetworkConfig )"<<FNC_VERSION<<" · 저장된 증거의 오프라인 분석</p>";
    auto text=[&](std::string_view t){return esc(t);};
    auto cell=[&](std::string v){if(v.empty())v="—";if(v.size()>4000){size_t end=4000;while(end&&(static_cast<unsigned char>(v[end])&0xc0)==0x80)--end;v.resize(end);v+=" … [발췌]";}h<<"<td>"<<text(v)<<"</td>";};
    auto table=[&](std::initializer_list<const char*> headings){h<<"<div class=\"scroll\"><table><thead><tr>";for(auto label:headings)h<<"<th scope=\"col\">"<<text(label)<<"</th>";h<<"</tr></thead><tbody>";};
    auto end_table=[&](){h<<"</tbody></table></div>";};
    auto row=[&](std::initializer_list<std::string> cells){h<<"<tr>";for(auto v:cells)cell(v);h<<"</tr>";};
    auto heading=[&](const char* id,const char* title){h<<"<h2 id=\""<<id<<"\">"<<text(title)<<"</h2>";};
    auto query_rows=[&](std::string_view mod,auto callback){for(const auto& q:arr(module(s,mod),"queries"))for(const auto& a:arr(q,"rows"))callback(a,q);};
    const auto& sys=module(s,"system");std::string os=field(obj(sys,"os"),"ProductName");
    const auto& wmi=arr(obj(sys,"operating_system_wmi"),"rows");if(!wmi.empty())os=field(wmi[0],"Caption");
    h<<"<section class=\"card\"><strong>"<<text(field(sys,"computer_name"))<<"</strong> · "<<text(os)<<" · 빌드 "<<text(field(obj(sys,"os"),"CurrentBuildNumber"))<<"."<<text(field(obj(sys,"os"),"UBR"))
     <<"<p>수집 시작(UTC): "<<text(field(s,"started_at_utc"))<<" / 종료: "<<text(field(s,"completed_at_utc"))<<"</p>"
     <<"<p>요청 이력(UTC): "<<text(field(obj(s,"inputs"),"from_utc"))<<" ~ "<<text(field(obj(s,"inputs"),"to_utc"))<<"</p>"
     <<"<p>무결성: manifest에 포함된 파일의 크기·SHA-256 검증 완료. ZIP 입력은 각 항목의 CRC도 검증했습니다. 해시는 전자서명이 아닙니다.</p></section>";
    size_t active=0,hardware=0,overlap_up=0,overlap_other=0;for(const auto& n:r.at("nics"))if(n["state"]=="Up"){++active;if(n.value("hardware_interface",false))++hardware;}
    for(const auto& o:r.at("overlaps")){if(o["both_up"].get<bool>())++overlap_up;else ++overlap_other;}
    h<<"<details class=\"card"<<(r.at("incomplete").get<bool>()?" alert":"")<<"\"><summary>수집·분석 범위 요약</summary><p>분석 상태: <strong>"<<(r.at("incomplete").get<bool>()?"누락/부분 수집 또는 제외된 증거 있음":"검증된 접근 가능 자료 분석 완료")
     <<"</strong></p><p>인터페이스 "<<field(r,"interface_count")<<"개 (필터 "<<field(r,"filter_count")<<"개), Up "<<active<<"개 / 그중 하드웨어 인터페이스 "<<hardware
     <<"개. 실제 물리 카드 개수와 다릅니다.</p><p>이벤트 "<<field(r,"event_count")<<"개, SetupAPI 섹션 "<<arr(r,"setupapi").size()<<"개.</p><p>서브넷 중복: Up NIC 간 "<<overlap_up<<"쌍 / 비활성 NIC가 포함된 "<<overlap_other<<"쌍.</p>";
    for(const auto& link:arr(r,"links"))h<<"<p>"<<text(field(link,"name"))<<": 링크 분리 "<<field(link,"down")<<"건 / 설정 "<<field(link,"up")<<"건 (보존된 선택 이력 기준).</p>";
    h<<"<p class=\"muted\">현재 설정, 과거 이력, 원인 추론은 구분합니다. 기록 없음은 변경 없음의 증거가 아닙니다. 카메라 검색·설정 조회·통신 검증은 수행하지 않았습니다.</p></details>";
    if(!arr(r,"notices").empty()){h<<"<details class=\"card alert\"><summary>누락 및 분석 제외 ("<<field(r,"notice_count")<<"건)</summary><ul>";for(const auto& n:r["notices"])h<<"<li>"<<text(str(n))<<"</li>";h<<"</ul><p>총 "<<field(r,"notice_count")<<"건, 최대 100건 표시.</p></details>";}
    if(!obj(r,"event_date_filter").empty()) {
        const auto& f=obj(r,"event_date_filter");h<<"<section class=\"card\"><h3>지정 날짜의 이벤트 추출</h3><p>"<<text(field(f,"date"))<<" · UTC"<<text(field(f,"utc_offset"))
         <<" 기준 00:00 이상, 다음 날 00:00 미만.</p><p>UTC 범위: "<<text(field(f,"from_utc"))<<" ≤ 시각 &lt; "<<text(field(f,"to_utc_exclusive"))
         <<"</p><p>원본의 유효 이벤트 "<<field(r,"source_event_count")<<"개 중 "<<field(r,"event_count")<<"개, SetupAPI "<<field(r,"source_setupapi_count")<<"개 중 "<<arr(r,"setupapi").size()
         <<"개 선택. 시각 미상 SetupAPI "<<field(r,"undated_setupapi_count")<<"개 제외.</p><p><a href=\"#selected-events\">추출 이벤트 목록 바로 보기</a> · <a href=\"selected-events.csv\" download>CSV 전체 추출</a> · <a href=\"selected-events.jsonl\" download>원본 XML 포함 JSONL</a></p>"
         <<"<p class=\"muted\">이력 집계에만 날짜를 적용했습니다. NIC/IP/필터/설정은 수집 시점의 현재 상태이며 지정 날짜 당시 상태를 복원한 결과가 아닙니다.</p></section>";
    }
    h<<R"(<nav><a href="#verdict">판정</a><a href="#synthesis">종합 분석</a><a href="#findings">문제</a><a href="#checklist">체크리스트</a><a href="#sdk-summary">SDK</a><a href="#timeline">타임라인</a><a href="#appendix">부록</a> | <a href="#nics">NIC</a><a href="#routes">경로</a><a href="#settings">고급 설정</a><a href="#drivers">드라이버·SDK</a><a href="#firewall">방화벽</a><a href="#history">이력</a><a href="#coverage">수집 범위</a></nav>
<div class="controls"><label for="search">검색</label><input id="search" type="search" placeholder="NIC 이름, IP, 필터, 설정 이름"><label><input id="problems" type="checkbox" style="min-width:0"> 문제 항목만 보기</label><label><input id="active" type="checkbox" style="min-width:0"> NIC에서 Up만 보기</label><button id="expand" type="button">NIC 펼치기</button><button id="collapse" type="button">NIC 접기</button><button id="print" type="button">인쇄 / PDF 저장</button><span id="matches" aria-live="polite"></span></div>)";
    diagnosis_sections(h,r);
    if(!obj(r,"event_date_filter").empty()) {
        heading("selected-events","지정 날짜의 이벤트 목록");table({"시각 (선택한 UTC offset)","구분 / 채널","Provider / ID / level","메시지","원본 파일:행"});size_t shown_events=0;
        for(const auto& a:arr(r,"selected_events")) {
            if(shown_events++>=1000)break;const auto& e=obj(a,"record");
            row({field(a,"time_selected"),field(a,"kind")+" / "+field(e,"channel"),field(e,"provider")+" / "+field(e,"event_id")+" / "+field(e,"level"),field(e,"message"),field(a,"source_file")+":"+field(a,"source_line")});
        }end_table();h<<"<p>시간순 최대 1,000개 표시. CSV/JSONL에는 선택된 전체 "<<arr(r,"selected_events").size()<<"개를 보존합니다. JSONL의 record에는 원래 XML과 원래 시각이 있습니다.</p>";
        if(arr(r,"selected_events").empty())h<<"<p class=\"muted\">저장된 자료에서 해당 날짜에 일치하는 유효 기록이 없습니다. 미보존·미수집 가능성이 있으며 해당 날짜에 이벤트가 없었다는 뜻으로 단정하지 않습니다.</p>";
    }
    h<<"<details class=\"appendix\" id=\"appendix\"><summary>부록 — 전체 원본 데이터 (NIC·경로·설정·드라이버·방화벽·이력·SDK·덤프·수집 범위)</summary>";
    auto group=[](const Json& n){if(n["state"]=="NotPresent")return 4;return n.value("hardware_interface",false)?(n["state"]=="Up"?0:1):(n["state"]=="Up"?2:3);};
    std::vector<const Json*> ordered;for(const auto& n:r["nics"])ordered.push_back(&n);
    std::sort(ordered.begin(),ordered.end(),[&](const Json* a,const Json* b){auto ga=group(*a),gb=group(*b);return ga!=gb?ga<gb:a->at("if_index").get<unsigned>()<b->at("if_index").get<unsigned>();});
    auto status_name=[](const Json& n){auto s=string_value(n,"state");return s=="Up"?"연결됨 (Up)":s=="Down"?"연결 끊김 (Down)":s=="NotPresent"?"장치 없음 (NotPresent)":s;};
    auto source_text=[](const Json& a){auto v=field(a,"Source");return v=="2"?"장치 조회 (2)":v=="3"?"저장 설정 (3)":"Source "+v;};
    auto bool_text=[](const Json& a,const char* key){if(!a.contains(key)||!a[key].is_boolean())return std::string("미수집");return std::string(a[key].get<bool>()?"활성 (true)":"비활성 (false)");};
    auto ip_summary=[&](const Json& n){std::string result;for(const auto& a:arr(n,"ipv4")){if(!result.empty())result+='\n';result+=field(a,"address")+"/"+field(a,"prefix_length")+" · "+assignment_text(a);}return result.empty()?"IPv4 기록 없음":result;};
    heading("nics","1. NIC별 IP 주소와 상세 구성");
    h<<"<p>NIC 이름을 누르면 IP·필터 드라이버·세부 설정을 함께 볼 수 있습니다. 연결된 하드웨어 NIC부터 표시합니다. 수동 169.254 주소를 DHCP 실패로 판정하지 않으며, 연결되지 않은 NIC의 주소도 수집 당시 기록을 그대로 표시합니다.</p>";
    auto overview=[&](bool up){table({"NIC","상태","장치","IPv4 주소 / 할당","IP MTU","활성 필터 / 전체","드라이버 버전"});
    for(const auto* p:ordered) {if((p->at("state")=="Up")!=up)continue;
        const auto& n=*p;const auto& d=obj(n,"details");auto filters=filter_counts(n);std::string version="미수집/미매핑";
        for(const auto& a:arr(d,"drivers")){version=field(a,"DriverVersion");break;}
        h<<"<tr data-nic=\"1\" data-up=\""<<(n["state"]=="Up"?"1":"0")<<"\"><td><a class=\"nic-link\" href=\"#nic-"<<field(n,"if_index")<<"\">"<<text(field(n,"friendly_name"))<<"</a></td>";
        for(auto v:{status_name(n),field(n,"description"),ip_summary(n),field(obj(n,"interface"),"mtu"),std::to_string(filters.enabled)+" / "+std::to_string(filters.total)+(filters.unknown?" · 미확인 "+std::to_string(filters.unknown):""),version})cell(v);h<<"</tr>";
    }end_table();};
    h<<"<h3>연결된 NIC 주소 요약</h3>";overview(true);
    h<<"<details><summary>연결되지 않았거나 현재 장치가 없는 NIC 주소 요약</summary>";overview(false);h<<"</details>";
    h<<"<p class=\"muted\">필터 개수는 해당 NIC의 Filter 바인딩 조회값입니다. 0/0 또는 미수집은 모듈의 수집 상태와 함께 확인하십시오.</p>";
    int last_group=-1;static const char* groups[]={"연결된 하드웨어 NIC","연결되지 않은 하드웨어 NIC","연결된 가상·소프트웨어 NIC","연결되지 않은 가상·소프트웨어 NIC","현재 장치가 없는 NIC"};
    for(const auto* p:ordered) {
        const auto& n=*p;const auto& i=obj(n,"interface");const auto& d=obj(n,"details");auto filters=filter_counts(n);auto g=group(n);
        if(g!=last_group){if(last_group!=-1)h<<"</details>";size_t count=0;for(const auto* candidate:ordered)if(group(*candidate)==g)++count;
            h<<"<details class=\"nic-group\""<<((g==0||g==2)?" open":"")<<"><summary>"<<groups[g]<<" ("<<count<<"개)</summary>";last_group=g;}
        h<<"<details class=\"nic-card\" id=\"nic-"<<field(n,"if_index")<<"\" data-up=\""<<(n["state"]=="Up"?"1":"0")<<"\""<<(g==0?" open":"")<<">"
         <<"<summary><span class=\"nic-title\">"<<text(field(n,"friendly_name"))<<"</span><span class=\"badge"<<(n["state"]=="Up"?" up":"")<<"\">"<<text(status_name(n))<<"</span>"
         <<"<span class=\"nic-summary\">"<<text(field(n,"description"))<<"<br><span class=\"ip-summary\">"<<text(ip_summary(n))<<"</span></span></summary><div class=\"nic-body\"><div class=\"nic-grid\"><section><h3>IP 주소</h3>";
        h<<"<div class=\"addresses\">";table({"IPv4 주소","Prefix / 서브넷 마스크","할당 방식"});
        for(const auto& a:arr(n,"ipv4"))row({field(a,"address"),"/"+field(a,"prefix_length")+" · "+mask_text(a),assignment_text(a)+(a.value("link_local",false)?" · Link-local 대역":"")});end_table();h<<"</div>";
        if(arr(n,"ipv4").empty())h<<"<p class=\"nic-empty\">IPv4 주소 기록이 없습니다.</p>";
        h<<"<dl class=\"facts\">";
        auto fact=[&](std::string label,std::string value){h<<"<dt>"<<text(label)<<"</dt><dd>"<<text(value.empty()?"기록 없음":value)<<"</dd>";};
        fact("DHCP IPv4",bool_text(n,"dhcp_v4_enabled"));fact("DHCP 서버",field(n,"dhcp_v4_server"));
        fact("기본 게이트웨이",list_text(n,"gateways"));fact("DNS 서버",list_text(n,"dns_servers"));fact("DNS suffix",field(n,"dns_suffix"));
        for(const auto& a:arr(d,"profiles"))fact("네트워크 프로필",field(a,"Name")+" / "+(field(a,"NetworkCategory")=="0"?"Public":field(a,"NetworkCategory")=="1"?"Private":field(a,"NetworkCategory")=="2"?"Domain":"미해석"));
        h<<"</dl><details><summary>IPv6 주소</summary>";table({"IPv6 주소","Prefix","할당 출처"});
        for(const auto& a:arr(n,"addresses"))if(string_value(a,"address").find(':')!=std::string::npos)row({field(a,"address"),"/"+field(a,"prefix_length"),assignment_text(a)});end_table();h<<"</details>";
        h<<"<h3>장치와 NIC 드라이버</h3><dl class=\"facts\">";
        fact("MAC 주소",field(n,"mac"));fact("인터페이스 번호",field(n,"if_index"));fact("장치 GUID",field(n,"adapter_name"));
        fact("링크 수신 / 송신",speed_text(i,"rx_link_bps")+" / "+speed_text(i,"tx_link_bps"));fact("IP MTU",field(i,"mtu")+" bytes");
        for(const auto& a:arr(d,"drivers")){fact("드라이버 버전",field(a,"DriverVersion"));fact("공급자 / INF",field(a,"DriverProviderName")+" / "+field(a,"InfName"));fact("드라이버 날짜",driver_date(a));}
        if(arr(d,"drivers").empty())fact("드라이버 버전","미수집/미매핑 — 전체 드라이버 목록 확인");
        h<<"</dl></section><section><h3>NIC 전원관리</h3>";
        if(arr(d,"power").empty())h<<"<p class=\"nic-empty\">NIC에 대응하는 전원관리 조회값이 없습니다. 미지원·누락·미매핑을 수집 상태와 원본에서 확인하십시오.</p>";
        for(const auto& a:arr(d,"power")) {
            h<<"<p class=\"muted\">"<<text(source_text(a))<<"</p>";table({"설정","조회값"});
            for(const auto& kv:std::initializer_list<std::pair<const char*,const char*>>{{"장치 전원 차단 허용","AllowComputerToTurnOffDevice"},{"Selective Suspend","SelectiveSuspend"},{"연결 해제 시 절전","DeviceSleepOnDisconnect"},{"Wake on Magic Packet","WakeOnMagicPacket"},{"Wake on Pattern","WakeOnPattern"},{"ARP offload","ArpOffload"},{"NS offload","NSOffload"},{"RSN rekey offload","RsnRekeyOffload"},{"D0 packet coalescing","D0PacketCoalescing"}})row({kv.first,power_value(a,kv.second)});
            end_table();if(!a.contains("AllowComputerToTurnOffDevice")||a["AllowComputerToTurnOffDevice"]!=2)h<<"<p class=\"muted\">전원 차단 허용이 Enabled가 아니므로 하위 전원 속성은 정의되지 않은 값일 수 있습니다.</p>";
        }
        h<<"<p class=\"muted\">Unsupported (0) = 미지원, Disabled (1) = 비활성, Enabled (2) = 활성. 현재 절전 중이라는 의미가 아닙니다.</p></section></div>";
        h<<"<h3>필터 드라이버 <span class=\"badge\">활성 "<<filters.enabled<<" / 전체 "<<filters.total<<(filters.unknown?" · 미확인 "+std::to_string(filters.unknown):"")<<"</span></h3>";
        table({"필터 드라이버","활성 여부","Component ID"});
        for(const auto& a:arr(d,"bindings"))if(string_value(a,"ComponentClassName")=="Filter") {
            auto enabled=boolean_value(a,"Enabled");h<<"<tr>";cell(field(a,"DisplayName"));h<<"<td><span class=\"badge "<<(!enabled?"unknown":*enabled?"enabled":"disabled")<<"\">"<<text(bool_text(a,"Enabled"))<<"</span></td>";cell(field(a,"ComponentID"));h<<"</tr>";
        }end_table();if(!filters.total)h<<"<p class=\"nic-empty\">매핑된 Filter 바인딩 기록이 없습니다.</p>";
        h<<"<details><summary>프로토콜·서비스를 포함한 모든 바인딩</summary>";table({"구성 요소","분류","활성 여부","Component ID"});
        for(const auto& a:arr(d,"bindings"))row({field(a,"DisplayName"),field(a,"ComponentClassName"),bool_text(a,"Enabled"),field(a,"ComponentID")});end_table();h<<"</details>";
        h<<"<h3>주요 NIC 세부 설정 — Jumbo·EEE·절전·버퍼</h3>";table({"설정 이름","표시값","원래 키","저장값","출처"});
        for(const auto& a:arr(d,"advanced"))if(core_setting(a))row({field(a,"DisplayName"),field(a,"DisplayValue"),field(a,"RegistryKeyword"),setting_value(a),source_text(a)});end_table();
        h<<"<p class=\"muted\">Jumbo Packet 드라이버 표시값과 IP MTU는 별도 값입니다. 저장값은 제조사 선택 코드일 수 있으며 적용 상태를 단정하지 않습니다.</p>";
        h<<"<details><summary>고급 설정 전체 ("<<arr(d,"advanced").size()<<"개)</summary>";table({"설정 이름","표시값","원래 키","저장값","출처"});
        for(const auto& a:arr(d,"advanced"))row({field(a,"DisplayName"),field(a,"DisplayValue"),field(a,"RegistryKeyword"),setting_value(a),source_text(a)});end_table();h<<"</details>";
        h<<"<details><summary>RSS·오프로드 세부 설정</summary>";table({"조회 종류","속성","조회값"});
        for(const auto& a:arr(d,"offload"))for(const auto& kv:a.items()) {
            if(kv.value().is_structured()||kv.value().is_null())continue;
            if(kv.key()=="evidence"||kv.key()=="Caption"||kv.key()=="Description"||kv.key()=="ElementName"||kv.key()=="InstanceID"||kv.key()=="InterfaceDescription"||kv.key()=="Name"||kv.key()=="SystemName")continue;
            auto query=string_value(a,"evidence");auto colon=query.rfind(':');if(colon!=std::string::npos)query.erase(0,colon+1);
            row({query,kv.key(),str(kv.value())});
        }end_table();h<<"<p class=\"muted\">수치형 enum은 원래 값입니다. 원본 snapshot에는 배열과 복합 속성도 보존됩니다.</p></details>";
        h<<"<details><summary>저장된 NIC 레지스트리 값·누적 카운터·조회 출처</summary>";table({"키","저장값","증거 경로"});
        for(const auto& a:arr(d,"saved_settings"))row({field(a,"RegistryKeyword"),field(a,"RegistryValue"),field(a,"evidence")});end_table();
        table({"누적 카운터","수집값"});for(const auto& kv:obj(i,"counters").items())row({kv.key(),str(kv.value())});end_table();
        h<<"<p class=\"muted\">IP/MAC/MTU: network.adapters / interfaces. 필터: bindings. 전원: power. 고급 설정: advanced. NIC 드라이버: drivers의 장치 GUID → PNPDeviceID → DeviceID 대응. 모듈의 조회 시각·오류는 수집 범위에서 확인할 수 있습니다.</p></details></div></details>";
    }
    if(last_group!=-1)h<<"</details>";
    h<<"<details><summary>서브넷 중복 상세 ("<<arr(r,"overlaps").size()<<"쌍)</summary>";table({"NIC A","NIC B","분류"});for(const auto& o:r["overlaps"])row({field(o,"a"),field(o,"b"),o.value("both_up",false)?"두 NIC 모두 Up":"비활성 NIC 포함 — 현재 경로 경쟁 근거 아님"});end_table();h<<"</details>";
    heading("routes","2. 경로 및 기존 Neighbor 캐시");h<<"<p>근거: snapshot.json → network.routes / neighbors. 캐시는 현재 장치 IP 또는 통신 성공을 검증한 결과가 아닙니다.</p>";
    h<<"<details class=\"technical\"><summary>전체 IPv4 경로와 Neighbor 캐시 펼치기</summary>";
    table({"목적지 / prefix","ifIndex","Next hop","경로 metric","NIC metric","합계"});
    for(const auto& a:arr(net,"routes")) {
        if(string_value(a,"destination").find(':')!=std::string::npos)continue;
        row({field(a,"destination")+"/"+field(a,"prefix_length"),field(a,"if_index"),field(a,"next_hop"),field(a,"route_metric"),field(a,"interface_metric"),
            a.contains("route_metric")&&a.contains("interface_metric")?std::to_string(a["route_metric"].get<uint64_t>()+a["interface_metric"].get<uint64_t>()):"미수집"});
    }end_table();h<<"<details><summary>Neighbor 캐시</summary>";table({"ifIndex","주소","MAC","상태(원시값)","Unreachable"});
    for(const auto& a:arr(net,"neighbors"))row({field(a,"if_index"),field(a,"address"),field(a,"mac"),field(a,"state"),field(a,"is_unreachable")});end_table();h<<"</details></details>";
    heading("settings","3. 필터·전원관리·고급 설정");
    h<<"<details class=\"technical\"><summary>전체 NIC 비교표와 NIC에 매핑되지 않은 설정 펼치기</summary>";
    h<<"<h3>Jumbo Packet 설정과 IP MTU</h3><p>근거: snapshot.json → advanced. 드라이버 표시값과 저장값을 그대로 기록합니다. 드라이버의 숫자 선택 코드(예: 2)를 바이트 수로 변환하지 않습니다. IP MTU는 별도 조회값이며 Jumbo 설정과 같은 단위·범위라는 뜻이 아닙니다.</p>";
    table({"NIC / 상태","장치","IP MTU (bytes)","설정 이름 / 키","드라이버 표시값","저장값","Source"});
    for(const auto& a:arr(obj(r,"nic_settings"),"advanced"))if(string_value(a,"category")=="Jumbo Packet")
        row({field(a,"Name")+" / "+field(a,"nic_state"),field(a,"InterfaceDescription"),field(a,"ip_mtu"),field(a,"DisplayName")+" / "+field(a,"RegistryKeyword"),field(a,"DisplayValue"),field(a,"RegistryValue"),field(a,"Source")});
    end_table();
    h<<"<h3>NIC 전원관리</h3>";
    table({"NIC","장치 전원 차단 허용","Selective Suspend","연결 해제 시 절전","Wake on Magic Packet","Wake on Pattern","Source"});
    query_rows("power",[&](const Json& a,const Json&){row({field(a,"Name"),power_value(a,"AllowComputerToTurnOffDevice"),power_value(a,"SelectiveSuspend"),power_value(a,"DeviceSleepOnDisconnect"),power_value(a,"WakeOnMagicPacket"),power_value(a,"WakeOnPattern"),field(a,"Source")});});end_table();
    h<<"<p>Source 2 = Device, 3 = Persistent storage. Unsupported(0)은 Disabled(1)과 다릅니다. 장치 전원 차단 허용이 Enabled가 아니면 하위 전원 속성은 정의되지 않은 값입니다. 이 표는 설정 조회이며 PC 또는 NIC가 현재 절전 중인지 측정한 결과가 아닙니다.</p>";
    h<<"<h3>드라이버의 절전·EEE·Wake 관련 고급 설정</h3><p>원래 키의 power/EEE/energy/suspend/sleep/wake/DMAC 등의 문자열로 선별했습니다. 제조사별 의미는 표시값을 우선 확인하고, 나머지 속성은 아래 전체 고급 속성 표에서 확인하십시오.</p>";
    table({"NIC / 상태","설정 이름","Registry keyword","드라이버 표시값","저장값","Source"});
    for(const auto& a:arr(obj(r,"nic_settings"),"advanced"))if(string_value(a,"category")=="전원·EEE·Wake")
        row({field(a,"Name")+" / "+field(a,"nic_state"),field(a,"DisplayName"),field(a,"RegistryKeyword"),field(a,"DisplayValue"),field(a,"RegistryValue"),field(a,"Source")});end_table();
    h<<"<details><summary>저장된 NIC 레지스트리의 Jumbo·절전 관련 값 (분리된 NIC 포함 가능)</summary><p>근거: snapshot.json → registry.keys. 장치 GUID로 매핑하며 현재 NIC가 없으면 미매핑으로 표시합니다. 저장된 값만으로 현재 적용 상태를 판정하지 않습니다.</p>";
    table({"NIC / 상태","장치 GUID","Registry keyword","저장값","레지스트리 형식","증거 경로"});
    for(const auto& a:arr(obj(r,"nic_settings"),"registry"))row({field(a,"Name")+" / "+field(a,"nic_state"),field(a,"InstanceID"),field(a,"RegistryKeyword"),field(a,"RegistryValue"),field(a,"registry_type"),field(a,"evidence")});end_table();h<<"</details>";
    h<<"<details><summary>전원관리의 나머지 속성</summary>";table({"NIC","ARP offload","NS offload","RSN rekey offload","D0 packet coalescing","Source"});
    query_rows("power",[&](const Json& a,const Json&){row({field(a,"Name"),power_value(a,"ArpOffload"),power_value(a,"NSOffload"),power_value(a,"RsnRekeyOffload"),power_value(a,"D0PacketCoalescing"),field(a,"Source")});});end_table();h<<"</details>";
    h<<"<p>값이 없거나 표가 비어 있으면 미지원·누락·조회 실패일 수 있습니다. 7절의 advanced / power / registry 수집 상태를 확인하십시오. 기능이 꺼졌다는 뜻으로 해석하지 않습니다.</p><h3>바인딩 / 필터</h3>";
    table({"NIC","Component ID","필터 이름","Enabled"});query_rows("bindings",[&](const Json& a,const Json&){if(string_value(a,"ComponentClassName")=="Filter"||string_value(a,"ComponentID")=="ms_tcpip"||string_value(a,"ComponentID")=="ms_tcpip6")row({field(a,"Name"),field(a,"ComponentID"),field(a,"DisplayName"),field(a,"Enabled")});});end_table();
    h<<"<p>여러 필터가 활성화됐다는 사실만으로 충돌이나 주소 변경을 단정하지 않습니다.</p>";
    h<<"<details><summary>고급 속성 원래 키·표시값·저장값</summary>";table({"NIC","Registry keyword","설정 이름","표시값","저장값","Source"});
    query_rows("advanced",[&](const Json& a,const Json&){row({field(a,"Name"),field(a,"RegistryKeyword"),field(a,"DisplayName"),field(a,"DisplayValue"),field(a,"RegistryValue"),field(a,"Source")});});end_table();h<<"</details>";
    h<<"<details><summary>오프로드 / RSS</summary>";table({"출처","NIC","관찰값"});query_rows("offload",[&](const Json& a,const Json& q){Json copy=a;for(auto key:{"_cim_types","Caption","InstanceID","SystemName","Description","ElementName"})copy.erase(key);row({field(q,"source"),field(a,"Name"),json_text(copy)});});end_table();h<<"</details>";
    h<<"</details>";
    heading("drivers","4. 드라이버와 설치된 영상 소프트웨어");
    table({"장치","버전","드라이버 날짜(원시값)","공급자","INF / Device ID"});query_rows("drivers",[&](const Json& a,const Json&){if(a.contains("DriverVersion"))row({field(a,"DeviceName"),field(a,"DriverVersion"),field(a,"DriverDate"),field(a,"DriverProviderName"),field(a,"InfName")+"\n"+field(a,"DeviceID")});});end_table();
    table({"설치 목록 이름","버전","보고된 설치일","Publisher","출처"});for(const auto& a:arr(module(s,"software"),"software"))row({field(a,"display_name"),field(a,"display_version"),field(a,"install_date_reported"),field(a,"publisher"),field(a,"registry_key")});end_table();
    h<<"<p>드라이버 날짜는 실제 설치일과 다릅니다. 설치 목록은 이름 검색 결과이므로 누락·과잉 매칭이 가능하며, 프로그램 실행 중 여부를 뜻하지 않습니다.</p>";
    heading("firewall","5. 네트워크 프로필과 방화벽");table({"NIC","프로필 이름","Category (0 Public / 1 Private / 2 Domain)","IPv4 connectivity (원시값)"});
    query_rows("bindings",[&](const Json& a,const Json&){if(a.contains("NetworkCategory"))row({field(a,"InterfaceAlias"),field(a,"Name"),field(a,"NetworkCategory"),field(a,"IPv4Connectivity")});});end_table();
    const auto& fw=module(s,"firewall");h<<"<p>근거: snapshot.json → firewall. 전체 규칙 "<<arr(fw,"rules").size()<<"개. 현재 프로필 비트 마스크: "<<field(fw,"current_profile_types")<<".</p>";
    table({"프로필 (1 Domain / 2 Private / 4 Public)","Enabled","기본 inbound (0 Block / 1 Allow)","기본 outbound","전체 inbound 차단"});
    for(const auto& a:arr(fw,"profiles"))row({field(a,"type"),field(a,"enabled"),field(a,"default_inbound_action"),field(a,"default_outbound_action"),field(a,"block_all_inbound")});end_table();
    h<<"<details><summary>영상 프로그램 관련 방화벽 규칙 (이름/경로 검색)</summary>";table({"규칙","실행 경로","Enabled","프로필 마스크","방향 / action","protocol"});
    for(const auto& a:arr(fw,"rules")) {
        auto searchable=lower(json_text(a));bool match=false;for(auto term:{"gige","genicam","sapera","balluff","matrox","teledyne","pylon","camera","galaxy","ebus"})if(searchable.find(term)!=std::string::npos)match=true;
        if(match)row({field(a,"name"),field(a,"application_name"),field(a,"enabled"),field(a,"profiles"),field(a,"direction")+" / "+field(a,"action"),field(a,"protocol")});
    }end_table();h<<"</details><p>프로필 마스크는 NIC별 프로필과 대조해야 합니다. 규칙 존재만으로 실제 패킷 허용·차단을 확정하지 않습니다.</p>";
    heading("history","6. 기존 이력 집계");h<<"<p>이벤트 시각은 원본의 UTC/local 값을 그대로 사용합니다. 증거 표시는 원본 JSONL 파일명:행 번호입니다. 시간 초과·보존 기간 제한이 있으면 전체 기간의 횟수가 아닙니다.</p>";
    table({"NIC","링크 분리","링크 설정","분리→설정 쌍","시각 간격 중앙값(초)"});for(const auto& a:arr(r,"links"))row({field(a,"name"),field(a,"down"),field(a,"up"),field(a,"pairs"),field(a,"median_s")});end_table();
    h<<"<p>링크 분류: e1rexpress/e2fnexpress의 ID 27(분리), 32(설정), aqnic650의 ID 14(분리). XML 장치명과 정확히 일치하는 NIC 설명이 하나일 때만 매핑합니다. 후보가 여러 개면 모호한 NIC로, 후보가 없으면 미매핑으로 표시합니다. 시각 간격은 실제 패킷 단절시간 측정값이 아닙니다.</p>";
    for(const auto& a:arr(r,"links")) {
        h<<"<details><summary>"<<text(field(a,"name"))<<" — 날짜별 링크 이력 및 증거</summary>";
        auto candidates=obj(r,"ambiguous_link_nics").find(field(a,"name"));
        if(candidates!=obj(r,"ambiguous_link_nics").end())h<<"<p>식별할 수 없는 NIC 후보: "<<text(str(*candidates))<<". 특정 포트의 이력으로 확정할 수 없습니다.</p>";
        table({"날짜(원본 local 기준)","분리","설정"});for(const auto& d:arr(a,"daily"))row({field(d,"day"),field(d,"down"),field(d,"up")});end_table();
        table({"원본 local 시각","동작","증거","메시지"});for(const auto& e:arr(a,"samples"))row({field(e,"time_local"),field(e,"action"),reference(e),field(e,"message")});end_table();h<<"<small>최대 6개 사례. 전체 횟수는 모든 유효 기록을 집계했습니다.</small></details>";
    }
    h<<"<details><summary>Provider / ID / 수준별 집계</summary>";table({"Provider","ID / level","건수","최초~최신(UTC)","최근 증거","메시지 예시"});size_t shown=0;
    for(const auto& a:arr(r,"event_groups")){if(shown++>=500)break;row({field(a,"provider"),field(a,"id")+" / "+field(a,"level"),field(a,"count"),field(a,"oldest")+"\n"+field(a,"newest"),reference(a.at("example")),field(a.at("example"),"message")});}end_table();h<<"<p>전체 그룹 "<<arr(r,"event_groups").size()<<"개 중 빈도순 최대 500개 표시. level 1 Critical / 2 Error / 3 Warning / 4 Information / 0 LogAlways.</p></details>";
    h<<"<details><summary>SetupAPI 기존 설치 이력</summary>";table({"원본 local 시각","작업","증거"});size_t sections=0;for(const auto& a:arr(r,"setupapi")){if(sections++>=500)break;row({field(a,"time_local"),field(a,"message"),reference(a)});}end_table();h<<"<p>최대 500개 표시. 장치 설치 기록이며 모든 설정 변경 이력이 아닙니다.</p></details>";
    heading("applications","애플리케이션 오류·응답 없음·WER 기록");
    h<<"<p>Windows 기록 "<<arr(r,"app_incidents").size()<<"개. Application Error와 WER는 각각 보존합니다. ReportID 또는 같은 앱·PID와 5분 이내 시각이 확인될 때만 연관 증거를 표시하며, 서로 다른 이벤트를 하나의 사고로 합산하지 않습니다.</p>";
    table({"시각(UTC)","Provider / ID","앱 / 버전","모듈 / 예외 코드","PID / ReportID","연관 기록","증거"});size_t app_shown=0;
    for(const auto& a:arr(r,"app_incidents")){if(app_shown++>=500)break;row({field(a,"time_utc"),field(a,"provider")+" / "+field(a,"event_id"),field(a,"app_name")+" / "+field(a,"app_version"),field(a,"module_name")+" / "+field(a,"exception_code"),field(a,"pid")+" / "+field(a,"report_id"),json_text(arr(a,"related_records")),reference(a)});}end_table();h<<"<p class=\"muted\">최대 500개 표시. 상세 경로와 원본 EventData는 이벤트 JSONL의 XML에서 확인할 수 있습니다.</p>";
    heading("sdk","SDK 로그의 세션과 통계");const auto& sdk=obj(r,"sdk");
    h<<"<p>SDK 구조화 기록 "<<field(r,"source_sdk_event_count")<<"개 / 날짜 선택에 포함된 기록 "<<field(r,"sdk_event_count")<<"개 / UTC 미확정 "<<field(r,"undated_sdk_count")<<"개. 원본 로그 오프셋: "<<text(field(sdk,"utc_offset"))<<". 세션과 버전 표는 전체 원본 범위입니다. 원본 로그마다 PID와 연결·취득 경계로 구분하며 다른 파일의 세션은 합치지 않습니다.</p>";
    table({"원본 파일 / PID","세션의 원래 시각 범위","설정·카메라 정보","ERROR / WARN","오류 유형","통계 / 근거 행"});size_t sdk_shown=0;
    for(const auto& a:arr(sdk,"sessions")){if(sdk_shown++>=500)break;row({field(a,"source_file")+" / "+field(a,"pid"),field(a,"first_timestamp")+" ~ "+field(a,"last_timestamp"),json_text(obj(a,"fields")),field(a,"error_count")+" / "+field(a,"warning_count"),json_text(obj(a,"families")),json_text(arr(a,"statistics"))});}end_table();
    table({"실행 중 SDK·GigE 버전","근거 파일:행"});for(const auto& a:arr(sdk,"versions"))row({json_text(obj(a,"fields")),field(a,"source_file")+":"+field(a,"source_line")});end_table();
    h<<"<p>ERROR 건수, 미지원 파라미터, 취득 중단 전환만으로 네트워크 장애나 크래시 원인을 확정하지 않습니다. 설치 목록·실행 중 SDK·덤프 모듈 버전은 서로 다른 관찰값입니다. 날짜 추출은 UTC를 확정한 SDK 기록만 포함하며 Windows 이벤트 건수와 별도로 집계합니다.</p>";
    h<<"<details><summary>SDK 구조화 이벤트와 원본 위치 (최대 500개)</summary>";table({"원래 시각 / UTC","종류 / 수준","PID / thread","원본 파일:행 / 바이트 위치","내용"});size_t sdk_rows=0;
    for(const auto& e:arr(sdk,"events")){if(sdk_rows++>=500)break;row({field(e,"original_timestamp")+" / "+field(e,"time_utc"),field(e,"kind")+" / "+field(e,"level"),field(e,"pid")+" / "+field(e,"thread_id"),field(e,"source_file")+":"+field(e,"source_line")+" / "+field(e,"source_byte_offset"),field(e,"message")});}end_table();h<<"</details>";
    heading("memory","물리 메모리 관찰값");const auto& memory=obj(sys,"physical_memory");
    table({"총 물리 메모리(bytes)","사용 가능(bytes)","부하(%)","관찰 시각(UTC)"});row({field(memory,"total_bytes"),field(memory,"available_bytes"),field(memory,"load_percent"),field(memory,"observed_at_utc")});end_table();
    table({"제조사","Part number","용량(bytes, 64비트)","보고 속도 / 구성 속도(MHz)","관찰 시각(UTC)"});for(const auto& a:arr(obj(sys,"memory_modules_wmi"),"rows"))row({field(a,"Manufacturer"),field(a,"PartNumber"),field(a,"Capacity"),field(a,"Speed")+" / "+field(a,"ConfiguredClockSpeed"),field(sys,"memory_modules_observed_at_utc")});end_table();
    heading("dumps","명시한 덤프의 메타데이터");h<<"<p>메타데이터만 읽었습니다. 스택과 장애 원인은 분석하지 않습니다. 예외 스트림이 없으면 예외 정보 없음으로 표시합니다. 원본을 선택 첨부한 경우 diagnostics.zip과 별도의 파일로 전달합니다.</p>";
    table({"원본 경로 / 크기(bytes)","생성 시각(UTC)","아키텍처 / OS build","플래그 / Full memory","예외 정보","근거"});
    for(const auto& a:arr(r,"dumps"))row({field(a,"source_path")+" / "+field(a,"source_size_bytes"),field(a,"created_at_utc"),field(a,"architecture_name")+" ("+field(a,"architecture")+") / "+field(a,"os_build"),field(a,"flags")+" / "+field(a,"includes_full_memory"),a.value("exception_stream_present",false)?json_text(obj(a,"exception")):"예외 정보 없음",field(a,"evidence_file")});end_table();
    h<<"<details><summary>덤프 모듈의 파일 버전 (실행 중 SDK 버전과 별도, 최대 500개 표시)</summary>";table({"메타데이터 파일","모듈 경로","파일 버전"});size_t dump_modules=0;for(const auto& a:arr(r,"dumps"))for(const auto& m:arr(a,"modules")){if(dump_modules++<500)row({field(a,"evidence_file"),field(m,"path"),field(m,"file_version")});}end_table();h<<"<p>전체 "<<dump_modules<<"개. 전체 목록은 각 메타데이터 JSON을 확인하십시오.</p></details>";
    table({"별도 첨부 파일","크기(bytes)","SHA-256"});for(const auto& a:arr(r,"external_attachments"))row({field(a,"name"),field(a,"size_bytes"),field(a,"sha256")});end_table();
    heading("coverage","7. 수집 상태와 증거 범위");table({"모듈","상태","관찰 시각(UTC)","채널 활성","가장 오래 보존된 시각(local)","누락/오류"});
    for(const auto& a:arr(s,"modules"))row({field(a,"task_id"),field(a,"status"),field(a,"observed_at_utc"),field(obj(a,"metadata"),"enabled"),field(obj(obj(a,"metadata"),"oldest_retained_event"),"time_local"),json_text(arr(a,"issues"))});end_table();
    table({"이벤트 파일","선택된 이벤트","원본 유효 이벤트","날짜 범위 외","제외 행","선택 시각 범위(UTC)"});for(const auto& a:arr(r,"event_channels"))row({field(a,"file"),field(a,"count"),field(a,"valid_source_count"),field(a,"outside_date"),field(a,"excluded"),field(a,"oldest")+"\n"+field(a,"newest")});end_table();
    h<<"<p>원본 snapshot에는 더 많은 속성과 원래 형식이 있습니다. SDK 로그는 인식한 MVSDK/CamClient 형식만 구조화합니다. 다른 사용자 로그와 SetupAPI 원문은 원본 증거로 확인하십시오. Security 변경 기록은 기존 감사 설정과 보존 기간에 따라 없을 수 있습니다.</p>"
     <<"<p>값 정의: <a href=\"https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_if_row2\" rel=\"noreferrer\">Microsoft NIC 상태</a> · <a href=\"https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/netadaptercimprov/msft-netadapterpowermanagementsettingdata\" rel=\"noreferrer\">전원관리 CIM</a>. 외부 자료는 링크를 눌렀을 때만 열립니다.</p>";
    h<<"</details>";
    h<<R"(<script nonce="fnc-analyze">
const search=document.getElementById('search'),active=document.getElementById('active'),problems=document.getElementById('problems'),appendix=document.getElementById('appendix');
const cards=Array.from(document.querySelectorAll('.nic-card'));
function filter(){const q=search.value.toLocaleLowerCase();if(q)document.querySelectorAll('details:not(.nic-card)').forEach(d=>d.open=true);let count=0,nics=0;
cards.forEach(card=>{const header=card.querySelector('summary').textContent.toLocaleLowerCase();const match=(!active.checked||card.dataset.up==='1')&&card.textContent.toLocaleLowerCase().includes(q);card.hidden=!match;if(match){nics++;if(q)card.open=true;}card.querySelectorAll('tbody tr').forEach(row=>{row.hidden=!!q&&!header.includes(q)&&!row.textContent.toLocaleLowerCase().includes(q);});});
document.querySelectorAll('tbody tr').forEach(row=>{if(row.closest('.nic-card')){if(!row.hidden&&!row.closest('.nic-card').hidden)count++;return;}const match=row.textContent.toLocaleLowerCase().includes(q)&&(!active.checked||!row.dataset.nic||row.dataset.up==='1');row.hidden=!match;if(match)count++;});
document.querySelectorAll('.nic-group').forEach(group=>group.hidden=!Array.from(group.querySelectorAll('.nic-card')).some(card=>!card.hidden));const only=problems.checked;document.querySelectorAll('.finding').forEach(f=>f.hidden=only&&!['critical','warning','unknown'].includes(f.dataset.sev));
document.querySelectorAll('tr[data-status]').forEach(row=>{if(only&&['ok','info'].includes(row.dataset.status))row.hidden=true;});
document.getElementById('matches').textContent='NIC '+nics+'개 / 표 '+count+'개 행 표시';}
function reveal(){const id=location.hash.slice(1);const target=id&&document.getElementById(id);if(target&&appendix.contains(target)){appendix.open=true;const group=target.closest('.nic-group');if(group)group.open=true;if(target.tagName==='DETAILS')target.open=true;target.scrollIntoView();}}
window.addEventListener('hashchange',reveal);reveal();problems.addEventListener('change',filter);
document.querySelectorAll('.nic-link').forEach(link=>link.addEventListener('click',()=>{const card=document.getElementById(link.getAttribute('href').slice(1));if(card){appendix.open=true;card.closest('.nic-group').open=true;card.open=true;}}));
document.getElementById('expand').addEventListener('click',()=>{appendix.open=true;cards.filter(c=>!c.hidden).forEach(c=>{c.closest('.nic-group').open=true;c.open=true;});});document.getElementById('collapse').addEventListener('click',()=>cards.forEach(c=>c.open=false));
search.addEventListener('input',filter);active.addEventListener('change',filter);document.getElementById('print').addEventListener('click',()=>{document.querySelectorAll('details').forEach(d=>d.open=true);window.print();});filter();
</script></main></body></html>)";
    auto html=h.str();need(html.size()<=20*1024*1024,"HTML report size limit exceeded.");return html;
}
} // namespace fnc
