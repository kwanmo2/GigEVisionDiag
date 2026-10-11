#include "common.hpp"
#include <bcrypt.h>
#include <charconv>
#include <cstdio>
#include <iomanip>
#include <sstream>
#include <iostream>

namespace fnc {
ComScope::ComScope() : hr(CoInitializeEx(nullptr, COINIT_MULTITHREADED)) {
    check_hr(hr, "CoInitializeEx");
    auto security = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
    if (security != RPC_E_TOO_LATE) check_hr(security, "CoInitializeSecurity");
}
ComScope::~ComScope() { if (SUCCEEDED(hr)) CoUninitialize(); }
std::string utf8(std::wstring_view s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    if (!n) fail_win("UTF-8 encode");
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n, nullptr, nullptr);
    return out;
}
std::wstring wide(std::string_view s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (!n) fail_win("UTF-8 decode");
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}
std::string lower(std::string s) {
    for (char& c : s) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
    return s;
}
std::string mac_text(const BYTE* bytes, size_t n) {
    std::ostringstream out;
    for (size_t i = 0; i < n; ++i) {
        if (i) out << ':';
        out << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(bytes[i]);
    }
    return out.str();
}
ULONGLONG now_ticks() { FILETIME t; GetSystemTimeAsFileTime(&t); return (ULONGLONG(t.dwHighDateTime) << 32) | t.dwLowDateTime; }
std::string iso_time(ULONGLONG ticks) {
    FILETIME f{static_cast<DWORD>(ticks), static_cast<DWORD>(ticks >> 32)};
    SYSTEMTIME s{};
    if (!FileTimeToSystemTime(&f, &s)) fail_win("FileTimeToSystemTime");
    char out[40];
    sprintf_s(out, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", s.wYear, s.wMonth, s.wDay,
        s.wHour, s.wMinute, s.wSecond, s.wMilliseconds);
    return out;
}
std::string utc_now() { return iso_time(now_ticks()); }
std::optional<ULONGLONG> parse_iso_time(std::string_view input) {
    // Required offset: YYYY-MM-DDTHH:MM:SS[.sss]Z or +/-HH:MM.
    std::string s(input);
    if (s.size() < 20 || s[4]!='-' || s[7]!='-' || s[10]!='T' || s[13]!=':' || s[16]!=':') return {};
    auto number = [&](size_t p, size_t n) -> int {
        int v = 0; auto r = std::from_chars(s.data()+p, s.data()+p+n, v);
        return r.ec == std::errc() && r.ptr == s.data()+p+n ? v : -1;
    };
    int y=number(0,4), mo=number(5,2), d=number(8,2), h=number(11,2), mi=number(14,2), sec=number(17,2);
    if (y<1601 || mo<1 || mo>12 || d<1 || d>31 || h<0 || h>23 || mi<0 || mi>59 || sec<0 || sec>59) return {};
    size_t p=19; int ms=0;
    if (s[p]=='.') {
        size_t begin=++p; while (p<s.size() && s[p]>='0' && s[p]<='9') ++p;
        if (p==begin || p-begin>7) return {};
        for (size_t i=0; i<3; ++i) ms=ms*10+(begin+i<p ? s[begin+i]-'0' : 0);
    }
    int offset=0;
    if (p<s.size() && s[p]=='Z' && p+1==s.size()) {}
    else if (p+6==s.size() && (s[p]=='+' || s[p]=='-') && s[p+3]==':') {
        int oh=number(p+1,2), om=number(p+4,2);
        if (oh<0 || oh>14 || om<0 || om>59 || (oh==14 && om)) return {};
        offset=(oh*60+om)*(s[p]=='+' ? 1 : -1);
    } else return {};
    SYSTEMTIME st{}; st.wYear=WORD(y); st.wMonth=WORD(mo); st.wDay=WORD(d);
    st.wHour=WORD(h); st.wMinute=WORD(mi); st.wSecond=WORD(sec); st.wMilliseconds=WORD(ms);
    FILETIME ft{};
    if (!SystemTimeToFileTime(&st,&ft)) return {};
    SYSTEMTIME round{}; FileTimeToSystemTime(&ft,&round);
    if (round.wDay!=st.wDay || round.wMonth!=st.wMonth) return {};
    auto t=(ULONGLONG(ft.dwHighDateTime)<<32)|ft.dwLowDateTime;
    auto delta=static_cast<LONGLONG>(offset)*60*10000000LL;
    if (delta>0 && t<static_cast<ULONGLONG>(delta)) return {};
    return static_cast<ULONGLONG>(static_cast<LONGLONG>(t)-delta);
}
std::string local_time(ULONGLONG ticks) {
    FILETIME ft{DWORD(ticks),DWORD(ticks>>32)}; SYSTEMTIME utc{}, local{};
    if (!FileTimeToSystemTime(&ft,&utc) || !SystemTimeToTzSpecificLocalTimeEx(nullptr,&utc,&local)) return {};
    FILETIME pretend{},rounded_utc{}; SystemTimeToFileTime(&local,&pretend);SystemTimeToFileTime(&utc,&rounded_utc);
    LONGLONG lt=static_cast<LONGLONG>((ULONGLONG(pretend.dwHighDateTime)<<32)|pretend.dwLowDateTime);
    auto ut=static_cast<LONGLONG>((ULONGLONG(rounded_utc.dwHighDateTime)<<32)|rounded_utc.dwLowDateTime);
    auto minutes=(lt-ut)/600000000LL;
    char out[48]; auto absmin=minutes<0 ? -minutes : minutes;
    sprintf_s(out,"%04u-%02u-%02uT%02u:%02u:%02u.%03u%c%02lld:%02lld",local.wYear,local.wMonth,local.wDay,
        local.wHour,local.wMinute,local.wSecond,local.wMilliseconds,minutes>=0?'+':'-',absmin/60,absmin%60);
    return out;
}
std::string win_error(DWORD code) {
    wchar_t* msg=nullptr;
    DWORD n=FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,code,0,reinterpret_cast<LPWSTR>(&msg),0,nullptr);
    std::string out=n ? utf8(std::wstring_view(msg,n)) : "Windows error";
    if (msg) LocalFree(msg);
    while (!out.empty() && (out.back()=='\r' || out.back()=='\n')) out.pop_back();
    return out+" ("+std::to_string(code)+")";
}
std::string error_status(DWORD code) {
    if(code==ERROR_ACCESS_DENIED||code==static_cast<DWORD>(E_ACCESSDENIED)||code==static_cast<DWORD>(WBEM_E_ACCESS_DENIED))return "access_denied";
    if(code==ERROR_FILE_NOT_FOUND||code==ERROR_PATH_NOT_FOUND||code==ERROR_EVT_CHANNEL_NOT_FOUND)return "missing";
    if(code==static_cast<DWORD>(WBEM_E_INVALID_CLASS)||code==static_cast<DWORD>(WBEM_E_INVALID_NAMESPACE))return "unsupported";
    return "error";
}
[[noreturn]] void fail_win(std::string_view operation,DWORD code) { throw WinError(std::string(operation)+": "+win_error(code),code); }
void check_hr(HRESULT hr,std::string_view op) { if (FAILED(hr)) fail_win(op,static_cast<DWORD>(hr)); }
bool elevated() { Handle token; HANDLE h=nullptr; if (!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&h)) fail_win("OpenProcessToken");
    token.reset(h); TOKEN_ELEVATION e{}; DWORD n=0; if (!GetTokenInformation(token.get(),TokenElevation,&e,sizeof(e),&n)) fail_win("TokenElevation"); return e.TokenIsElevated!=0; }
fs::path executable_path() { std::wstring buf(32768,L'\0'); DWORD n=GetModuleFileNameW(nullptr,buf.data(),DWORD(buf.size()));
    if (!n || n==buf.size()) fail_win("GetModuleFileNameW"); buf.resize(n); return buf; }

void ensure_local_path(const fs::path& input) {
    auto p=fs::absolute(input).lexically_normal(); auto s=p.native();
    if (s.size()<3 || s[1]!=L':' || s[2]!=L'\\' || s.find(L':',2)!=std::wstring::npos || s.find_first_of(L"*?")!=std::wstring::npos)
        throw std::runtime_error("Only ordinary local drive paths are allowed (no UNC, device paths or alternate streams).");
    UINT type=GetDriveTypeW(p.root_path().c_str());
    if (type!=DRIVE_FIXED && type!=DRIVE_REMOVABLE) throw std::runtime_error("Path must use a fixed or removable local drive.");
    // Reject junctions/symlinks anywhere in the ancestry, including mapped network redirection.
    fs::path part=p.root_path();
    for (const auto& element:p.relative_path()) {
        auto component=element.native();
        if(component.empty() || component.back()==L'.' || component.back()==L' ')
            throw std::runtime_error("Ambiguous Windows path component is not allowed.");
        auto stem=lower(utf8(component.substr(0,component.find(L'.'))));
        if(stem=="con"||stem=="prn"||stem=="aux"||stem=="nul"||stem=="conin$"||stem=="conout$" ||
            ((stem.starts_with("com")||stem.starts_with("lpt")) &&
             ((stem.size()==4&&stem[3]>='1'&&stem[3]<='9')||stem.substr(3)=="¹"||stem.substr(3)=="²"||stem.substr(3)=="³")))
            throw std::runtime_error("Windows device aliases are not allowed in local file paths.");
        part/=element; DWORD attr=GetFileAttributesW(part.c_str());
        if (attr!=INVALID_FILE_ATTRIBUTES && (attr&FILE_ATTRIBUTE_REPARSE_POINT))
            throw std::runtime_error("Reparse points (junctions/symlinks) are not allowed: "+utf8(part.native()));
    }
}
fs::path canonical_local_path(const fs::path& input) { ensure_local_path(input); return fs::absolute(input).lexically_normal(); }
Output::Output(fs::path root) : root_(canonical_local_path(root)) {
    DWORD attr=GetFileAttributesW(root_.c_str());
    if (attr==INVALID_FILE_ATTRIBUTES || !(attr&FILE_ATTRIBUTE_DIRECTORY)) throw std::runtime_error("Run output directory does not exist.");
    lock_.reset(CreateFileW(root_.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    if (!lock_) fail_win("Lock output directory");
    BY_HANDLE_FILE_INFORMATION info{}; if (!GetFileInformationByHandle(lock_.get(),&info)) fail_win("Inspect output directory");
    if (info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) throw std::runtime_error("Output directory must not be a reparse point.");
}
fs::path Output::create_run(const fs::path& parent,std::string_view prefix) {
    if(prefix!="FetchNetworkConfig-" && prefix!="FetchNetworkAnalysis-")throw std::runtime_error("Invalid run prefix.");
    auto base=canonical_local_path(parent);
    if (!fs::is_directory(base)) throw std::runtime_error("--output must be an existing local directory.");
    Output parent_lock(base);
    GUID g{}; check_hr(CoCreateGuid(&g),"CoCreateGuid"); wchar_t guid[40]{}; StringFromGUID2(g,guid,40);
    auto time=utc_now(); for (char& c:time) if (c==':' || c=='.') c='-';
    auto root=base/wide(std::string(prefix)+time+"-"+utf8(guid).substr(1,8));
    if (!CreateDirectoryW(root.c_str(),nullptr)) fail_win("Create run directory");
    return root;
}
fs::path Output::file(std::string_view name) const {
    if (name.empty() || name=="." || name==".." || name.find_first_of("/\\:< >|\"?*\r\n")!=std::string_view::npos || name.back()=='.')
        throw std::runtime_error("Invalid flat output filename.");
    if (name.front()=='.') throw std::runtime_error("Hidden/relative filenames are not allowed.");
    auto stem=lower(std::string(name.substr(0,name.find('.'))));
    if(stem=="con"||stem=="prn"||stem=="aux"||stem=="nul" ||
        (stem.size()==4 && (stem.starts_with("com")||stem.starts_with("lpt")) && stem[3]>='1'&&stem[3]<='9'))
        throw std::runtime_error("Reserved Windows device filenames are not allowed.");
    auto p=root_/wide(name); ensure_local_path(p); return p;
}
Handle Output::create(std::string_view name) const {
    auto p=file(name); Handle h(CreateFileW(p.c_str(),GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    if (!h) fail_win("Create output file"); return h;
}
void write_all(HANDLE h,std::string_view bytes) {
    while (!bytes.empty()) { DWORD written=0; DWORD n=DWORD((std::min)(bytes.size(),size_t(1024*1024)));
        if (!WriteFile(h,bytes.data(),n,&written,nullptr) || !written) fail_win("Write result"); bytes.remove_prefix(written); }
}
void console_text(std::string_view bytes,bool error) {
    std::cout.flush();std::cerr.flush();auto handle=GetStdHandle(error?STD_ERROR_HANDLE:STD_OUTPUT_HANDLE);DWORD mode=0;
    // Write Unicode directly; never change the customer's console code page or mode.
    if(GetConsoleMode(handle,&mode)) {
        auto text=wide(bytes);std::wstring_view remaining(text);
        while(!remaining.empty()) {DWORD count=0;auto n=DWORD((std::min)(remaining.size(),size_t(16384)));
            if(!WriteConsoleW(handle,remaining.data(),n,&count,nullptr)||!count)fail_win("Write console");remaining.remove_prefix(count);}
    } else write_all(handle,bytes);
}
void Output::write(std::string_view name,std::string_view bytes) const { auto h=create(name); write_all(h.get(),bytes); }
std::string read_local_file(const fs::path& file,size_t max_bytes) {
    ensure_local_path(file); Handle h(CreateFileW(file.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,nullptr)); if (!h) fail_win("Read local file");
    LARGE_INTEGER size{}; if (!GetFileSizeEx(h.get(),&size)) fail_win("GetFileSizeEx");
    if (size.QuadPart<0 || static_cast<ULONGLONG>(size.QuadPart)>max_bytes) throw std::runtime_error("Read size limit exceeded.");
    std::string out(static_cast<size_t>(size.QuadPart),'\0'); size_t offset=0;
    while (offset<out.size()) { DWORD n=0; if (!ReadFile(h.get(),out.data()+offset,DWORD((std::min)(out.size()-offset,size_t(1024*1024))),&n,nullptr)) fail_win("ReadFile"); if (!n) break; offset+=n; }
    out.resize(offset); return out;
}
std::string sha256(const fs::path& p) {
    ensure_local_path(p); Handle file(CreateFileW(p.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,nullptr));
    if (!file) fail_win("Hash file");
    BCRYPT_ALG_HANDLE alg=nullptr; BCRYPT_HASH_HANDLE hash=nullptr;
    auto check=[](NTSTATUS s){if(s<0) fail_win("SHA-256",static_cast<DWORD>(s));};
    check(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0));
    try {
        check(BCryptCreateHash(alg,&hash,nullptr,0,nullptr,0,0));
        std::vector<BYTE> buf(65536); DWORD n=0;
        while (true) { if (!ReadFile(file.get(),buf.data(),DWORD(buf.size()),&n,nullptr)) fail_win("Read hash input"); if(!n) break; check(BCryptHashData(hash,buf.data(),n,0)); }
        BYTE digest[32]; check(BCryptFinishHash(hash,digest,sizeof(digest),0));
        std::string out; char b[3]; for (auto x:digest) { sprintf_s(b,"%02x",x); out+=b; }
        BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(alg,0); return out;
    } catch (...) { if(hash) BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(alg,0); throw; }
}
std::string sha256_bytes(std::string_view bytes) {
    BCRYPT_ALG_HANDLE alg=nullptr; BCRYPT_HASH_HANDLE hash=nullptr;
    auto check=[](NTSTATUS s){if(s<0)fail_win("SHA-256 bytes",static_cast<DWORD>(s));};
    check(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0));
    try {
        check(BCryptCreateHash(alg,&hash,nullptr,0,nullptr,0,0));
        while(!bytes.empty()) {
            auto n=static_cast<ULONG>((std::min)(bytes.size(),size_t(65536)));
            check(BCryptHashData(hash,reinterpret_cast<PUCHAR>(const_cast<char*>(bytes.data())),n,0));bytes.remove_prefix(n);
        }
        BYTE digest[32];check(BCryptFinishHash(hash,digest,32,0));std::string out;char b[3];
        for(auto x:digest){sprintf_s(b,"%02x",x);out+=b;}
        BCryptDestroyHash(hash);BCryptCloseAlgorithmProvider(alg,0);return out;
    } catch(...) {if(hash)BCryptDestroyHash(hash);BCryptCloseAlgorithmProvider(alg,0);throw;}
}
std::string csv_cell(std::string_view s) {
    std::string out="\"";
    // Prevent formulas when the report is opened in spreadsheet applications.
    if (!s.empty() && (s.front()=='=' || s.front()=='+' || s.front()=='-' || s.front()=='@' || s.front()=='\t' || s.front()=='\r')) out+='\'';
    for(char c:s) { if(c=='\"') out+='\"'; out+=c; } out+='\"'; return out;
}
std::string json_text(const Json& j,int indent) { return j.dump(indent,' ',false,Json::error_handler_t::replace); }
Json result(std::string_view source,std::string_view status) { return Json{{"source",source},{"status",status},{"observed_at_utc",utc_now()},{"issues",Json::array()},{"artifacts",Json::array()}}; }
void issue(Json& r,std::string_view status,std::string_view reason,DWORD code) {
    if (r["status"]=="ok" || r["status"]=="empty") r["status"]=status;
    r["issues"].push_back(Json{{"reason",reason},{"error_code",code}});
}
int utc_offset_minutes(std::string_view v) {
    if(v.size()!=6||(v[0]!='+'&&v[0]!='-')||v[3]!=':')throw std::runtime_error("UTC offset requires +HH:MM or -HH:MM.");
    for(auto i:{1,2,4,5})if(v[i]<'0'||v[i]>'9')throw std::runtime_error("Invalid UTC offset.");
    int h=(v[1]-'0')*10+v[2]-'0',m=(v[4]-'0')*10+v[5]-'0';
    if(h>14||m>59||(h==14&&m))throw std::runtime_error("UTC offset must be within -14:00..+14:00.");
    return (h*60+m)*(v[0]=='-'?-1:1);
}
Options parse_options(const std::vector<std::wstring>& args) {
    Options o; o.output=executable_path().parent_path(); std::set<std::wstring> used;
    size_t first=!args.empty() && args[0]==L"collect" ? 1 : 0;
    for(size_t i=first;i<args.size();++i) {
        auto key=args[i]; if (key!=L"--output" && key!=L"--days" && key!=L"--incident-time" && key!=L"--camera-mac" && key!=L"--expected-camera-ip" && key!=L"--log-file" && key!=L"--dump-file" && key!=L"--app-name" && key!=L"--log-utc-offset" && key!=L"--attach-dumps" && key!=L"--include-evtx") throw std::runtime_error("Unknown option: "+utf8(key));
        if(key!=L"--log-file" && key!=L"--dump-file" && key!=L"--app-name" && !used.insert(key).second) throw std::runtime_error("Duplicate option: "+utf8(key));
        if(key==L"--attach-dumps"){o.attach_dumps=true;continue;}
        if(key==L"--include-evtx"){o.include_evtx=true;continue;}
        if(++i>=args.size() || args[i].empty() || args[i].starts_with(L"--")) throw std::runtime_error("Missing value: "+utf8(key));
        auto v=utf8(args[i]);
        if(key==L"--output") o.output=args[i];
        else if(key==L"--days") { unsigned n=0; auto r=std::from_chars(v.data(),v.data()+v.size(),n); if(r.ec!=std::errc() || r.ptr!=v.data()+v.size() || n<1 || n>3650) throw std::runtime_error("--days must be 1..3650."); o.days=n; }
        else if(key==L"--incident-time") { if(!parse_iso_time(v)) throw std::runtime_error("--incident-time requires ISO 8601 with a timezone, e.g. 2026-10-08T14:00:00+09:00."); o.incident=v; }
        else if(key==L"--camera-mac") { for(char& c:v) if(c=='-') c=':'; if(v.size()!=17) throw std::runtime_error("MAC must contain 6 hex octets.");
            for(size_t p=0;p<v.size();++p) if(p%3==2 ? v[p]!=':' : !isxdigit(static_cast<unsigned char>(v[p]))) throw std::runtime_error("Invalid MAC address."); o.camera_mac=lower(v); }
        else if(key==L"--expected-camera-ip") { IN_ADDR addr{}; auto w=wide(v); if(InetPtonW(AF_INET,w.c_str(),&addr)!=1) throw std::runtime_error("--expected-camera-ip must be a numeric IPv4 address."); o.expected_ip=v; }
        else if(key==L"--log-utc-offset"){utc_offset_minutes(v);o.log_utc_offset=v;}
        else if(key==L"--app-name") {v=lower(v);if(v.size()>240||!v.ends_with(".exe")||v.find_first_of("/\\:<>|\"?*\r\n")!=std::string::npos||std::any_of(v.begin(),v.end(),[](unsigned char c){return c<32;}))throw std::runtime_error("--app-name requires a pathless executable name, e.g. MVviewer.exe.");if(o.app_names.size()>=32)throw std::runtime_error("At most 32 app names are allowed.");o.app_names.push_back(v);}
        else if(key==L"--dump-file") {if(o.dump_files.size()>=kDumpCount)throw std::runtime_error("At most 8 --dump-file inputs are allowed.");if(lower(utf8(fs::path(args[i]).extension().native()))!=".dmp")throw std::runtime_error("--dump-file requires an existing .dmp file.");o.dump_files.emplace_back(args[i]);}
        else { if(o.log_files.size()>=kUserLogCount) throw std::runtime_error("At most 16 --log-file inputs are allowed."); o.log_files.emplace_back(args[i]); }
    }
    o.output=canonical_local_path(o.output);
    for(auto& p:o.log_files) p=canonical_local_path(p);
    for(auto& p:o.dump_files)p=canonical_local_path(p);
    if(o.attach_dumps&&o.dump_files.empty())throw std::runtime_error("--attach-dumps requires --dump-file.");
    return o;
}
} // namespace fnc
