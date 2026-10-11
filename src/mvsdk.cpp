#include "common.hpp"
#include <userenv.h>
#include <algorithm>

namespace fnc {
namespace {
constexpr size_t entry_limit=8192;
struct Candidate {fs::path path;uint64_t modified;};
struct FindHandle {
    HANDLE value;
    ~FindHandle(){if(value!=INVALID_HANDLE_VALUE)FindClose(value);}
};
template<class F> void entries(const fs::path& directory,size_t& scanned,F visit) {
    WIN32_FIND_DATAW data{};FindHandle search{FindFirstFileW((directory/L"*").c_str(),&data)};
    if(search.value==INVALID_HANDLE_VALUE){auto code=GetLastError();if(code==ERROR_FILE_NOT_FOUND)return;fail_win("Enumerate MVSDK directory",code);}
    do {
        if(std::wstring_view(data.cFileName)==L"."||std::wstring_view(data.cFileName)==L"..")continue;
        if(scanned>=entry_limit)return;
        ++scanned;visit(data);
    }while(FindNextFileW(search.value,&data));
    auto code=GetLastError();if(code!=ERROR_NO_MORE_FILES)fail_win("Enumerate MVSDK directory",code);
}
fs::path profile_root() {
    HANDLE raw=nullptr;if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw))fail_win("MVSDK profile token");Handle token(raw);
    DWORD length=0;GetUserProfileDirectoryW(token.get(),nullptr,&length);
    if(!length)fail_win("MVSDK profile directory size");
    std::vector<wchar_t> buffer(length);
    if(!GetUserProfileDirectoryW(token.get(),buffer.data(),&length))fail_win("MVSDK profile directory");
    return fs::path(buffer.data())/L"MVSDK";
}
} // namespace

Json copy_mvsdk_logs(const fs::path& root,const Output& output) {
    auto r=result("Existing MVSDK application logs");
    r["discovery"]={{"root",utf8(root.native())},{"scope","Immediate application subdirectories, *.log files only"},{"order","Last modification descending, path ascending on ties"},
        {"file_limit",kMvSdkLogCount},{"file_byte_limit",kUserLogBytes},{"total_byte_limit",kMvSdkLogBytes},{"entry_limit",entry_limit},{"scanned_entries",0},{"candidate_count",0},{"omitted_files",0},{"skipped_reparse_points",0}};
    r["coverage_note"]="Current process user's profile only. No date filtering, SDK loading or log settings changes. Original paths and application names are in the index; oversized text logs retain only their final bytes. Not an atomic snapshot.";
    r["files"]=Json::array();r["copied_bytes"]=0;
    try {
        auto base=canonical_local_path(root);auto attr=GetFileAttributesW(base.c_str());
        if(attr==INVALID_FILE_ATTRIBUTES)fail_win("Inspect MVSDK root");
        if(!(attr&FILE_ATTRIBUTE_DIRECTORY))throw std::runtime_error("MVSDK root must be a local directory.");
        std::vector<Candidate> candidates;size_t scanned=0,reparse=0;
        entries(base,scanned,[&](const WIN32_FIND_DATAW& app){
            if(app.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT){++reparse;return;}
            if(!(app.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY))return;
            auto directory=base/app.cFileName;
            try {
                ensure_local_path(directory);
                entries(directory,scanned,[&](const WIN32_FIND_DATAW& log){
                    if(log.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT){++reparse;return;}
                    if(log.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)return;
                    auto path=directory/log.cFileName;if(lower(utf8(path.extension().native()))!=".log")return;
                    candidates.push_back({path,(uint64_t(log.ftLastWriteTime.dwHighDateTime)<<32)|log.ftLastWriteTime.dwLowDateTime});
                });
            }catch(const WinError& e){issue(r,"partial",utf8(directory.native())+": "+e.what(),e.code);}
            catch(const std::exception& e){issue(r,"partial",utf8(directory.native())+": "+e.what());}
        });
        r["discovery"]["scanned_entries"]=scanned;r["discovery"]["candidate_count"]=candidates.size();r["discovery"]["skipped_reparse_points"]=reparse;
        if(scanned>=entry_limit)issue(r,"partial","MVSDK directory scan reached the entry limit; discovery is incomplete.");
        if(reparse)issue(r,"partial","MVSDK reparse points were skipped.");
        std::sort(candidates.begin(),candidates.end(),[](const Candidate& a,const Candidate& b){return a.modified!=b.modified?a.modified>b.modified:a.path.native()<b.path.native();});
        size_t total=0,attempted=0;
        for(const auto& candidate:candidates) {
            if(attempted>=kMvSdkLogCount||total>=kMvSdkLogBytes)break;
            auto name="mvsdk-log-"+std::to_string(++attempted)+".log";
            auto file=result("Existing MVSDK text log");file["artifact"]=name;file["application_name"]=utf8(candidate.path.parent_path().filename().native());
            file["relative_path"]=utf8(candidate.path.lexically_relative(base).native());file["file_metadata"]={{"path",utf8(candidate.path.native())}};
            try {
                auto copied=copy_text_log(candidate.path,name,output,(std::min)(kUserLogBytes,kMvSdkLogBytes-total));
                for(auto key:{"status","issues","artifacts","file_metadata"})file[key]=copied[key];
            }catch(const WinError& e){issue(file,error_status(e.code),e.what(),e.code);}
            catch(const std::exception& e){issue(file,"error",e.what());}
            // Preserve a partially written output even if copying failed before returning metadata.
            if(fs::exists(output.file(name))){r["artifacts"].push_back(name);total+=static_cast<size_t>(fs::file_size(output.file(name)));}
            if(file["status"]!="ok")issue(r,"partial",utf8(candidate.path.native())+": "+file["status"].get<std::string>());
            r["files"].push_back(std::move(file));
        }
        r["copied_bytes"]=total;r["discovery"]["omitted_files"]=candidates.size()-attempted;
        if(attempted<candidates.size())issue(r,"partial","MVSDK file count or total byte limit reached; older logs were omitted.");
        if(candidates.empty()&&r["status"]=="ok")r["status"]="empty";
        r["artifacts"].push_back("mvsdk-index.json");output.write("mvsdk-index.json",json_text(r,2)+"\n");
    }catch(const WinError& e){issue(r,error_status(e.code),e.what(),e.code);}
    catch(const std::exception& e){issue(r,"error",e.what());}
    return r;
}
Json collect_mvsdk_logs(const Output& output) {
    try {auto r=copy_mvsdk_logs(profile_root(),output);r["discovery"]["path_source"]="Current process token user profile";return r;}
    catch(const WinError& e){auto r=result("Existing MVSDK application logs");issue(r,error_status(e.code),e.what(),e.code);return r;}
    catch(const std::exception& e){auto r=result("Existing MVSDK application logs");issue(r,"error",e.what());return r;}
}
} // namespace fnc
