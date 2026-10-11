#include "common.hpp"
#include <algorithm>
#include <array>

namespace fnc {
namespace {
constexpr wchar_t registry_key[]=L"SOFTWARE\\Teledyne DALSA\\Sapera Log Server";
fs::path sapera_path(Json& discovery) {
    discovery["registry_key"]="HKLM\\SOFTWARE\\Teledyne DALSA\\Sapera Log Server";
    discovery["registry_value"]="LogFile";
    for(auto view:{KEY_WOW64_64KEY,KEY_WOW64_32KEY}) {
        // RegGetValue expands REG_EXPAND_SZ and only accepts string values.
        std::array<wchar_t,32768> value{};DWORD bytes=DWORD(sizeof(value));
        auto flags=RRF_RT_REG_SZ|RRF_RT_REG_EXPAND_SZ|
            (view==KEY_WOW64_64KEY?RRF_SUBKEY_WOW6464KEY:RRF_SUBKEY_WOW6432KEY);
        auto code=RegGetValueW(HKEY_LOCAL_MACHINE,registry_key,L"LogFile",flags,nullptr,value.data(),&bytes);
        if(code==ERROR_FILE_NOT_FOUND||code==ERROR_PATH_NOT_FOUND)continue;
        if(code!=ERROR_SUCCESS)fail_win("Read Sapera LogFile registry value",code);
        if(!value[0])throw std::runtime_error("Sapera LogFile registry value is empty.");
        discovery["path_source"]="registry";discovery["registry_view_bits"]=view==KEY_WOW64_64KEY?64:32;
        if(!fs::path(value.data()).is_absolute())throw std::runtime_error("Sapera LogFile must be an absolute local path.");
        return canonical_local_path(fs::path(value.data()));
    }
    wchar_t windows[32768]{};auto n=GetWindowsDirectoryW(windows,DWORD(std::size(windows)));
    if(!n||n>=std::size(windows))fail_win("Windows directory");
    discovery["path_source"]="default";
    return canonical_local_path(fs::path(windows)/L"System32"/L"Logs.dat");
}
uint64_t size_of(const BY_HANDLE_FILE_INFORMATION& info) {
    return (uint64_t(info.nFileSizeHigh)<<32)|info.nFileSizeLow;
}
uint64_t modified(const BY_HANDLE_FILE_INFORMATION& info) {
    return (uint64_t(info.ftLastWriteTime.dwHighDateTime)<<32)|info.ftLastWriteTime.dwLowDateTime;
}
} // namespace

Json copy_sapera_log(const fs::path& path,const Output& output) {
    auto r=result("Existing Sapera Log Server file");
    r["coverage_note"]="Opaque original bytes for Sapera Log Viewer; no SDK loading or date filtering. The service is not stopped; this is not an atomic snapshot.";
    r["file_metadata"]={{"path",utf8(path.native())},{"byte_limit",kSaperaLogBytes}};
    try {
        ensure_local_path(path);
        Handle source(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            nullptr,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
        if(!source)fail_win("Open existing Sapera log");
        BY_HANDLE_FILE_INFORMATION before{},after{};
        if(!GetFileInformationByHandle(source.get(),&before))fail_win("Sapera log metadata");
        if(GetFileType(source.get())!=FILE_TYPE_DISK||before.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))
            throw std::runtime_error("Sapera log must be a regular local file without reparse points.");
        auto size=size_of(before);auto& meta=r["file_metadata"];
        meta["source_size_before"]=size;meta["source_modified_before_utc"]=iso_time(modified(before));
        meta["copied_offset_bytes"]=0;meta["copied_bytes"]=0;meta["tail_only"]=false;
        if(size>kSaperaLogBytes) {
            issue(r,"not_collected","Sapera log exceeds 64 MiB; no truncated binary file was created.");return r;
        }
        auto target=output.create("sapera-Logs.dat");r["artifacts"].push_back("sapera-Logs.dat");
        std::array<char,65536> buffer{};uint64_t copied=0;
        while(copied<size) {
            DWORD n=0;if(!ReadFile(source.get(),buffer.data(),DWORD((std::min)(uint64_t(buffer.size()),size-copied)),&n,nullptr))fail_win("Read existing Sapera log");
            if(!n)break;write_all(target.get(),std::string_view(buffer.data(),n));copied+=n;meta["copied_bytes"]=copied;
        }
        if(!GetFileInformationByHandle(source.get(),&after))fail_win("Sapera log final metadata");
        bool changed=size!=size_of(after)||modified(before)!=modified(after)||copied!=size;
        meta["source_size_after"]=size_of(after);meta["source_modified_after_utc"]=iso_time(modified(after));meta["changed_during_read"]=changed;
        if(changed)issue(r,"partial","Sapera log changed during read; the copy may contain concurrent writes or be incomplete.");
    }catch(const WinError& e){issue(r,error_status(e.code),e.what(),e.code);}
    catch(const std::exception& e){issue(r,"error",e.what());}
    return r;
}

Json collect_sapera_log(const Output& output) {
    auto r=result("Existing Sapera Log Server file");Json discovery=Json::object();
    try {auto path=sapera_path(discovery);r=copy_sapera_log(path,output);}
    catch(const WinError& e){issue(r,error_status(e.code),e.what(),e.code);}
    catch(const std::exception& e){issue(r,"error",e.what());}
    r["discovery"]=discovery;return r;
}
} // namespace fnc
