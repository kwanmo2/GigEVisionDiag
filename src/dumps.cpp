#include "common.hpp"
#include <dbghelp.h>
#include <miniz.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>

namespace fnc {
namespace {
constexpr uint64_t dump_limit=1ULL<<30, attachment_limit=2ULL<<30;
constexpr size_t metadata_limit=4*1024*1024, module_limit=4096;
uint64_t file_size(const BY_HANDLE_FILE_INFORMATION& i){return (uint64_t(i.nFileSizeHigh)<<32)|i.nFileSizeLow;}
uint64_t modified(const BY_HANDLE_FILE_INFORMATION& i){return (uint64_t(i.ftLastWriteTime.dwHighDateTime)<<32)|i.ftLastWriteTime.dwLowDateTime;}
Handle open_dump(const fs::path& path,BY_HANDLE_FILE_INFORMATION& info) {
    ensure_local_path(path);Handle h(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_SEQUENTIAL_SCAN,nullptr));if(!h)fail_win("Open existing dump");
    if(!GetFileInformationByHandle(h.get(),&info))fail_win("Dump metadata");
    if(GetFileType(h.get())!=FILE_TYPE_DISK||(info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)))throw std::runtime_error("Dump must be a regular local file.");
    if(file_size(info)>dump_limit)throw std::runtime_error("Dump exceeds 1 GiB input limit.");return h;
}
struct Reader {
    HANDLE file;uint64_t size;size_t bytes=0;
    void read(uint64_t offset,void* target,size_t count) {
        if(offset>size||count>size-offset||count>metadata_limit-bytes)throw std::runtime_error("Invalid dump range or metadata budget exceeded.");
        bytes+=count;LARGE_INTEGER p{};p.QuadPart=static_cast<LONGLONG>(offset);if(!SetFilePointerEx(file,p,nullptr,FILE_BEGIN))fail_win("Dump metadata offset");
        DWORD n=0;if(!ReadFile(file,target,DWORD(count),&n,nullptr)||n!=count)throw std::runtime_error("Truncated dump metadata.");
    }
    template<class T>T at(uint64_t offset){T value{};read(offset,&value,sizeof(value));return value;}
    std::string name(uint64_t offset) {
        if(!offset)return {};auto n=at<ULONG32>(offset);if(n>4096||n%2)throw std::runtime_error("Invalid dump module name length.");
        std::wstring value(n/2,L'\0');read(offset+4,value.data(),n);return utf8(value);
    }
};
std::string version(DWORD ms,DWORD ls){return std::to_string(HIWORD(ms))+"."+std::to_string(LOWORD(ms))+"."+std::to_string(HIWORD(ls))+"."+std::to_string(LOWORD(ls));}
size_t zip_write(void* opaque,mz_uint64 offset,const void* buffer,size_t size) {
    if(offset>MAXLONGLONG||size>MAXDWORD)return 0;LARGE_INTEGER p{};p.QuadPart=static_cast<LONGLONG>(offset);auto h=static_cast<HANDLE>(opaque);
    if(!SetFilePointerEx(h,p,nullptr,FILE_BEGIN))return 0;DWORD n=0;return WriteFile(h,buffer,DWORD(size),&n,nullptr)?n:0;
}
struct AttachmentSource {
    HANDLE file;uint64_t bytes=0,deadline;BCRYPT_ALG_HANDLE alg=nullptr;BCRYPT_HASH_HANDLE hash=nullptr;bool timed_out=false;
    AttachmentSource(HANDLE h,uint64_t end):file(h),deadline(end) {
        if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0)throw std::runtime_error("Dump SHA-256 provider failed.");
        if(BCryptCreateHash(alg,&hash,nullptr,0,nullptr,0,0)<0){BCryptCloseAlgorithmProvider(alg,0);alg=nullptr;throw std::runtime_error("Dump SHA-256 initialization failed.");}
    }
    ~AttachmentSource(){if(hash)BCryptDestroyHash(hash);if(alg)BCryptCloseAlgorithmProvider(alg,0);}
    std::string finish(){BYTE d[32];if(BCryptFinishHash(hash,d,sizeof(d),0)<0)throw std::runtime_error("Dump SHA-256 failed.");std::string s;char b[3];for(auto c:d){sprintf_s(b,"%02x",c);s+=b;}return s;}
};
size_t zip_read(void* opaque,mz_uint64 offset,void* buffer,size_t count) {
    auto& s=*static_cast<AttachmentSource*>(opaque);if(GetTickCount64()>=s.deadline){s.timed_out=true;return 0;}
    if(offset!=s.bytes||count>MAXDWORD)return 0;DWORD n=0;
    if(!ReadFile(s.file,buffer,DWORD(count),&n,nullptr))return 0;
    if(BCryptHashData(s.hash,static_cast<PUCHAR>(buffer),n,0)<0)return 0;s.bytes+=n;return n;
}
}
Json read_dump_metadata(const fs::path& path) {
    BY_HANDLE_FILE_INFORMATION before{},after{};auto h=open_dump(path,before);Reader reader{h.get(),file_size(before)};
    auto header=reader.at<MINIDUMP_HEADER>(0);
    if(header.Signature!=MINIDUMP_SIGNATURE||(header.Version&0xffff)!=MINIDUMP_VERSION||header.NumberOfStreams>4096)throw std::runtime_error("Invalid minidump header or stream count.");
    Json r={{"source_path",utf8(path.native())},{"source_size_bytes",file_size(before)},{"source_modified_utc",iso_time(modified(before))},
        {"created_at_utc",iso_time((uint64_t(header.TimeDateStamp)+11644473600ULL)*10000000ULL)},{"flags",header.Flags},{"includes_full_memory",(header.Flags&MiniDumpWithFullMemory)!=0},
        {"architecture",nullptr},{"os_build",nullptr},{"exception_stream_present",false},{"exception",nullptr},{"modules",Json::array()}};
    std::vector<MINIDUMP_DIRECTORY> streams(header.NumberOfStreams);reader.read(header.StreamDirectoryRva,streams.data(),streams.size()*sizeof(MINIDUMP_DIRECTORY));
    std::set<ULONG32> seen;
    for(const auto& stream:streams) {
        if(stream.Location.Rva>reader.size||stream.Location.DataSize>reader.size-stream.Location.Rva)throw std::runtime_error("Dump stream outside source bounds.");
        if(stream.StreamType!=SystemInfoStream&&stream.StreamType!=ModuleListStream&&stream.StreamType!=ExceptionStream)continue;
        if(!seen.insert(stream.StreamType).second)throw std::runtime_error("Duplicate minidump metadata stream.");
        auto at=stream.Location.Rva;
        if(stream.StreamType==SystemInfoStream) {
            if(stream.Location.DataSize<sizeof(MINIDUMP_SYSTEM_INFO))throw std::runtime_error("Truncated system-info stream.");auto s=reader.at<MINIDUMP_SYSTEM_INFO>(at);
            r["architecture"]=s.ProcessorArchitecture;r["processor_count"]=s.NumberOfProcessors;r["os_build"]=s.BuildNumber;r["os_major"]=s.MajorVersion;r["os_minor"]=s.MinorVersion;
            r["architecture_name"]=s.ProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64?"x64":s.ProcessorArchitecture==PROCESSOR_ARCHITECTURE_INTEL?"x86":s.ProcessorArchitecture==PROCESSOR_ARCHITECTURE_ARM64?"ARM64":"Unknown";
        } else if(stream.StreamType==ExceptionStream) {
            if(stream.Location.DataSize<sizeof(MINIDUMP_EXCEPTION_STREAM))throw std::runtime_error("Truncated exception stream.");auto s=reader.at<MINIDUMP_EXCEPTION_STREAM>(at);
            if(s.ExceptionRecord.NumberParameters>EXCEPTION_MAXIMUM_PARAMETERS)throw std::runtime_error("Invalid exception parameter count.");
            r["exception_stream_present"]=true;r["exception"]={{"thread_id",s.ThreadId},{"code",s.ExceptionRecord.ExceptionCode},{"address",s.ExceptionRecord.ExceptionAddress}};
        } else {
            if(stream.Location.DataSize<4)throw std::runtime_error("Truncated module-list stream.");auto count=reader.at<ULONG32>(at);
            if(count>module_limit||uint64_t(count)*sizeof(MINIDUMP_MODULE)+4>stream.Location.DataSize)throw std::runtime_error("Invalid module count or module-list range.");
            for(ULONG32 i=0;i<count;++i){auto m=reader.at<MINIDUMP_MODULE>(uint64_t(at)+4+uint64_t(i)*sizeof(MINIDUMP_MODULE));r["modules"].push_back({{"path",reader.name(m.ModuleNameRva)},
                {"base_address",m.BaseOfImage},{"size_bytes",m.SizeOfImage},{"file_version",m.VersionInfo.dwSignature==0xfeef04bd?Json(version(m.VersionInfo.dwFileVersionMS,m.VersionInfo.dwFileVersionLS)):Json(nullptr)}});}
        }
    }
    if(!GetFileInformationByHandle(h.get(),&after))fail_win("Dump final metadata");r["changed_during_read"]=file_size(before)!=file_size(after)||modified(before)!=modified(after);
    r["metadata_bytes_read"]=reader.bytes;r["exception_note"]=r["exception_stream_present"]==true?"Exception metadata present; no stack or cause analysis was performed.":"예외 정보 없음";return r;
}
Json collect_dump(size_t index,const Json& input,const Output& output) {
    auto r=result("Explicit dump metadata");auto meta=read_dump_metadata(fs::path(wide(input.at("dump_files").at(index).get<std::string>())));
    auto name="dump-"+std::to_string(index+1)+"-metadata.json";output.write(name,json_text(meta,2)+"\n");r["metadata"]=meta;r["artifacts"].push_back(name);
    if(meta["changed_during_read"]==true)issue(r,"partial","Dump source changed during metadata read.");return r;
}
Json attach_dumps(const Json& input,const Output& output,DWORD timeout_ms) {
    auto r=result("Opt-in original dump attachment");r["task_id"]="dump-attachments";r["title"]="Original dump attachments";
    auto deadline=GetTickCount64()+timeout_ms;Json entries=Json::array();uint64_t total=0;
    // Validate every requested source before creating the optional archive.
    for(const auto& p:input.at("dump_files")){BY_HANDLE_FILE_INFORMATION info{};auto h=open_dump(fs::path(wide(p.get<std::string>())),info);if(file_size(info)>attachment_limit-total)throw std::runtime_error("Dump attachment total exceeds 2 GiB.");total+=file_size(info);}
    auto file=output.create("dump-attachments.zip");mz_zip_archive zip{};zip.m_pWrite=zip_write;zip.m_pIO_opaque=file.get();
    if(!mz_zip_writer_init(&zip,0))throw std::runtime_error("Cannot initialize attachment ZIP.");
    try {
        size_t i=0;for(const auto& p:input.at("dump_files")) {
            BY_HANDLE_FILE_INFORMATION before{},after{};auto path=fs::path(wide(p.get<std::string>()));auto h=open_dump(path,before);auto name="dump-"+std::to_string(++i)+".dmp";
            if(input.contains("dump_metadata")&&input["dump_metadata"].size()>=i){const auto& m=input["dump_metadata"][i-1];if(m.is_null()||m.value("changed_during_read",true)||m.at("source_size_bytes").get<uint64_t>()!=file_size(before)||m.at("source_modified_utc").get<std::string>()!=iso_time(modified(before)))throw std::runtime_error("Dump changed since metadata collection or metadata is unavailable.");}
            AttachmentSource source(h.get(),deadline);
            if(!mz_zip_writer_add_read_buf_callback(&zip,name.c_str(),zip_read,&source,file_size(before),nullptr,nullptr,0,MZ_BEST_SPEED,nullptr,0,nullptr,0))throw std::runtime_error(source.timed_out?"Dump attachment five-minute budget exhausted.":"Dump attachment ZIP read failed.");
            if(!GetFileInformationByHandle(h.get(),&after)||file_size(before)!=file_size(after)||modified(before)!=modified(after)||source.bytes!=file_size(before))throw std::runtime_error("Dump changed during attachment read.");
            entries.push_back({{"name",name},{"source_path",p},{"size_bytes",source.bytes},{"sha256",source.finish()},{"source_modified_utc",iso_time(modified(before))}});
        }
        auto manifest=json_text(Json{{"schema_version",1},{"files",entries},{"note","Explicit original dump attachments; separate from diagnostics.zip."}},2)+"\n";
        if(GetTickCount64()>=deadline)throw std::runtime_error("Dump attachment five-minute budget exhausted.");
        if(!mz_zip_writer_add_mem(&zip,"manifest.json",manifest.data(),manifest.size(),MZ_BEST_SPEED)||!mz_zip_writer_finalize_archive(&zip))throw std::runtime_error("Dump attachment ZIP finalization failed.");
        mz_zip_writer_end(&zip);file.reset();auto digest=sha256(output.file("dump-attachments.zip"));if(GetTickCount64()>=deadline)throw std::runtime_error("Dump attachment five-minute budget exhausted.");
        output.write("dump-attachments.zip.sha256",digest+"  dump-attachments.zip\r\n");r["external_attachment"]={{"name","dump-attachments.zip"},{"size_bytes",fs::file_size(output.file("dump-attachments.zip"))},{"sha256",digest},{"files",entries}};
    }catch(...){if(zip.m_pState)mz_zip_writer_end(&zip);throw;}return r;
}
}
