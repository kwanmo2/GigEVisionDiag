#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <wbemidl.h>
#include <winevt.h>
#include <wrl/client.h>
#include <json.hpp>
#include <filesystem>
#include <functional>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <set>
#include <string>
#include <vector>

namespace fnc {
using Json = nlohmann::json;
using Microsoft::WRL::ComPtr;
namespace fs = std::filesystem;
constexpr size_t kMaxWorkerBytes = 24 * 1024 * 1024;
constexpr size_t kEventBytes = 16 * 1024 * 1024;
constexpr size_t kEventCount = 10000;
constexpr size_t kUserLogBytes = 16 * 1024 * 1024;
constexpr size_t kUserLogCount = 16;
constexpr size_t kSaperaLogBytes = 64 * 1024 * 1024;
constexpr size_t kSetupSectionCount = 20000;
constexpr size_t kDumpCount = 8;

class Handle {
    HANDLE h_ = INVALID_HANDLE_VALUE;
public:
    Handle() = default;
    explicit Handle(HANDLE h) : h_(h) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& x) noexcept : h_(x.release()) {}
    Handle& operator=(Handle&& x) noexcept { reset(x.release()); return *this; }
    HANDLE get() const { return h_; }
    HANDLE release() { auto h = h_; h_ = INVALID_HANDLE_VALUE; return h; }
    explicit operator bool() const { return h_ != INVALID_HANDLE_VALUE && h_ != nullptr; }
    void reset(HANDLE h = INVALID_HANDLE_VALUE) { if (*this) CloseHandle(h_); h_ = h; }
};
struct EventHandle {
    EVT_HANDLE value = nullptr;
    explicit EventHandle(EVT_HANDLE h = nullptr) : value(h) {}
    ~EventHandle() { if (value) EvtClose(value); }
    EventHandle(const EventHandle&) = delete;
    EventHandle& operator=(const EventHandle&) = delete;
};
struct ComScope {
    HRESULT hr;
    ComScope();
    ~ComScope();
};
struct Options {
    fs::path output;
    unsigned days = 30;
    std::optional<std::string> incident;
    std::optional<std::string> camera_mac;
    std::optional<std::string> expected_ip;
    std::vector<fs::path> log_files;
    std::vector<fs::path> dump_files;
    std::vector<std::string> app_names;
    std::optional<std::string> log_utc_offset;
    bool attach_dumps = false, include_evtx = false;
};
Options parse_options(const std::vector<std::wstring>& args);
std::string utf8(std::wstring_view s);
std::wstring wide(std::string_view s);
std::string lower(std::string s);
std::string mac_text(const BYTE* bytes, size_t n);
std::string utc_now();
std::string iso_time(ULONGLONG filetime);
ULONGLONG now_ticks();
std::optional<ULONGLONG> parse_iso_time(std::string_view input);
std::string local_time(ULONGLONG ticks);
std::string win_error(DWORD code);
struct WinError : std::runtime_error {
    DWORD code;
    WinError(std::string message, DWORD value) : std::runtime_error(std::move(message)), code(value) {}
};
std::string error_status(DWORD code);
[[noreturn]] void fail_win(std::string_view operation, DWORD code = GetLastError());
void check_hr(HRESULT hr, std::string_view operation);
bool elevated();
fs::path executable_path();
void ensure_local_path(const fs::path& p);
fs::path canonical_local_path(const fs::path& p);
std::string sha256(const fs::path& p);
std::string sha256_bytes(std::string_view bytes);
std::string csv_cell(std::string_view s);
std::string json_text(const Json& j, int indent = -1);

// All application-owned writes pass through this flat, existing run directory.
// Its open handle denies rename/delete while the application is running.
class Output {
    fs::path root_;
    Handle lock_;
public:
    explicit Output(fs::path existing_root);
    static fs::path create_run(const fs::path& parent, std::string_view prefix = "FetchNetworkConfig-");
    const fs::path& root() const { return root_; }
    fs::path file(std::string_view name) const;
    Handle create(std::string_view name) const;
    void write(std::string_view name, std::string_view bytes) const;
};
void write_all(HANDLE h, std::string_view bytes);
void console_text(std::string_view bytes, bool error = false);
std::string read_local_file(const fs::path& file, size_t max_bytes);
Json result(std::string_view source, std::string_view status = "ok");
void issue(Json& r, std::string_view status, std::string_view reason, DWORD code = 0);

struct Task { std::string id; std::string title; };
std::vector<Task> collection_tasks(size_t log_count, size_t dump_count = 0, bool include_evtx = false);
Json history_nic_tokens(const Json& network);
Json collect_task(std::string_view id, const Json& input, const Output& output);
Json collect_events(std::string_view channel, const Json& input, const Output& output);
Json collect_setupapi(const Json& input, const Output& output);
Json copy_user_log(size_t index, const Json& input, const Output& output);
Json copy_sapera_log(const fs::path& path, const Output& output);
Json collect_sapera_log(const Output& output);
bool event_interesting(const Json& event, std::string_view channel, const Json& input);
std::wstring evtx_record_query(std::string_view channel, const std::vector<uint64_t>& ids);
Json export_selected_evtx(const Json& input, const Output& output);
int utc_offset_minutes(std::string_view offset);
Json read_dump_metadata(const fs::path& path);
Json collect_dump(size_t index, const Json& input, const Output& output);
Json attach_dumps(const Json& input, const Output& output, DWORD timeout_ms = 300000);
Json query_wmi(std::wstring_view name_space, std::wstring_view class_name,
               std::wstring_view where = L"");
Json run_worker(const Task& task, const Json& input, DWORD timeout_ms = 30000,
                const fs::path& exe = executable_path());
int worker_main(std::string_view task_id);
int collect(const Options& options);
bool write_reports(const Output& output, const Json& input, const Json& modules,
                   const std::string& start, const std::string& end);
void write_manifest(const Output& output, const Json& input, const Json& modules,
                    const std::string& start, const std::string& end);
void create_zip(const Output& output);
std::vector<std::string> setupapi_blocks(std::string_view text,
    const std::vector<std::string>& device_ids, ULONGLONG from, ULONGLONG to);
} // namespace fnc
