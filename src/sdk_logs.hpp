#pragma once
#include "common.hpp"
#include <map>

namespace fnc {
constexpr size_t kSdkEventCount=10000, kSdkEventBytes=4*1024*1024, kSdkLineBytes=64*1024;
// One parser spans all explicit input files, so limits apply to the whole run.
class SdkLogParser {
    std::string source_, original_, pending_, pid_;
    uint64_t offset_=0, line_offset_=0, line_number_=0, base_offset_=0;
    bool utf16_=false, probed_=false, tail_=false, oversized_=false, budget_exhausted_=false;
    size_t retained_bytes_=0;
    Json events_=Json::array(), files_=Json::array();
    size_t recognized_=0, skipped_=0;
    void line(std::string bytes);
public:
    void begin(std::string source, std::string original={}, uint64_t base_offset=0, bool utf16=false);
    void feed(std::string_view bytes);
    void end();
    Json finish(const std::optional<std::string>& utc_offset=std::nullopt);
};
Json sdk_summary(Json events, Json sources, const std::optional<std::string>& utc_offset=std::nullopt);
Json collect_sdk_logs(const Json& input, const Output& output);
}
