#pragma once
#include "common.hpp"
#include <map>
namespace fnc {
struct EvidenceDigest {
    uint64_t size_bytes=0;std::string sha256;
    bool operator==(const EvidenceDigest&) const = default;
};
// User log bodies are verified and parsed in bounded chunks, then discarded.
// Sapera binary logs are verified in bounded chunks without text parsing.
// Only load_evidence can attach a digest in place of a retained body.
class EvidenceFiles : public std::map<std::string,std::string> {
    std::map<std::string,EvidenceDigest> streamed_;
    Json streamed_sdk_;
    friend EvidenceFiles load_evidence(const fs::path& input);
public:
    using std::map<std::string,std::string>::map;
    const auto& streamed_digests() const {return streamed_;}
    const Json& streamed_sdk() const {return streamed_sdk_;}
    bool operator==(const EvidenceFiles& other) const {
        return static_cast<const std::map<std::string,std::string>&>(*this)==other&&streamed_==other.streamed_;
    }
};
EvidenceFiles load_evidence(const fs::path& input);
struct EventDateFilter {std::string date,utc_offset;ULONGLONG from=0,to=0;int offset_minutes=0;};
EventDateFilter event_date_filter(std::string date,std::string utc_offset="+09:00");
Json analyze_evidence(const EvidenceFiles& files,const std::optional<EventDateFilter>& filter=std::nullopt,
                      const std::optional<std::string>& log_utc_offset=std::nullopt);
std::string selected_events_csv(const Json& report);
std::string selected_events_jsonl(const Json& report);
std::string analysis_html(const Json& report);
int analyze_main(const std::vector<std::wstring>& args);
}
