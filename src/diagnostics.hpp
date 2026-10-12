#pragma once
#include "common.hpp"

namespace fnc {
// Rule-based GigE Vision diagnosis over an analyze_evidence report.
// Findings separate confirmed observations from inferred correlations; missing values are "unknown", never "disabled".
Json diagnose(const Json& report);
// Bounded, masked context for an optional external LLM review performed outside this executable.
Json llm_context(const Json& report);
// Validates an ai-review.json produced by tools/ai-review.ps1. Throws on schema violations.
Json validate_ai_review(const Json& review);
}
