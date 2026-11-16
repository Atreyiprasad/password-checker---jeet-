#ifndef AI_GUARD_H
#define AI_GUARD_H
// Agentic-AI security layer: detects prompt injection, policy bypass, obfuscation,
// code injection / exfiltration in healed output, and policy weakening (intent drift).
#include "pw_runtime.h"
#include <string>
#include <vector>
#include <ostream>

namespace guard {

struct Finding {
    std::string category;   // PromptInjection, PolicyBypass, RoleHijack, Exfiltration, Obfuscation, CodeInjection, MaliciousCode, PolicyDrift, EncodedPayload
    int line = 0;           // 0 = whole artifact
    double weight = 0;      // 0..1 contribution to risk
    std::string evidence;   // short, sanitized excerpt
};

struct Verdict {
    double risk = 0;                 // noisy-OR of finding weights, 0..1
    std::string action = "ALLOW";    // ALLOW | WARN | BLOCK
    std::vector<Finding> findings;
};

Verdict scanInput(const std::string& policyOrPromptText);                         // before the compiler acts
Verdict scanOutput(const std::string& generatedCode, const std::string& label);   // after the agent produced code
Verdict checkDrift(const pwrt::Policy& original, const pwrt::Policy& healed);      // healed must not be weaker
bool    parsePolicy(const std::string& text, pwrt::Policy& out);                   // plain pipeline: lex+parse+semantic

std::string verdictJson(const Verdict& v);
void        logAttack(const std::string& source, const Verdict& v, const std::string& input);  // appends to attacks.log

// Attack simulation + detection metrics. Returns JSON when asJson, else a readable table.
std::string runSimulation(bool asJson);
// Full pipeline as one JSON document (used by the web UI).
std::string analyzeJson(const std::string& source, const std::string& user, const std::string& password);
// Batch test runner: compile the policy once, evaluate many (category, password) cases, return per-case entropy + verdicts as JSON.
std::string batchJson(const std::string& source, const std::string& user, const std::vector<std::pair<std::string, std::string>>& cases);

} // namespace guard
#endif
