#ifndef AGENTIC_AI_H
#define AGENTIC_AI_H

#include "token.h"
#include "ast.h"
#include "semantic.h"
#include "ir.h"
#include "ir_analyzer.h"
#include "pw_runtime.h"

#include <string>
#include <vector>
#include <map>
#include <memory>

namespace agentic {

// ============================================================================
// LEVEL 1: AGENTIC LEXER (Trojan Source & Obfuscation + Autonomous Token Recovery)
// ============================================================================
struct SecurityThreat {
    std::string type;       // "TrojanSource", "ZeroWidthCharacter", "Homoglyph", "BidiOverride"
    std::string details;
    SourcePos pos;
    std::string remediation;
};

struct LexerRepairAction {
    SourcePos pos;
    std::string original;
    std::string repaired;
    std::string reason;
};

struct AgenticLexResult {
    std::vector<Token> tokens;
    std::vector<SecurityThreat> securityThreats;
    std::vector<LexerRepairAction> repairs;
    std::string sanitizedSource;
    bool wasRepaired = false;
};

// ============================================================================
// LEVEL 2: AGENTIC PARSER (Self-Healing Grammar & Natural Language Intent Bridge)
// ============================================================================
struct ParserRepairAction {
    SourcePos pos;
    std::string ruleName;
    std::string originalSyntax;
    std::string repairedSyntax;
    std::string explanation;
    double confidence;      // 0.0 - 1.0
};

struct AgenticParseResult {
    ProgramNode program;
    std::vector<ParserRepairAction> repairs;
    std::vector<std::string> reasoningTrace;
    bool hadGrammarRepairs = false;
};

// ============================================================================
// LEVEL 3: AGENTIC SEMANTIC & REASONING (SMT Prover, Delta Suggester, Compliance)
// ============================================================================
struct DeltaSuggestion {
    std::string ruleName;
    std::string currentVal;
    std::string suggestedVal;
    std::string justification;
};

struct FeasibilityProof {
    bool isSatisfiable = true;
    std::string proofSummary;
    std::vector<std::string> conflictRoots;
    std::vector<DeltaSuggestion> minimalDeltaFixes;
};

struct StandardCompliance {
    std::string standardName;       // "NIST SP 800-63B", "OWASP ASVS v4.0", "PCI-DSS v4.0", "ISO 27001"
    int compliancePercent = 0;       // 0..100
    std::string status;              // "COMPLIANT", "PARTIAL", "NON-COMPLIANT"
    std::vector<std::string> metRequirements;
    std::vector<std::string> missingRequirements;
    std::vector<std::string> automatedRemediations;
};

struct ComplianceAuditReport {
    std::vector<StandardCompliance> standards;
    int overallScore = 0;
};

// ============================================================================
// LEVEL 4: AGENTIC IR & ADVERSARIAL RED-TEAM SIMULATOR
// ============================================================================
struct HardwareCrackProfile {
    std::string hardwareName;        // e.g. "8x NVIDIA RTX 4090 GPU Cluster"
    std::string algorithm;           // "NTLM/MD5 (Fast Hash)", "SHA-256", "Argon2id / Bcrypt (Slow)"
    double hashesPerSec;
    std::string estimatedTime;
    std::string riskLevel;           // "CRITICAL", "HIGH", "MODERATE", "SECURE"
};

struct RedTeamSimulation {
    std::vector<HardwareCrackProfile> hardwareScenarios;
    double rainbowTableVulnerability;  // 0.0 - 1.0
    double dictionaryStuffingRisk;     // 0.0 - 1.0
    double cognitiveWalkVulnerability;  // 0.0 - 1.0
    std::vector<std::string> attackVectorsIdentified;
    std::vector<std::string> hardeningRecommendations;
};

// ============================================================================
// LEVEL 5: AGENTIC MULTI-TARGET CODE GENERATOR
// ============================================================================
struct MultiTargetCode {
    std::string cppCode;
    std::string pythonCode;
    std::string typeScriptCode;
    std::string jsonIR;
    std::string hmacSignature;
    std::string sha256Fingerprint;
};

// ============================================================================
// LEVEL 6: AGENTIC BLUE-TEAM DEFENSE ADVISOR (Neuro-Symbolic Runtime Copilot)
// ============================================================================
struct DefenseActionRecommendation {
    std::string riskTier;            // "LOW", "ELEVATED", "CRITICAL"
    double dynamicRiskScore;         // 0.0 - 1.0
    std::vector<std::string> recommendedActions; // e.g. "Require FIDO2 Step-up MFA", "Enforce 5s progressive delay"
    std::vector<std::string> cognitiveExplanations; // Safe hints without leaking secrets
};

// ============================================================================
// COMPREHENSIVE COMPILER TRACE (For Live Visualizer & Public Demo)
// ============================================================================
struct PipelineLevelState {
    int levelNumber;
    std::string levelName;
    std::string agentPersona;
    std::string status;              // "SUCCESS", "REPAIRED", "THREAT_NEUTRALIZED", "WARNING"
    std::string summary;
    std::vector<std::string> insights;
    std::string rawDataSnapshot;
};

struct CompilerAgentPipelineTrace {
    std::vector<PipelineLevelState> levels;
    bool allSuccess = true;
};

// ============================================================================
// MASTER AGENTIC COMPILER ENGINE
// ============================================================================
class AgenticCompilerEngine {
public:
    // Level 1: Autonomous Lexing with Trojan Source & Homoglyph detection
    static AgenticLexResult runAgenticLexer(const std::string& rawSource);

    // Level 2: Autonomous Parsing with Self-Healing Grammar
    static AgenticParseResult runAgenticParser(const std::vector<Token>& tokens, const std::string& rawSource);

    // Natural Language to Formal Policy DSL Agent
    static std::string naturalLanguageToPolicy(const std::string& prompt);

    // Level 3: Logic SMT-Style Satisfiability Prover & Minimal Delta Suggester
    static FeasibilityProof proveFeasibility(const pwrt::Policy& p);

    // Level 3: Regulatory Compliance Audit (NIST, OWASP, PCI-DSS, ISO 27001)
    static ComplianceAuditReport auditCompliance(const PolicyIR& ir);

    // Level 4: Adversarial Red-Team Simulator
    static RedTeamSimulation runRedTeamSimulation(const PolicyIR& ir);

    // Level 5: Multi-Target Code Synthesis (C++, Python, TypeScript, JSON)
    static MultiTargetCode synthesizeAllTargets(const PolicyIR& ir, const std::string& secretKey = "agentic_policy_salt_2026");

    // Level 6: Blue-Team Real-Time Defense & Countermeasure Advisor
    static DefenseActionRecommendation adviseDefense(const pwrt::Evaluation& eval, const pwrt::Policy& p);

    // Complete End-to-End Pipeline Execution Trace
    static CompilerAgentPipelineTrace executeFullPipeline(
        const std::string& source, 
        const std::string& testPassword = "", 
        const std::string& user = ""
    );

    // Autonomous Policy Doctor: Auto-heals syntax, removes contradictions, and applies optimal compliance
    static std::string autoHealAndOptimize(const std::string& source);
};

} // namespace agentic

#endif // AGENTIC_AI_H
