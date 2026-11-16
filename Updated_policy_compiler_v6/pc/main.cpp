#include "pw_runtime.h"      // keep first: it sets platform macros before other headers

#include <iostream>
#include <fstream>
#include <sstream>

#include "lexer.h"
#include "parser.h"
#include "semantic.h"
#include "ir.h"
#include "ir_analyzer.h"
#include "neurosymbolic.h"
#include "codegen.h"
#include "agentic_ai.h"
#include "ai_guard.h"
#include <iomanip>

using namespace std;

static const size_t kMaxPolicyBytes = 64 * 1024;   // refuse absurdly large policy files

static void printUsage()
{
    cout << "Usage: policy_compiler <policyfile> [options]\n"
         << "Standard Options:\n"
         << "  --out <file>       where to write the generated validator (default generated_validator.cpp)\n"
         << "  --user <name>      username, for the noUserInfo rule\n"
         << "  --generate [N]     print N random passwords that satisfy the policy (default 1) and exit\n"
         << "  --harden <file>    write a stronger version of the policy to <file>\n"
         << "  --no-prompt        compile only; do not ask for a password\n"
         << "  --verbose          also print the IR pass log\n"
         << "\nAgentic AI & Advanced Security Options:\n"
         << "  --agentic          enable Agentic AI across all compiler levels (self-healing, SMT prover, defense)\n"
         << "  --auto-heal        autonomously heal syntax errors & contradictions, and output repaired policy\n"
         << "  --audit            run Autonomous Regulatory Compliance Audit (NIST, OWASP, PCI-DSS, ISO 27001)\n"
         << "  --redteam          run Adversarial Red-Team Simulator (RTX 4090 GPU cluster crack times)\n"
         << "  --emit-all <base>  synthesize multi-target validators: <base>.cpp, <base>.py, <base>.ts, <base>.json\n"
         << "  --trace            display detailed agent execution trace across all 6 compiler pipeline levels\n"
         << "\nAI Security Layer:\n"
         << "  --guard            scan input for prompt injection / bypass / obfuscation and scan generated code; BLOCK = exit 3\n"
         << "  --attack-sim       simulate attacks on the agentic AI and print detection metrics (precision/recall/F1/ASR)\n"
         << "  --json             print the whole analysis as one JSON document (used by the web UI)\n"
         << "  --pw-stdin         with --json: read a password to evaluate from the first line of stdin\n"
         << "  --batch <file>     with --json: evaluate many passwords at once (lines: category<TAB>password, max 500)\n"
         << "\nExit code: 0 ok / password valid, 1 compile error or password invalid, 2 usage/IO error\n";
}

static bool readFile(const string& path, string& out)
{
    ifstream f(path, ios::binary);
    if(!f) return false;
    stringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}

static void printDiagnostic(const char* kind, const string& msg, const SourcePos& pos, const vector<string>& lines)
{
    if(pos.line <= 0) {                 // no source location (whole-policy problems)
        cout << kind << ": " << msg << "\n";
        return;
    }
    cout << kind << " at line " << pos.line << ", col " << pos.col << ": " << msg << "\n";

    if((size_t)pos.line <= lines.size()) {
        string prefix = "  " + to_string(pos.line) + " | ";
        cout << prefix << lines[pos.line - 1] << "\n";
        cout << string(prefix.length() + pos.col - 1, ' ') << "^~~\n";
    }
}

int main(int argc, char* argv[])
{
    string path, outFile = "generated_validator.cpp", user, hardenFile, emitBase, batchFile;
    bool noPrompt = false, verbose = false;
    bool guardMode = false, attackSim = false, jsonMode = false, pwStdin = false;
    bool agenticMode = false, autoHealMode = false, auditMode = false, redteamMode = false, traceMode = false;
    int genCount = 0;

    for(int i = 1; i < argc; i++) {
        string a = argv[i];
        if(a == "--help" || a == "-h") { printUsage(); return 0; }
        else if(a == "--out" && i + 1 < argc) outFile = argv[++i];
        else if(a == "--user" && i + 1 < argc) user = argv[++i];
        else if(a == "--harden" && i + 1 < argc) hardenFile = argv[++i];
        else if(a == "--emit-all" && i + 1 < argc) emitBase = argv[++i];
        else if(a == "--batch" && i + 1 < argc) batchFile = argv[++i];
        else if(a == "--no-prompt") noPrompt = true;
        else if(a == "--verbose") verbose = true;
        else if(a == "--agentic") agenticMode = true;
        else if(a == "--auto-heal") autoHealMode = true;
        else if(a == "--audit") auditMode = true;
        else if(a == "--redteam") redteamMode = true;
        else if(a == "--trace") traceMode = true;
        else if(a == "--guard") guardMode = true;
        else if(a == "--attack-sim") attackSim = true;
        else if(a == "--json") jsonMode = true;
        else if(a == "--pw-stdin") pwStdin = true;
        else if(a == "--generate") {
            genCount = 1;
            if(i + 1 < argc && atoi(argv[i + 1]) > 0) genCount = min(50, atoi(argv[++i]));
        }
        else if(!a.empty() && a[0] == '-') { cout << "Unknown option: " << a << "\n"; printUsage(); return 2; }
        else path = a;
    }

    if(attackSim) { cout << guard::runSimulation(jsonMode) << "\n"; return 0; }
    if(path.empty()) { printUsage(); return 2; }

    string input;
    if(!readFile(path, input)) {
        cout << "Error: cannot open file: " << path << "\n";
        return 2;
    }
    if(input.size() > kMaxPolicyBytes) {
        cout << "Error: policy file is larger than " << kMaxPolicyBytes / 1024 << " KB; refusing to compile it\n";
        return 2;
    }

    if(jsonMode && !batchFile.empty()) {             // batch test runner: one "category<TAB>password" per line
        string raw; vector<pair<string,string>> cases;
        if(!readFile(batchFile, raw)) { cout << "{\"error\":\"cannot open batch file\"}\n"; return 2; }
        stringstream bs(raw); string ln;
        while(getline(bs, ln) && cases.size() < 500) {
            if(!ln.empty() && ln.back() == '\r') ln.pop_back();
            size_t t = ln.find('\t');
            if(t == string::npos) cases.push_back({"custom", ln}); else cases.push_back({ln.substr(0, t), ln.substr(t + 1)});
        }
        cout << guard::batchJson(input, user, cases) << "\n";
        return 0;
    }
    if(jsonMode) {
        string pw;
        if(pwStdin) getline(cin, pw);
        cout << guard::analyzeJson(input, user, pw) << "\n";
        return 0;
    }
    if(guardMode) {
        cout << "[AI-GUARD] Scanning input for prompt-injection / policy-bypass / obfuscation...\n";
        auto gv = guard::scanInput(input);
        guard::logAttack("cli-input", gv, input);
        for(const auto& f : gv.findings)
            cout << "  [" << f.category << "] line " << f.line << " (weight " << f.weight << "): " << f.evidence << "\n";
        cout << "  Risk score: " << gv.risk << "  -> " << gv.action << "\n";
        if(gv.action == "BLOCK") {
            cout << "[AI-GUARD] ATTACK BLOCKED. Compilation halted, event written to attacks.log\n";
            return 3;
        }
    }

    // ------------------------------------------------------------- AUTO-HEAL MODE
    if(autoHealMode) {
        cout << "--- AGENTIC POLICY DOCTOR: AUTONOMOUS REPAIR & OPTIMIZATION ---\n";
        string healed = agentic::AgenticCompilerEngine::autoHealAndOptimize(input);
        if(guardMode) {
            pwrt::Policy op, hp;
            if(guard::parsePolicy(input, op) && guard::parsePolicy(healed, hp)) {
                auto dv = guard::checkDrift(op, hp);
                guard::logAttack("cli-heal-drift", dv, healed);
                if(dv.action == "BLOCK") { cout << "[AI-GUARD] Healed policy is WEAKER than the original - blocked.\n"; return 3; }
            }
        }
        cout << healed << "\n";
        return 0;
    }

    vector<string> sourceLines;
    {
        stringstream ss(input);
        string line;
        while(getline(ss, line)) {
            if(!line.empty() && line.back() == '\r') line.pop_back();
            sourceLines.push_back(line);
        }
    }

    // ---------------------------------------------------------- LEVEL 1: LEXICAL
    vector<Token> tokens;
    if(agenticMode) {
        cout << "[Agentic AI] Level 1: Scanning for Trojan Source, Zero-Width characters & Homoglyphs...\n";
        auto lexRes = agentic::AgenticCompilerEngine::runAgenticLexer(input);
        for(const auto& st : lexRes.securityThreats) {
            cout << "  [SECURITY ALERT] " << st.type << " at line " << st.pos.line << ", col " << st.pos.col << "\n";
            cout << "    Details: " << st.details << "\n";
            cout << "    Remediation: " << st.remediation << "\n";
        }
        for(const auto& rep : lexRes.repairs) {
            cout << "  [Autonomous Self-Repair] " << rep.reason << " (line " << rep.pos.line << ")\n";
        }
        tokens = lexRes.tokens;
    } else {
        Lexer lex(input);
        tokens = lex.tokenize();
        if(!lex.errors().empty()) {
            cout << "\n--- LEXICAL ERRORS ---\n";
            for(const auto& e : lex.errors()) { printDiagnostic("Error", e.message, e.pos, sourceLines); cout << "\n"; }
            cout << "Tip: Run with --agentic or --auto-heal to activate autonomous error recovery.\n";
            return 1;
        }
    }

    // ----------------------------------------------------------- LEVEL 2: SYNTAX
    ProgramNode prog;
    if(agenticMode) {
        cout << "[Agentic AI] Level 2: Activating Self-Healing Grammar & Intent Parser...\n";
        auto parseRes = agentic::AgenticCompilerEngine::runAgenticParser(tokens, input);
        for(const auto& rep : parseRes.repairs) {
            cout << "  [Grammar Healed] " << rep.explanation << " -> '" << rep.repairedSyntax << "' (confidence " << (int)(rep.confidence * 100) << "%)\n";
        }
        prog = parseRes.program;
    } else {
        Parser parser(tokens);
        prog = parser.parse();
        if(!parser.errors().empty()) {
            cout << "\n--- SYNTAX ERRORS ---\n";
            for(const auto& e : parser.errors()) { printDiagnostic("Error", e.message, e.pos, sourceLines); cout << "\n"; }
            cout << "Tip: Run with --agentic or --auto-heal to enable self-healing grammar recovery.\n";
            return 1;
        }
    }

    // --------------------------------------------------------- LEVEL 3: SEMANTICS
    SemanticAnalyzer sem;
    sem.analyze(prog);

    if(!sem.errors().empty() && !agenticMode) {
        cout << "\n--- SEMANTIC ERRORS ---\n";
        for(const auto& e : sem.errors()) { printDiagnostic("Error", e.message, e.pos, sourceLines); cout << "\n"; }
        return 1;
    }
    for(const auto& w : sem.warnings()) { printDiagnostic("Warning", w.message, w.pos, sourceLines); cout << "\n"; }

    const auto& c = sem.getConstraints();

    if(agenticMode) {
        cout << "[Agentic AI] Level 3: Executing Formal SMT-Style Logic Satisfiability Prover...\n";
        auto sat = agentic::AgenticCompilerEngine::proveFeasibility(c);
        if(sat.isSatisfiable) {
            cout << "  [SAT Prover] " << sat.proofSummary << "\n";
        } else {
            cout << "  [SAT Alert] " << sat.proofSummary << "\n";
            for(const auto& fix : sat.minimalDeltaFixes) {
                cout << "    Minimal Delta Fix: Set " << fix.ruleName << " = " << fix.suggestedVal << " (" << fix.justification << ")\n";
            }
        }
    }

    cout << "\nPolicy Compiled Successfully!\n";
    cout << "\nFinal Policy Constraints:\n";
    cout << pwrt::toPolicyText(c);

    // ------------------------------------------------------------ LEVEL 4: IR
    PolicyIR ir = buildIR(c);
    cout << "\nPolicy fingerprint (SHA-256): " << ir.fingerprint << "\n";
    if(verbose) {
        cout << "\nIR passes:\n";
        for(const auto& s : ir.passes) cout << "  - " << s << "\n";
    }

    // Regulatory Compliance Audit
    if(auditMode || agenticMode) {
        cout << "\n--- AUTONOMOUS REGULATORY COMPLIANCE AUDIT ---\n";
        auto auditRep = agentic::AgenticCompilerEngine::auditCompliance(ir);
        cout << "Overall Compliance Score: " << auditRep.overallScore << "/100\n";
        for(const auto& st : auditRep.standards) {
            cout << "\n  [" << st.status << "] " << st.standardName << " - Score: " << st.compliancePercent << "%\n";
            for(const auto& met : st.metRequirements) cout << "    \xE2\x9C\x93 " << met << "\n";
            for(const auto& miss : st.missingRequirements) cout << "    \xE2\x9C\x97 GAP: " << miss << "\n";
            for(const auto& rem : st.automatedRemediations) cout << "    -> Auto-Remedy: " << rem << "\n";
        }
    }

    // Adversarial Red-Team Simulation
    if(redteamMode || agenticMode) {
        cout << "\n--- ADVERSARIAL RED-TEAM BRUTE-FORCE SIMULATION ---\n";
        auto sim = agentic::AgenticCompilerEngine::runRedTeamSimulation(ir);
        for(const auto& sc : sim.hardwareScenarios) {
            cout << "  * Hardware: " << sc.hardwareName << "\n";
            cout << "    Target: " << sc.algorithm << " (" << sc.hashesPerSec << " H/s)\n";
            cout << "    Cracking Time: " << sc.estimatedTime << " [" << sc.riskLevel << "]\n";
        }
        for(const auto& vec : sim.attackVectorsIdentified) cout << "  [VULNERABILITY] " << vec << "\n";
        for(const auto& rec : sim.hardeningRecommendations) cout << "  [HARDENING] " << rec << "\n";
    }

    // ------------------------------------------------------------ LEVEL 5: CODEGEN
    cout << "\nGenerating Target C++ Validation Program...\n";
    if(!CodeGenerator::generate(ir, outFile)) return 2;
    cout << "Target C++ code generated at: " << outFile << "\n";

    if(!emitBase.empty() || agenticMode) {
        string base = emitBase.empty() ? "validator_synthesized" : emitBase;
        cout << "\n[Agentic AI] Level 5: Synthesizing Multi-Target Code Suite (" << base << ")...\n";
        auto targets = agentic::AgenticCompilerEngine::synthesizeAllTargets(ir);
        
        ofstream pyF(base + ".py"); if(pyF) pyF << targets.pythonCode;
        ofstream tsF(base + ".ts"); if(tsF) tsF << targets.typeScriptCode;
        ofstream jF(base + ".json"); if(jF) jF << targets.jsonIR;

        cout << "  - Python 3 Validator: " << base << ".py\n";
        cout << "  - TypeScript Validator: " << base << ".ts\n";
        cout << "  - JSON Schema IR: " << base << ".json\n";
        cout << "  - HMAC-SHA256 Integrity Seal: " << targets.hmacSignature << "\n";
    }

    // Pipeline State Trace
    if(traceMode) {
        cout << "\n--- FULL PIPELINE TRACE ACROSS ALL 6 COMPILER LEVELS ---\n";
        auto trace = agentic::AgenticCompilerEngine::executeFullPipeline(input, "", user);
        for(const auto& lvl : trace.levels) {
            cout << "\nLevel " << lvl.levelNumber << " (" << lvl.levelName << ") - [" << lvl.status << "]\n";
            cout << "  Agent: " << lvl.agentPersona << "\n";
            cout << "  Summary: " << lvl.summary << "\n";
            for(const auto& ins : lvl.insights) cout << "  - " << ins << "\n";
        }
    }

    // ---------------------------------------------------------------- IR ANALYSIS
    IRReport report = IRAnalyzer::analyze(ir);
    cout << "\nPOLICY QUALITY: " << report.score << "/100 (grade " << report.grade << ")\n";
    static const char* tag[] = {"INFO    ", "WARNING ", "CRITICAL"};
    for(const auto& w : report.findings)
        cout << "  [" << tag[(int)w.severity] << "] " << w.message << "\n";

    if(!hardenFile.empty()) {
        ofstream h(hardenFile);
        if(!h) { cout << "\nCould not write " << hardenFile << "\n"; return 2; }
        h << IRAnalyzer::harden(ir);
        cout << "\nHardened policy suggestion written to " << hardenFile
             << "  (recompile it to compare scores)\n";
    }

    // -------------------------------------------------------- PASSWORD GENERATION
    if(genCount > 0) {
        cout << "\nGenerated passwords (OS CSPRNG, verified against the policy):\n";
        for(int i = 0; i < genCount; i++) {
            string g = pwrt::generate(ir.p, user);
            if(g.empty()) { cout << "  The generator could not satisfy this policy.\n"; return 1; }
            cout << "  " << g << "\n";
            pwrt::secureWipe(g);
        }
        return 0;
    }

    if(noPrompt) return 0;

    // -------------------------------------------------- NEURO-SYMBOLIC EVALUATION
    string password;
    if(!pwrt::readSecret("\nEnter password to evaluate (input hidden): ", password)) {
        cout << "No password provided.\n";
        return 2;
    }

    NSResult result = NeuroSymbolicEvaluator::evaluate(password, ir, user);
    pwrt::secureWipe(password);
    NeuroSymbolicEvaluator::print(result);

    if(agenticMode) {
        cout << "\n[Agentic AI] Level 6: Real-Time Blue-Team Defense Advisor:\n";
        auto defense = agentic::AgenticCompilerEngine::adviseDefense(result, ir.p);
        cout << "  Dynamic Risk Tier: " << defense.riskTier << " (Score: " << fixed << setprecision(2) << defense.dynamicRiskScore << ")\n";
        for(const auto& act : defense.recommendedActions) cout << "  [Action] " << act << "\n";
    }

    return result.valid ? 0 : 1;
}
