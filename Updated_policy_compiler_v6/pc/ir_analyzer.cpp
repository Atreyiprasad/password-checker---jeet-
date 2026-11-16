#include "ir_analyzer.h"
#include <algorithm>

using namespace std;

IRReport IRAnalyzer::analyze(const PolicyIR& ir)
{
    IRReport rep;
    const auto& p = ir.p;
    auto add = [&](Severity s, const string& m) { rep.findings.push_back({s, m}); };
    int score = 0;

    // ---- length (max 25)
    int eff = ir.effectiveMinLength;
    score += eff >= 14 ? 25 : eff >= 12 ? 22 : eff >= 10 ? 18 : eff >= 8 ? 14 : eff >= 6 ? 7 : 0;

    if(p.minLength == -1)
        add(Severity::Critical, "No minimum length: one-character passwords are accepted");
    else if(p.minLength < 6)
        add(Severity::Critical, "Weak policy: minimum length " + to_string(p.minLength) + " is far too small");
    else if(p.minLength < 8)
        add(Severity::Warning, "Weak policy: minimum length " + to_string(p.minLength) +
                               " is below the NIST SP 800-63B minimum of 8");

    if(p.minLength != -1 && p.minLength == p.maxLength)
        add(Severity::Warning, "Password length is fixed (" + to_string(p.minLength) +
                               "): attackers know the exact length, shrinking the search space");

    // ---- maximum length (max 10)
    if(p.maxLength == -1 || p.maxLength >= 64) score += 10;
    else if(p.maxLength >= 32) score += 5;
    if(p.maxLength != -1 && p.maxLength < 16)
        add(Severity::Warning, "maxLength " + to_string(p.maxLength) +
                               " blocks passphrases; NIST recommends allowing at least 64 characters");
    else if(p.maxLength != -1 && p.maxLength < 64)
        add(Severity::Info, "maxLength " + to_string(p.maxLength) + " is below the recommended 64");

    // ---- character classes (max 12): NIST discourages heavy composition rules, so modest weight
    score += ir.classesRequired >= 4 ? 12 : ir.classesRequired == 3 ? 10 : ir.classesRequired == 2 ? 6 : ir.classesRequired == 1 ? 3 : 0;
    if(ir.classesRequired == 0)
        add(Severity::Info, "No character-class requirements (fine if blockCommon and a length floor are set)");

    int forbidden = (p.requireUpper == 0) + (p.requireLower == 0) + (p.requireDigit == 0) + (p.requireSpecial == 0);
    if(forbidden > 0)
        add(Severity::Warning, to_string(forbidden) + " character class(es) are forbidden, shrinking the alphabet to " +
                               to_string(ir.allowedPool) + " symbols and giving users fewer ways to be unpredictable");

    // ---- common-password protection (max 15)
    if(p.blockCommon == 1) score += 15;
    else add(Severity::Warning, "No common-password protection: 'Password1!' style choices pass. Add: blockCommon true");

    // ---- pattern controls (max 15)
    if(p.maxRepeat != -1) score += 4;
    if(p.maxSequence != -1) score += 4;
    if(p.noKeyboardPatterns == 1) score += 4;
    if(p.noRepeatedBlocks == 1) score += 3;
    if(p.maxRepeat == -1 && p.maxSequence == -1 && p.noKeyboardPatterns != 1 && p.noRepeatedBlocks != 1)
        add(Severity::Info, "No pattern controls (maxRepeat, maxSequence, noKeyboardPatterns, noRepeatedBlocks)");

    // ---- context awareness (max 8)
    if(p.noUserInfo == 1) score += 5;
    else add(Severity::Info, "noUserInfo is off: the password may contain the username");
    if(!p.forbiddenWords.empty()) score += 3;

    // ---- entropy floor (max 15)
    if(p.minEntropy != -1)
        score += p.minEntropy >= 60 ? 15 : p.minEntropy >= 40 ? 10 : p.minEntropy >= 28 ? 5 : 2;
    else
        add(Severity::Info, "No entropy floor: consider minEntropy 50 to reject predictable-but-compliant passwords");

    // ---- keyspace (search-space) analysis
    if(ir.allowedPool > 0) {
        Severity sev = ir.minKeyspaceBits < 40 ? Severity::Critical : ir.minKeyspaceBits < 60 ? Severity::Warning : Severity::Info;
        add(sev, "Best case, even a perfectly random password at the minimum length (" + to_string(ir.effectiveMinLength) +
                 ") has only ~" + to_string((int)ir.minKeyspaceBits) + " bits (offline brute force: " +
                 pwrt::crackTime(ir.minKeyspaceBits, 1e10) + "). Real user passwords are much weaker");
    }

    // ---- strong policy
    if(eff >= 10 && p.requireUpper == 1 && p.requireLower == 1 && p.requireDigit == 1)
        add(Severity::Info, "Strong policy detected: length >= 10 with mixed character classes");

    // most severe first
    stable_sort(rep.findings.begin(), rep.findings.end(),
                [](const IRWarning& a, const IRWarning& b) { return (int)a.severity > (int)b.severity; });

    rep.score = min(100, score);
    rep.grade = rep.score >= 90 ? "A" : rep.score >= 75 ? "B" : rep.score >= 60 ? "C" : rep.score >= 40 ? "D" : "F";
    return rep;
}

string IRAnalyzer::harden(const PolicyIR& ir)
{
    pwrt::Policy h = ir.p;
    string notes;
    auto note = [&](const string& s) { notes += "#   - " + s + "\n"; };

    if(h.minLength == -1 || h.minLength < 12) { h.minLength = 12; note("minLength raised to 12"); }
    if(h.maxLength != -1 && h.maxLength < 64) { h.maxLength = 64; note("maxLength raised to 64 (allow passphrases)"); }
    if(h.requireUpper == 0)   { h.requireUpper = -1;   note("no longer forbids uppercase letters"); }
    if(h.requireLower == 0)   { h.requireLower = -1;   note("no longer forbids lowercase letters"); }
    if(h.requireDigit == 0)   { h.requireDigit = -1;   note("no longer forbids digits"); }
    if(h.requireSpecial == 0) { h.requireSpecial = -1; note("no longer forbids special characters"); }
    if(h.blockCommon != 1)        { h.blockCommon = 1;        note("blockCommon on"); }
    if(h.noUserInfo != 1)         { h.noUserInfo = 1;         note("noUserInfo on"); }
    if(h.noKeyboardPatterns != 1) { h.noKeyboardPatterns = 1; note("noKeyboardPatterns on"); }
    if(h.noRepeatedBlocks != 1)   { h.noRepeatedBlocks = 1;   note("noRepeatedBlocks on"); }
    if(h.maxRepeat == -1 || h.maxRepeat > 3)     { h.maxRepeat = 3;   note("maxRepeat 3"); }
    if(h.maxSequence == -1 || h.maxSequence > 3) { h.maxSequence = 3; note("maxSequence 3"); }
    if(h.minEntropy == -1 || h.minEntropy < 50)  { h.minEntropy = 50; note("minEntropy 50"); }

    string out = "# Hardened policy suggested by the Policy Compiler\n# Changes from your policy:\n";
    out += notes.empty() ? "#   - none, your policy already meets every recommendation\n" : notes;
    out += "\n" + pwrt::toPolicyText(h);
    return out;
}
