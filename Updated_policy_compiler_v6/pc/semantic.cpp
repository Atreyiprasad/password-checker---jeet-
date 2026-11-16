#include "semantic.h"
#include <algorithm>
#include <cmath>
#include <map>
#include <vector>
#include <string>
using namespace std;

// ---- Levenshtein distance for "Did you mean ...?" suggestions
static int levenshteinDistance(const string& s1, const string& s2) {
    const size_t len1 = s1.size(), len2 = s2.size();
    vector<vector<int>> d(len1 + 1, vector<int>(len2 + 1));
    for(size_t i = 0; i <= len1; ++i) d[i][0] = (int)i;
    for(size_t j = 0; j <= len2; ++j) d[0][j] = (int)j;

    for(size_t i = 1; i <= len1; ++i) {
        for(size_t j = 1; j <= len2; ++j) {
            int cost = (tolower((unsigned char)s1[i - 1]) == tolower((unsigned char)s2[j - 1])) ? 0 : 1;
            d[i][j] = min({ d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost });
        }
    }
    return d[len1][len2];
}

static string suggestRule(const string& typo) {
    vector<string> validRules;
    for(const auto& f : pwrt::fieldDefs()) validRules.push_back(f.name);
    validRules.push_back("forbidWord");

    string bestMatch;
    int minDistance = 3; // tolerance: up to 2 edits
    for(const auto& rule : validRules) {
        int dist = levenshteinDistance(typo, rule);
        if(dist < minDistance) { minDistance = dist; bestMatch = rule; }
    }
    return bestMatch;
}

// overflow-safe number parsing (max 9 digits, so it always fits in int)
static bool parseNumber(const string& s, int& out) {
    if(s.empty() || s.size() > 9) return false;
    long v = 0;
    for(char c : s) {
        if(c < '0' || c > '9') return false;
        v = v * 10 + (c - '0');
    }
    out = (int)v;
    return true;
}

void SemanticAnalyzer::analyze(const ProgramNode& prog) {
    map<string, SourcePos> firstSeen;

    auto posOf = [&](const string& n) -> SourcePos {
        auto it = firstSeen.find(n);
        return it == firstSeen.end() ? SourcePos{0, 0} : it->second;
    };

    // ---------- pass 1: per-rule checks (name, duplicates, type, range)
    for(const auto& rule : prog.rules) {

        if(rule.name == "forbidWord") {
            if(rule.valueType != PCTokenType::String) {
                errs.push_back({"'forbidWord' expects a quoted string, e.g. forbidWord \"acme\"", rule.pos});
                continue;
            }
            if(rule.value.empty() || rule.value.size() > 64) {
                errs.push_back({"'forbidWord' must be between 1 and 64 characters", rule.pos});
                continue;
            }
            bool printable = all_of(rule.value.begin(), rule.value.end(),
                                    [](char c){ return (unsigned char)c >= 0x20 && c != 0x7f; });
            if(!printable) {
                errs.push_back({"'forbidWord' contains control characters", rule.pos});
                continue;
            }
            if(constraints.forbiddenWords.size() >= 200) {
                errs.push_back({"Too many forbidWord rules (limit is 200)", rule.pos});
                continue;
            }
            constraints.forbiddenWords.push_back(rule.value);
            continue;
        }

        const pwrt::FieldDef* fd = nullptr;
        for(const auto& f : pwrt::fieldDefs())
            if(rule.name == f.name) { fd = &f; break; }

        if(!fd) {
            string msg = "Unknown rule: '" + rule.name + "'";
            string suggestion = suggestRule(rule.name);
            if(!suggestion.empty()) msg += ". Did you mean '" + suggestion + "'?";
            errs.push_back({msg, rule.pos});
            continue;
        }

        auto dup = firstSeen.find(rule.name);
        if(dup != firstSeen.end()) {
            errs.push_back({"Duplicate rule '" + rule.name + "' (first defined at line " +
                            to_string(dup->second.line) + ")", rule.pos});
            continue;
        }
        firstSeen[rule.name] = rule.pos;

        // type check: previously  minLength true  crashed the compiler inside stoi()
        if(fd->isBool) {
            if(rule.valueType != PCTokenType::Boolean) {
                errs.push_back({"'" + rule.name + "' expects true or false, got '" + rule.value + "'", rule.pos});
                continue;
            }
            constraints.*(fd->ptr) = (rule.value == "true") ? 1 : 0;
        } else {
            if(rule.valueType != PCTokenType::Number) {
                errs.push_back({"'" + rule.name + "' expects a number, got '" + rule.value + "'", rule.pos});
                continue;
            }
            int n;
            if(!parseNumber(rule.value, n) || n < fd->lo || n > fd->hi) {
                errs.push_back({"'" + rule.name + "' must be between " + to_string(fd->lo) +
                                " and " + to_string(fd->hi), rule.pos});
                continue;
            }
            constraints.*(fd->ptr) = n;
        }
    }

    const auto& c = constraints;

    // ---------- pass 2: logical conflicts / unsatisfiable policies
    if(c.minLength != -1 && c.maxLength != -1 && c.minLength > c.maxLength)
        errs.push_back({"minLength (" + to_string(c.minLength) + ") cannot be greater than maxLength (" +
                        to_string(c.maxLength) + ")", posOf("maxLength")});

    struct Cls { const char* req; const char* mn; int rq; int m; };
    const Cls cls[] = {
        {"requireUpper",   "minUpper",   c.requireUpper,   c.minUpper},
        {"requireLower",   "minLower",   c.requireLower,   c.minLower},
        {"requireDigit",   "minDigit",   c.requireDigit,   c.minDigit},
        {"requireSpecial", "minSpecial", c.requireSpecial, c.minSpecial},
    };

    int sumNeed = 0;
    int forbiddenClasses = 0;
    for(const auto& k : cls) {
        if(k.rq == 0 && k.m > 0)
            errs.push_back({string("Contradiction: ") + k.req + " is false (class forbidden) but " +
                            k.mn + " demands " + to_string(k.m), posOf(k.mn)});
        if(k.rq == 1 && k.m >= 1)
            warns.push_back({string(k.req) + " true is redundant because " + k.mn + " " +
                             to_string(k.m) + " already implies it", posOf(k.req)});
        if(k.rq == 0) forbiddenClasses++;
        sumNeed += max(k.m > 0 ? k.m : 0, k.rq == 1 ? 1 : 0);
    }

    if(forbiddenClasses == 4)
        errs.push_back({"Every character class is forbidden, so no password can ever satisfy this policy",
                        posOf("requireUpper")});

    if(c.maxLength != -1 && sumNeed > c.maxLength)
        errs.push_back({"Unsatisfiable: character-class minimums need " + to_string(sumNeed) +
                        " characters but maxLength is " + to_string(c.maxLength), posOf("maxLength")});

    if(c.minUnique != -1 && c.maxLength != -1 && c.minUnique > c.maxLength)
        errs.push_back({"Unsatisfiable: minUnique (" + to_string(c.minUnique) +
                        ") is larger than maxLength (" + to_string(c.maxLength) + ")", posOf("minUnique")});

    if(c.minEntropy != -1 && c.maxLength != -1 && forbiddenClasses < 4) {
        double pool = 0;
        if(c.requireUpper != 0) pool += 26;
        if(c.requireLower != 0) pool += 26;
        if(c.requireDigit != 0) pool += 10;
        if(c.requireSpecial != 0) pool += 83;    // 33 printable + 50 for non-ASCII, same as the estimator
        double maxBits = c.maxLength * pwrt::log2d(pool);
        if(maxBits < c.minEntropy)
            errs.push_back({"Unsatisfiable: even a perfectly random " + to_string(c.maxLength) +
                            "-character password over the allowed alphabet has at most " +
                            to_string((int)maxBits) + " bits, but minEntropy is " +
                            to_string(c.minEntropy), posOf("minEntropy")});
    }

    if(c.noSpaces == 0)
        warns.push_back({"'noSpaces false' means spaces are allowed (it does not require them)", posOf("noSpaces")});
}
