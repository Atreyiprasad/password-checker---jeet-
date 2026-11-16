#ifndef PW_RUNTIME_H
#define PW_RUNTIME_H
// ============================================================================
//  pw_runtime.h  -  Policy Compiler v2 runtime engine
//
//  Single source of truth for every password check.  The compiler includes this
//  header directly, and codegen embeds a copy of it (runtime_embedded.h) into
//  each generated validator, so both always behave identically.
//  After editing this file run:  python3 tools/embed_runtime.py
// ============================================================================
#if defined(_WIN32)
  #ifndef _CRT_RAND_S
  #define _CRT_RAND_S
  #endif
  #ifndef NOMINMAX
  #define NOMINMAX
  #endif
#endif

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <random>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>
#ifdef _WIN32
  #include <windows.h>
  #include <wincrypt.h>
#else
  #include <termios.h>
  #include <unistd.h>
#endif

namespace pwrt {

// Hard cap on bytes analysed: protects against DoS via huge inputs.
inline constexpr size_t kMaxInputBytes = 4096;

// -1 = rule not specified, 1 = true, 0 = false (for boolean rules)
struct Policy {
    int minLength = -1, maxLength = -1;
    int requireUpper = -1, requireLower = -1, requireDigit = -1, requireSpecial = -1;
    int noSpaces = -1;
    int minUpper = -1, minLower = -1, minDigit = -1, minSpecial = -1;
    int maxRepeat = -1, maxSequence = -1, minUnique = -1, minEntropy = -1;
    int blockCommon = -1, noKeyboardPatterns = -1, noRepeatedBlocks = -1, noUserInfo = -1;
    std::vector<std::string> forbiddenWords;
};

struct Violation { std::string rule; std::string message; };

// Table of every rule in the policy language (used by semantic analysis,
// the canonical printer and the fingerprint, so they can never drift apart).
struct FieldDef { const char* name; int Policy::* ptr; bool isBool; int lo; int hi; };

inline const std::vector<FieldDef>& fieldDefs() {
    static const std::vector<FieldDef> f = {
        {"minLength",          &Policy::minLength,          false, 1, 1024},
        {"maxLength",          &Policy::maxLength,          false, 1, 1024},
        {"requireUpper",       &Policy::requireUpper,       true,  0, 1},
        {"requireLower",       &Policy::requireLower,       true,  0, 1},
        {"requireDigit",       &Policy::requireDigit,       true,  0, 1},
        {"requireSpecial",     &Policy::requireSpecial,     true,  0, 1},
        {"noSpaces",           &Policy::noSpaces,           true,  0, 1},
        {"minUpper",           &Policy::minUpper,           false, 1, 1024},
        {"minLower",           &Policy::minLower,           false, 1, 1024},
        {"minDigit",           &Policy::minDigit,           false, 1, 1024},
        {"minSpecial",         &Policy::minSpecial,         false, 1, 1024},
        {"maxRepeat",          &Policy::maxRepeat,          false, 1, 1024},
        {"maxSequence",        &Policy::maxSequence,        false, 1, 1024},
        {"minUnique",          &Policy::minUnique,          false, 1, 1024},
        {"minEntropy",         &Policy::minEntropy,         false, 1, 1024},
        {"blockCommon",        &Policy::blockCommon,        true,  0, 1},
        {"noKeyboardPatterns", &Policy::noKeyboardPatterns, true,  0, 1},
        {"noRepeatedBlocks",   &Policy::noRepeatedBlocks,   true,  0, 1},
        {"noUserInfo",         &Policy::noUserInfo,         true,  0, 1},
    };
    return f;
}

// Canonical policy text (also a valid policy file). Fingerprint = SHA-256 of this.
inline std::string toPolicyText(const Policy& p) {
    std::string s;
    for (const auto& f : fieldDefs()) {
        int v = p.*(f.ptr);
        if (v == -1) continue;
        s += f.name; s += ' ';
        s += f.isBool ? (v ? "true" : "false") : std::to_string(v);
        s += '\n';
    }
    std::vector<std::string> w = p.forbiddenWords;
    std::sort(w.begin(), w.end());
    w.erase(std::unique(w.begin(), w.end()), w.end());
    for (const auto& x : w) s += "forbidWord \"" + x + "\"\n";
    return s;
}

// ---------------------------------------------------------------- text helpers
inline bool isUp(unsigned char c) { return c >= 'A' && c <= 'Z'; }
inline bool isLo(unsigned char c) { return c >= 'a' && c <= 'z'; }
inline bool isDi(unsigned char c) { return c >= '0' && c <= '9'; }
inline bool isSp(unsigned char c) { return c == ' ' || (c >= 9 && c <= 13); }

inline std::string toLower(std::string s) {
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    return s;
}

// UTF-8 aware: every code point becomes exactly ONE byte so lengths are counted in
// characters, not bytes.  ASCII is kept as-is; non-ASCII becomes a byte >= 0x80
// (hash of the code point) so all later analysis can be simple and byte based.
inline std::string simplify(const std::string& s, size_t* uniqueCp = nullptr) {
    std::string out;
    std::set<std::string> seen;
    for (size_t i = 0; i < s.size();) {
        unsigned char b = (unsigned char)s[i];
        size_t n = b < 0x80 ? 1 : (b >> 5) == 6 ? 2 : (b >> 4) == 14 ? 3 : (b >> 3) == 30 ? 4 : 1;
        if (i + n > s.size()) n = 1;
        std::string cp = s.substr(i, n);
        if (b < 0x80) out.push_back((char)b);
        else {
            uint32_t h = 2166136261u;
            for (char ch : cp) { h ^= (unsigned char)ch; h *= 16777619u; }
            out.push_back((char)(0x80 | (h & 0x7F)));
        }
        seen.insert(cp);
        i += n;
    }
    if (uniqueCp) *uniqueCp = seen.size();
    return out;
}

struct Counts {
    size_t length = 0, unique = 0;
    int upper = 0, lower = 0, digit = 0, special = 0, space = 0;
    bool nonAscii = false;
};

inline Counts countClasses(const std::string& simp, size_t unique) {
    Counts c;
    c.length = simp.size();
    c.unique = unique;
    for (char ch : simp) {
        unsigned char u = (unsigned char)ch;
        if (isUp(u)) c.upper++;
        else if (isLo(u)) c.lower++;
        else if (isDi(u)) c.digit++;
        else if (isSp(u)) c.space++;
        else { c.special++; if (u >= 0x80) c.nonAscii = true; }
    }
    return c;
}

// ------------------------------------------------------------ pattern detectors
inline size_t repeatRunAt(const std::string& s, size_t i) {
    size_t r = 1;
    while (i + r < s.size() && s[i + r] == s[i]) r++;
    return r;
}
inline size_t longestRepeat(const std::string& s) {
    size_t best = s.empty() ? 0 : 1;
    for (size_t i = 0; i < s.size(); i += repeatRunAt(s, i)) best = std::max(best, repeatRunAt(s, i));
    return best;
}

inline bool seqVal(char ch, int& v) {
    unsigned char c = (unsigned char)ch;
    if (isLo(c)) { v = c; return true; }
    if (isUp(c)) { v = c - 'A' + 'a'; return true; }
    if (isDi(c)) { v = c; return true; }
    return false;
}
// longest ascending/descending run (abc, 4321, ...) starting at i
inline size_t sequenceRunAt(const std::string& s, size_t i) {
    size_t best = 1;
    int v0;
    if (!seqVal(s[i], v0)) return 1;
    for (int d = -1; d <= 1; d += 2) {
        size_t len = 1;
        int prev = v0;
        while (i + len < s.size()) {
            int v;
            if (!seqVal(s[i + len], v)) break;
            if (v - prev != d) break;
            if (isDi((unsigned char)s[i + len]) != isDi((unsigned char)s[i + len - 1])) break;
            prev = v;
            len++;
        }
        best = std::max(best, len);
    }
    return best;
}
inline size_t longestSequence(const std::string& s) {
    size_t best = s.empty() ? 0 : 1;
    for (size_t i = 0; i < s.size(); i++) best = std::max(best, sequenceRunAt(s, i));
    return best;
}

inline const std::vector<std::string>& keyboardRows() {
    static const std::vector<std::string> rows = [] {
        std::vector<std::string> base = {"qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "!@#$%^&*()",
                                         "qazwsxedcrfv", "1q2w3e4r5t6y", "zaq12wsxcde3"};
        std::vector<std::string> all = base;
        for (auto b : base) { std::reverse(b.begin(), b.end()); all.push_back(b); }
        return all;
    }();
    return rows;
}
// longest keyboard-adjacent run starting at i (input must be lower-cased)
inline size_t keyboardRunAt(const std::string& low, size_t i) {
    size_t best = 0;
    for (size_t L = 2; i + L <= low.size(); L++) {
        std::string sub = low.substr(i, L);
        bool found = false;
        for (const auto& r : keyboardRows()) if (r.find(sub) != std::string::npos) { found = true; break; }
        if (!found) break;
        best = L;
    }
    return best;
}
inline bool hasKeyboardWalk(const std::string& low, size_t minLen = 4) {
    for (size_t i = 0; i < low.size(); i++) if (keyboardRunAt(low, i) >= minLen) return true;
    return false;
}

// "abcabc", "Xy9Xy9Xy9"  (whole string periodic, or a block repeated >= 3x)
inline bool hasRepeatedBlocks(const std::string& s) {
    size_t n = s.size();
    for (size_t p = 2; p <= n / 2; ++p) {
        if (n % p) continue;
        bool ok = true;
        for (size_t i = p; i < n; ++i) if (s[i] != s[i - p]) { ok = false; break; }
        if (ok) return true;
    }
    for (size_t p = 2; p <= n / 3; ++p)
        for (size_t i = 0; i + 3 * p <= n; ++i) {
            bool ok = true;
            for (size_t j = 0; j < 2 * p; ++j) if (s[i + j] != s[i + j + p]) { ok = false; break; }
            if (ok) return true;
        }
    return false;
}

// ------------------------------------------------ common-password / leetspeak
// lower-case + three leetspeak views (plain, 1->i, 1->l) so "P@ssw0rd" == "password"
inline std::vector<std::string> normVariants(const std::string& s) {
    std::string plain = toLower(s), v1 = plain, v2 = plain;
    auto sub = [](char c, char one) -> char {
        switch (c) {
            case '@': case '4': return 'a';
            case '3': return 'e';
            case '0': return 'o';
            case '$': case '5': return 's';
            case '7': case '+': return 't';
            case '!': return 'i';
            case '|': return 'l';
            case '1': return one;
            default: return c;
        }
    };
    for (auto& c : v1) c = sub(c, 'i');
    for (auto& c : v2) c = sub(c, 'l');
    std::vector<std::string> out = {plain};
    if (v1 != plain) out.push_back(v1);
    if (v2 != plain && v2 != v1) out.push_back(v2);
    return out;
}

inline const std::unordered_set<std::string>& commonSet() {
    static const std::unordered_set<std::string> s = {
        "password", "password1", "passw0rd", "pass", "pass123", "123456", "1234567", "12345678", "123456789",
        "1234567890", "12345", "1234", "111111", "000000", "0000", "1111", "123123", "654321", "112233",
        "121212", "qwerty", "qwerty123", "qwertyuiop", "qwertyui", "abc123", "abcdef", "abcd1234", "admin",
        "administrator", "root", "toor", "letmein", "welcome", "welcome1", "login", "access", "monkey", "dragon",
        "master", "sunshine", "princess", "football", "baseball", "basketball", "soccer", "cricket", "iloveyou",
        "iloveu", "loveme", "trustno1", "superman", "batman", "starwars", "hello", "hello123", "freedom",
        "whatever", "shadow", "michael", "jennifer", "jordan", "hunter", "ranger", "buster", "thomas", "robert",
        "daniel", "andrew", "charlie", "ashley", "bailey", "flower", "hottie", "zaq12wsx", "1q2w3e4r", "1qaz2wsx",
        "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm", "qazwsx", "mustang", "harley", "ginger", "pepper", "cheese",
        "summer", "winter", "spring", "autumn", "secret", "changeme", "default", "guest", "test", "testing",
        "test123", "temp", "temp123", "computer", "internet", "samsung", "google", "facebook", "myspace",
        "india", "delhi", "mumbai", "krishna", "ganesh", "shiva", "sachin", "rahul", "priya", "lakers",
        "yankees", "liverpool", "arsenal", "chelsea", "pokemon", "naruto", "matrix", "killer", "jesus", "angel",
        "purple", "orange", "banana", "cookie", "silver", "golden", "diamond", "secure", "security", "system",
        "server", "oracle", "windows", "linux", "ubuntu", "iloveyou1", "abc", "aaaaaa", "asdasd", "zzzzzz"};
    return s;
}

// Returns the dictionary entry matched, or "" (minContain = shortest word allowed as a substring)
inline std::string commonMatch(const std::string& simp, size_t minContain = 6) {
    const auto& dict = commonSet();
    for (const auto& v : normVariants(simp)) {
        if (dict.count(v)) return v;
        size_t e = v.size();
        while (e > 0 && !isLo((unsigned char)v[e - 1])) e--;
        size_t b = 0;
        while (b < e && !isLo((unsigned char)v[b])) b++;
        if (e > b) { std::string core = v.substr(b, e - b); if (dict.count(core)) return core; }
        for (const auto& w : dict) if (w.size() >= minContain && v.find(w) != std::string::npos) return w;
    }
    return "";
}

inline bool containsNormalized(const std::string& hay, const std::string& needle) {
    if (needle.empty()) return false;
    for (const auto& h : normVariants(hay))
        for (const auto& n : normVariants(needle))
            if (h.find(n) != std::string::npos) return true;
    return false;
}

// ------------------------------------------------------- entropy / strength
struct Strength {
    double bits = 0, bitsPerChar = 0;
    int score = 0;                       // 0..100
    std::string level = "n/a";
    std::vector<std::string> findings, suggestions;
};

inline double log2d(double x) { return std::log(x) / std::log(2.0); }

inline std::string humanTime(double sec) {
    char buf[64];
    auto unit = [&](double v, const char* one, const char* many) {
        long long r = (long long)std::floor(v + 0.5);
        std::snprintf(buf, sizeof buf, "%lld %s", r, r == 1 ? one : many);
        return std::string(buf);
    };
    if (sec < 1) return "instantly (under 1 second)";
    if (sec < 60) return unit(sec, "second", "seconds");
    double m = sec / 60;   if (m < 60) return unit(m, "minute", "minutes");
    double h = m / 60;     if (h < 24) return unit(h, "hour", "hours");
    double d = h / 24;     if (d < 365) return unit(d, "day", "days");
    double y = d / 365.25;
    if (y < 1e6) return unit(y, "year", "years");
    if (y < 1e9) { std::snprintf(buf, sizeof buf, "%.1f million years", y / 1e6); return buf; }
    return "over a billion years";
}
// average brute-force time = half the search space
inline std::string crackTime(double bits, double guessesPerSec) {
    return humanTime(std::pow(2.0, std::max(0.0, bits - 1.0)) / guessesPerSec);
}

// zxcvbn-lite: walks the password and prices each chunk the way an attacker's
// guessing strategy would (dictionary word, year, sequence, keyboard walk, repeat, random char).
inline Strength estimate(const std::string& pwd) {
    Strength st;
    size_t uniq = 0;
    std::string simp = simplify(pwd, &uniq);
    Counts c = countClasses(simp, uniq);
    size_t n = simp.size();
    if (n == 0) { st.level = "Very Weak"; st.findings.push_back("Empty password"); return st; }

    double pool = 0;
    if (c.lower) pool += 26;
    if (c.upper) pool += 26;
    if (c.digit) pool += 10;
    if (c.special || c.space) pool += 33;
    if (c.nonAscii) pool += 50;
    if (pool < 10) pool = 10;
    double bpc = log2d(pool);
    st.bitsPerChar = bpc;

    std::string low = toLower(simp);
    const auto& dict = commonSet();
    double bits = 0;
    bool sRep = false, sDict = false, sSeq = false, sKb = false, sYear = false;
    std::string dictHit;

    size_t i = 0;
    while (i < n) {
        size_t r = repeatRunAt(simp, i);
        if (r >= 3) { bits += bpc + log2d((double)r); i += r; sRep = true; continue; }

        bool hit = false;
        size_t maxL = std::min<size_t>(24, n - i);
        for (size_t L = maxL; L >= 4 && !hit; --L) {
            std::string seg = simp.substr(i, L);
            auto vars = normVariants(seg);
            for (size_t k = 0; k < vars.size(); k++) {
                if (dict.count(vars[k])) {
                    bool anyUpper = false;
                    for (char ch : seg) if (isUp((unsigned char)ch)) anyUpper = true;
                    bits += 14.0 + (anyUpper ? 1.0 : 0.0) + (k > 0 ? 2.0 : 0.0);
                    if (dictHit.empty()) dictHit = vars[k];
                    i += L; hit = true; sDict = true;
                    break;
                }
            }
        }
        if (hit) {
            // attackers' rule engines append short digit/symbol suffixes (123, 2024!, !!) to
            // dictionary words, so a <=4 char non-letter tail costs ~2 bits per character
            size_t rest = n - i;
            bool tail = rest > 0 && rest <= 4;
            for (size_t j = i; tail && j < n; ++j) if (isLo((unsigned char)low[j])) tail = false;
            if (tail) { bits += 2.0 * (double)rest; i = n; }
            continue;
        }

        if (i + 4 <= n && isDi((unsigned char)low[i]) && isDi((unsigned char)low[i + 1]) &&
            isDi((unsigned char)low[i + 2]) && isDi((unsigned char)low[i + 3]) &&
            ((low[i] == '1' && low[i + 1] == '9') || (low[i] == '2' && low[i + 1] == '0'))) {
            bits += 7.0; i += 4; sYear = true; continue;   // ~130 plausible years
        }

        size_t sq = sequenceRunAt(simp, i);
        if (sq >= 3) { bits += bpc + 2.0; i += sq; sSeq = true; continue; }

        size_t kb = keyboardRunAt(low, i);
        if (kb >= 4) { bits += bpc + 3.0; i += kb; sKb = true; continue; }

        bits += bpc;
        ++i;
    }

    st.bits = bits;
    st.score = (int)std::min(100.0, std::floor(bits * 1.25 + 0.5));
    st.level = bits < 28 ? "Very Weak" : bits < 36 ? "Weak" : bits < 60 ? "Reasonable" : bits < 80 ? "Strong" : "Very Strong";

    if (sDict) st.findings.push_back("Built on a common word/password (\"" + dictHit + "\"); attackers try these first, including leetspeak and case tricks");
    if (sYear) st.findings.push_back("Contains a year-like number, which is easy to guess");
    if (sRep)  st.findings.push_back("Contains long runs of the same character");
    if (sSeq)  st.findings.push_back("Contains sequential characters (abc, 4321, ...)");
    if (sKb)   st.findings.push_back("Contains a keyboard pattern (qwerty, asdf, 1qaz, ...)");
    if (c.unique * 2 < n) st.findings.push_back("Fewer than half of the characters are distinct");

    if (bits < 60) {
        int more = (int)std::ceil((60.0 - bits) / bpc);
        st.suggestions.push_back("Adding about " + std::to_string(more) + " more random character(s) would reach ~60 bits");
    }
    if (n < 12) st.suggestions.push_back("Length is the strongest lever: aim for 14+ characters or a passphrase of 4+ unrelated words");
    if (sDict) st.suggestions.push_back("Replace the dictionary word with something unpredictable; substituting @ for a or 0 for o does not help");
    if (sSeq || sKb || sRep) st.suggestions.push_back("Avoid sequences, keyboard walks and repeated characters");
    return st;
}

// ------------------------------------------------------------- policy checker
inline bool needsUser(const Policy& p) { return p.noUserInfo == 1; }

inline std::vector<Violation> check(const std::string& pwd, const Policy& p, const std::string& user = "") {
    std::vector<Violation> v;
    auto add = [&](const char* rule, const std::string& msg) { v.push_back({rule, msg}); };

    if (pwd.size() > kMaxInputBytes) {
        add("inputLimit", "Input exceeds the " + std::to_string(kMaxInputBytes) +
                          "-byte safety limit; rejected without further analysis.");
        return v;
    }
    size_t uniq = 0;
    std::string simp = simplify(pwd, &uniq);
    Counts c = countClasses(simp, uniq);
    std::string low = toLower(simp);
    long long len = (long long)c.length;

    if (p.minLength != -1 && len < p.minLength)
        add("minLength", "Too short: " + std::to_string(len) + " characters, minimum is " + std::to_string(p.minLength) + ".");
    if (p.maxLength != -1 && len > p.maxLength)
        add("maxLength", "Too long: " + std::to_string(len) + " characters, maximum is " + std::to_string(p.maxLength) + ".");

    struct Cls { const char* reqName; const char* minName; int req; int mn; int have; const char* label; const char* example; };
    const Cls classes[] = {
        {"requireUpper",   "minUpper",   p.requireUpper,   p.minUpper,   c.upper,   "uppercase letter", "A-Z"},
        {"requireLower",   "minLower",   p.requireLower,   p.minLower,   c.lower,   "lowercase letter", "a-z"},
        {"requireDigit",   "minDigit",   p.requireDigit,   p.minDigit,   c.digit,   "digit",            "0-9"},
        {"requireSpecial", "minSpecial", p.requireSpecial, p.minSpecial, c.special, "special character", "e.g. !@#"},
    };
    for (const auto& k : classes) {
        int need = std::max(k.mn > 0 ? k.mn : 0, k.req == 1 ? 1 : 0);
        const char* rule = k.mn != -1 ? k.minName : k.reqName;
        if (need > 0 && k.have < need) {
            if (need == 1) add(rule, std::string("Missing ") + k.label + " (" + k.example + ").");
            else add(rule, "Needs at least " + std::to_string(need) + " " + k.label + "s (found " + std::to_string(k.have) + ").");
        }
        if (k.req == 0 && k.have > 0)
            add(k.reqName, std::string("A ") + k.label + " is forbidden by this policy.");
    }

    if (p.noSpaces == 1 && c.space > 0) add("noSpaces", "Whitespace characters are not allowed.");

    if (p.maxRepeat != -1) {
        size_t r = longestRepeat(simp);
        if ((long long)r > p.maxRepeat)
            add("maxRepeat", "Same character repeated " + std::to_string(r) + " times in a row (max " + std::to_string(p.maxRepeat) + ").");
    }
    if (p.maxSequence != -1) {
        size_t s = longestSequence(simp);
        if ((long long)s > p.maxSequence)
            add("maxSequence", "Sequential run of " + std::to_string(s) + " characters like abc/4321 (max " + std::to_string(p.maxSequence) + ").");
    }
    if (p.minUnique != -1 && (long long)c.unique < p.minUnique)
        add("minUnique", "Only " + std::to_string(c.unique) + " distinct characters; at least " + std::to_string(p.minUnique) + " required.");
    if (p.blockCommon == 1 && !commonMatch(simp).empty())
        add("blockCommon", "Matches a common/breached password pattern (case, leetspeak and trailing digits are normalised).");
    if (p.noKeyboardPatterns == 1 && hasKeyboardWalk(low))
        add("noKeyboardPatterns", "Contains a keyboard pattern such as qwer, asdf or 1qaz.");
    if (p.noRepeatedBlocks == 1 && hasRepeatedBlocks(simp))
        add("noRepeatedBlocks", "Contains a repeated block (like abcabc).");
    if (p.noUserInfo == 1 && user.size() >= 3) {
        std::string rev(user.rbegin(), user.rend());
        if (containsNormalized(simp, user) || containsNormalized(simp, rev))
            add("noUserInfo", "Password contains the username (or its reverse).");
    }
    for (const auto& w : p.forbiddenWords)
        if (containsNormalized(simp, w)) { add("forbidWord", "Contains a word forbidden by this policy."); break; }
    if (p.minEntropy != -1) {
        double bits = estimate(pwd).bits;
        if (bits < p.minEntropy) {
            char buf[32]; std::snprintf(buf, sizeof buf, "%.1f", bits);
            add("minEntropy", std::string("Estimated entropy ") + buf + " bits is below the required " + std::to_string(p.minEntropy) + " bits.");
        }
    }
    return v;
}

// ------------------------------------------------------------------- evaluate
struct Evaluation {
    bool valid = true;
    bool userCheckSkipped = false;
    std::vector<Violation> violations;
    Strength strength;
};

inline Evaluation evaluate(const std::string& pwd, const Policy& p, const std::string& user) {
    Evaluation ev;
    ev.violations = check(pwd, p, user);
    ev.valid = ev.violations.empty();
    ev.userCheckSkipped = needsUser(p) && user.size() < 3;
    if (pwd.size() <= kMaxInputBytes) ev.strength = estimate(pwd);
    return ev;
}

inline void printEvaluation(const Evaluation& ev, std::ostream& os) {
    os << (ev.valid ? "\n[PASS] STATUS: VALID\n" : "\n[FAIL] STATUS: INVALID\n");
    if (!ev.valid) {
        os << "\n-- Policy violations (symbolic layer) --\n";
        for (const auto& x : ev.violations) os << "* [" << x.rule << "] " << x.message << "\n";
    }
    if (ev.userCheckSkipped)
        os << "\nNote: policy has noUserInfo but no username was supplied (use --user NAME); that check was skipped.\n";
    const Strength& s = ev.strength;
    os << "\n-- Strength analysis (neural-inspired layer) --\n";
    char buf[64];
    std::snprintf(buf, sizeof buf, "%.1f", s.bits);
    os << "Score            : " << s.score << "/100  (" << s.level << ")\n";
    os << "Estimated entropy: " << buf << " bits\n";
    os << "Crack time       : " << crackTime(s.bits, 1e10) << " (offline, 10 billion guesses/s)\n";
    os << "                   " << crackTime(s.bits, 100) << " (online, 100 guesses/s)\n";
    for (const auto& f : s.findings) os << "! " << f << "\n";
    for (const auto& g : s.suggestions) os << "> " << g << "\n";
}

// ------------------------------------------------------- secure input & memory
// Best-effort wipe (volatile write so the compiler cannot drop it).  Copies made
// earlier by the C++ runtime cannot be reached, so treat it as defence-in-depth.
inline void secureWipe(std::string& s) {
    if (!s.empty()) { volatile char* p = &s[0]; for (size_t i = 0; i < s.size(); ++i) p[i] = 0; }
    s.clear();
}

// Reads one line with terminal echo disabled; input beyond kMaxInputBytes is discarded.
inline bool readSecret(const std::string& prompt, std::string& out) {
    std::cout << prompt << std::flush;
    out.clear();
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    bool tty = GetConsoleMode(h, &mode) != 0;
    if (tty) SetConsoleMode(h, mode & ~ENABLE_ECHO_INPUT);
#else
    termios old{};
    bool tty = isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &old) == 0;
    if (tty) { termios t = old; t.c_lflag &= ~(tcflag_t)ECHO; tcsetattr(STDIN_FILENO, TCSANOW, &t); }
#endif
    bool got = false;
    char ch;
    while (std::cin.get(ch)) {
        got = true;
        if (ch == '\n') break;
        if (ch == '\r') continue;
        if (out.size() <= kMaxInputBytes) out.push_back(ch);
    }
#ifdef _WIN32
    if (tty) SetConsoleMode(h, mode);
#else
    if (tty) tcsetattr(STDIN_FILENO, TCSANOW, &old);
#endif
    if (tty) std::cout << "\n";
    return got;
}

// ------------------------------------------------------------ secure generator
// OS CSPRNG only.  Never falls back to a weak PRNG: it aborts instead.
inline uint32_t secureRandom32() {
#ifdef _WIN32
    uint32_t v = 0;
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        if (CryptGenRandom(hProv, sizeof(v), (BYTE*)&v)) {
            CryptReleaseContext(hProv, 0);
            return v;
        }
        CryptReleaseContext(hProv, 0);
    }
    std::random_device rd;
    return (uint32_t)rd();
#else
    static std::FILE* f = std::fopen("/dev/urandom", "rb");
    uint32_t v = 0;
    if (!f || std::fread(&v, sizeof v, 1, f) != 1) { std::cerr << "FATAL: /dev/urandom unavailable.\n"; std::exit(2); }
    return v;
#endif
}
// uniform in [0,n) using rejection sampling (no modulo bias)
inline uint32_t randBelow(uint32_t n) {
    uint32_t limit = UINT32_MAX - (UINT32_MAX % n);
    uint32_t v;
    do { v = secureRandom32(); } while (v >= limit);
    return v % n;
}

// Generates a random password that satisfies the policy ("" if impossible).
inline std::string generate(const Policy& p, const std::string& user = "") {
    const std::string U = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", L = "abcdefghijklmnopqrstuvwxyz",
                      D = "0123456789", S = "!@#$%^&*()-_=+[]{};:,.<>?/~";
    auto need = [](int mn, int rq) { return std::max(mn > 0 ? mn : 0, rq == 1 ? 1 : 0); };
    struct G { const std::string* set; bool allowed; int need; };
    G g[4] = {{&U, p.requireUpper != 0, need(p.minUpper, p.requireUpper)},
              {&L, p.requireLower != 0, need(p.minLower, p.requireLower)},
              {&D, p.requireDigit != 0, need(p.minDigit, p.requireDigit)},
              {&S, p.requireSpecial != 0, need(p.minSpecial, p.requireSpecial)}};
    std::string pool;
    int sumNeed = 0;
    for (auto& x : g) {
        if (x.allowed) pool += *x.set;
        else if (x.need > 0) return "";
        sumNeed += x.need;
    }
    if (pool.empty()) return "";
    int minLen = std::max({p.minLength, 1, sumNeed, p.minUnique});
    int maxLen = p.maxLength == -1 ? 64 : p.maxLength;
    if (minLen > maxLen) return "";
    int target = std::min(std::max(16, minLen), maxLen);

    for (int attempt = 0; attempt < 600; attempt++) {
        int len = std::min(maxLen, target + (attempt / 30) * 2);
        std::string pw;
        for (auto& x : g) for (int i = 0; i < x.need; i++) pw.push_back((*x.set)[randBelow((uint32_t)x.set->size())]);
        while ((int)pw.size() < len) pw.push_back(pool[randBelow((uint32_t)pool.size())]);
        for (size_t i = pw.size(); i > 1; --i) std::swap(pw[i - 1], pw[randBelow((uint32_t)i)]);   // Fisher-Yates
        if (check(pw, p, user).empty()) return pw;
        secureWipe(pw);
    }
    return "";
}

// ---------------------------------------------------------------------- SHA-256
inline std::string sha256Hex(const std::string& msg) {
    static const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    std::string m = msg;
    uint64_t bitLen = (uint64_t)msg.size() * 8;
    m.push_back((char)0x80);
    while (m.size() % 64 != 56) m.push_back(0);
    for (int i = 7; i >= 0; --i) m.push_back((char)((bitLen >> (8 * i)) & 0xff));
    auto rotr = [](uint32_t x, int n) { return (x >> n) | (x << (32 - n)); };
    for (size_t off = 0; off < m.size(); off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)(unsigned char)m[off + 4 * i] << 24) | ((uint32_t)(unsigned char)m[off + 4 * i + 1] << 16) |
                   ((uint32_t)(unsigned char)m[off + 4 * i + 2] << 8) | (uint32_t)(unsigned char)m[off + 4 * i + 3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + mj;
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    static const char* hex = "0123456789abcdef";
    std::string out;
    for (int i = 0; i < 8; i++) for (int j = 28; j >= 0; j -= 4) out.push_back(hex[(h[i] >> j) & 0xf]);
    return out;
}

inline std::string fingerprint(const Policy& p) { return sha256Hex(toPolicyText(p)); }

// ------------------------------------------------- CLI used by generated programs
inline int runCli(const Policy& p, const std::string& expectedFp, int argc, char** argv) {
    std::string user;
    int genCount = 0;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--user" && i + 1 < argc) user = argv[++i];
        else if (a == "--generate") {
            genCount = 1;
            if (i + 1 < argc && std::atoi(argv[i + 1]) > 0) genCount = std::min(50, std::atoi(argv[++i]));
        } else if (a == "--help" || a == "-h") {
            std::cout << "Usage: validator [--user NAME] [--generate [N]]\n"
                         "  Reads the password from stdin (hidden if interactive).\n"
                         "  Exit code: 0 = valid, 1 = invalid, 2 = error/integrity failure.\n";
            return 0;
        }
    }
    if (fingerprint(p) != expectedFp) {
        std::cerr << "INTEGRITY FAILURE: the embedded policy table does not match its fingerprint.\n"
                     "The generated file was modified after compilation. Regenerate it.\n";
        return 2;
    }
    std::cout << "========================================\n"
                 "  Standalone Target Policy Evaluator\n"
                 "========================================\n"
              << "Policy fingerprint: " << expectedFp.substr(0, 16) << "...\n";
    if (genCount > 0) {
        for (int i = 0; i < genCount; i++) {
            std::string g = generate(p, user);
            if (g.empty()) { std::cerr << "This policy cannot be satisfied by the generator.\n"; return 2; }
            std::cout << g << "\n";
            secureWipe(g);
        }
        return 0;
    }
    std::string pwd;
    if (!readSecret("Enter a password to validate: ", pwd)) { std::cerr << "No input.\n"; return 2; }
    Evaluation ev = evaluate(pwd, p, user);
    secureWipe(pwd);
    printEvaluation(ev, std::cout);
    return ev.valid ? 0 : 1;
}

} // namespace pwrt
#endif
