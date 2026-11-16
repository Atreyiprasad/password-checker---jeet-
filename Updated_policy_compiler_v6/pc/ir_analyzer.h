#ifndef IR_ANALYZER_H
#define IR_ANALYZER_H

#include "ir.h"
#include <vector>
#include <string>

enum class Severity { Info, Warning, Critical };

struct IRWarning {
    Severity severity;
    std::string message;
};

struct IRReport {
    std::vector<IRWarning> findings;
    int score = 0;            // 0..100 policy quality score
    std::string grade;        // A..F
};

class IRAnalyzer {
public:
    static IRReport analyze(const PolicyIR& ir);
    // Returns a stronger version of the policy as policy-file text (with comments).
    static std::string harden(const PolicyIR& ir);
};

#endif
