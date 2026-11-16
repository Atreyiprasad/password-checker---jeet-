#ifndef SEMANTIC_H
#define SEMANTIC_H

#include "ast.h"
#include "pw_runtime.h"
#include <vector>
#include <string>

struct SemanticError {
    std::string message;
    SourcePos pos;
};

// The validated policy. Same layout as the runtime's Policy:
//   -1 = not specified, 1 = true, 0 = false (booleans);  forbiddenWords = all forbidWord rules
struct PolicyConstraints : pwrt::Policy {};

class SemanticAnalyzer {
    std::vector<SemanticError> errs;
    std::vector<SemanticError> warns;
    PolicyConstraints constraints;

public:
    void analyze(const ProgramNode& prog);

    const std::vector<SemanticError>& errors() const { return errs; }
    const std::vector<SemanticError>& warnings() const { return warns; }
    const PolicyConstraints& getConstraints() const { return constraints; }
};

#endif
