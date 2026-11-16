#ifndef AST_H
#define AST_H

#include "token.h"
#include <string>
#include <vector>

struct RuleNode {
    std::string name;
    std::string value;
    SourcePos pos;
    PCTokenType valueType = PCTokenType::Unknown;   // NEW: lets the semantic phase type-check values
};

struct ProgramNode {
    std::vector<RuleNode> rules;
};

#endif
