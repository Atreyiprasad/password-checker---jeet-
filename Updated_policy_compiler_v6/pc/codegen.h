#ifndef CODEGEN_H
#define CODEGEN_H

#include "ir.h"
#include <string>

// Emits a standalone C++ validator (single file, no dependencies) for the given IR.
class CodeGenerator {
public:
    static bool generate(const PolicyIR& ir, const std::string& outputFile);
};

#endif
