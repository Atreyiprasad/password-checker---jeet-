#ifndef TOKEN_H
#define TOKEN_H

#include <string>

// NOTE: reconstructed from how the other files use it (token.h was not in the upload).
// v2 change: added TokenType::String for  forbidWord "text"  rules.

struct SourcePos {
    int line = 1;
    int col  = 1;
};

enum class PCTokenType {
    Identifier,
    Number,
    Boolean,
    String,     // NEW in v2: "quoted text"
    Newline,
    End,
    Unknown
};

struct Token {
    PCTokenType type;
    std::string lexeme;
    SourcePos pos;
};

#endif
