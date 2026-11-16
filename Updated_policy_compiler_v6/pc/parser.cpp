#include "parser.h"

using namespace std;

Parser::Parser(vector<Token> tokens) : ts(move(tokens)) {}

const Token& Parser::cur() const {
    if(k >= ts.size()) return ts.back();
    return ts[k];
}

void Parser::skipNewlines() {
    while(cur().type == PCTokenType::Newline)
        k++;
}

void Parser::skipLine() {
    while(cur().type != PCTokenType::Newline && cur().type != PCTokenType::End)
        k++;
    if(cur().type == PCTokenType::Newline)
        k++;
}

// rule := IDENT VALUE NEWLINE      VALUE := NUMBER | BOOLEAN | STRING
bool Parser::parseRule(RuleNode& out) {
    if(cur().type != PCTokenType::Identifier) {
        errs.push_back({"Expected rule name (identifier)", cur().pos});
        skipLine();
        return false;
    }

    Token nameTok = ts[k++];
    Token valTok = cur();

    if(valTok.type == PCTokenType::Number ||
       valTok.type == PCTokenType::Boolean ||
       valTok.type == PCTokenType::String) {
        k++;
    } else {
        errs.push_back({"Expected a value (number, true/false or \"text\") after '" +
                        nameTok.lexeme + "'", valTok.pos});
        skipLine();
        return false;
    }

    // exactly one rule per line
    if(cur().type != PCTokenType::Newline && cur().type != PCTokenType::End) {
        errs.push_back({"Unexpected '" + cur().lexeme +
                        "' after value; only one rule per line is allowed", cur().pos});
        skipLine();
    } else if(cur().type == PCTokenType::Newline) {
        k++;
    }

    out.name = nameTok.lexeme;
    out.value = valTok.lexeme;
    out.pos = nameTok.pos;
    out.valueType = valTok.type;
    return true;
}

ProgramNode Parser::parse() {
    ProgramNode prog;
    skipNewlines();

    while(cur().type != PCTokenType::End) {
        if(cur().type == PCTokenType::Newline) {
            skipNewlines();
            continue;
        }

        if(cur().type == PCTokenType::Unknown) {
            errs.push_back({"Unknown token in input", cur().pos});
            skipLine();
            continue;
        }

        RuleNode r;
        if(parseRule(r))
            prog.rules.push_back(r);
        skipNewlines();

        // DoS guard against absurdly large policy files
        if(prog.rules.size() > 500) {
            errs.push_back({"Too many rules (limit is 500)", cur().pos});
            break;
        }
    }
    return prog;
}
