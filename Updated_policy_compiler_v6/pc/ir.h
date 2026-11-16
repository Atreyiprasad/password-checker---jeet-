#ifndef IR_H
#define IR_H

#include "semantic.h"
#include <string>
#include <vector>

// Intermediate representation: the validated policy plus facts derived by the IR passes.
struct PolicyIR {
    pwrt::Policy p;                     // normalised policy (forbidden words lower-cased, de-duplicated, sorted)

    int    effectiveMinLength = 1;      // max(minLength, sum of class minimums, minUnique)
    int    classesRequired = 0;         // how many of upper/lower/digit/special must appear
    int    allowedPool = 0;             // size of the permitted alphabet
    double minKeyspaceBits = 0;         // log2(pool ^ effectiveMinLength): best case for a RANDOM password at min length
    std::string fingerprint;            // SHA-256 of the canonical policy text
    std::vector<std::string> passes;    // human-readable log of what each pass did
};

PolicyIR buildIR(const PolicyConstraints& c);

#endif
