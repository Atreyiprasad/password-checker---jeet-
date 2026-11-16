#include "ir.h"
#include <algorithm>
#include <cmath>

using namespace std;

PolicyIR buildIR(const PolicyConstraints& c)
{
    PolicyIR ir;
    ir.p = c;   // slices PolicyConstraints down to pwrt::Policy

    // PASS 1 - normalise forbidden words: lower-case, sort, de-duplicate
    size_t before = ir.p.forbiddenWords.size();
    for(auto& w : ir.p.forbiddenWords) w = pwrt::toLower(w);
    sort(ir.p.forbiddenWords.begin(), ir.p.forbiddenWords.end());
    ir.p.forbiddenWords.erase(unique(ir.p.forbiddenWords.begin(), ir.p.forbiddenWords.end()),
                              ir.p.forbiddenWords.end());
    ir.passes.push_back("normalize-words: " + to_string(before) + " forbidWord rule(s) -> " +
                        to_string(ir.p.forbiddenWords.size()) + " unique lower-case word(s)");

    // PASS 2 - derive the true minimum length implied by all rules together
    int sumNeed = 0, required = 0;
    auto need = [](int mn, int rq) { return max(mn > 0 ? mn : 0, rq == 1 ? 1 : 0); };
    int n[4] = { need(ir.p.minUpper, ir.p.requireUpper), need(ir.p.minLower, ir.p.requireLower),
                 need(ir.p.minDigit, ir.p.requireDigit), need(ir.p.minSpecial, ir.p.requireSpecial) };
    for(int x : n) { sumNeed += x; if(x > 0) required++; }
    ir.classesRequired = required;
    ir.effectiveMinLength = max({ ir.p.minLength, sumNeed, ir.p.minUnique, 1 });
    if(ir.effectiveMinLength != max(ir.p.minLength, 1))
        ir.passes.push_back("derive-min-length: declared minLength " + to_string(ir.p.minLength) +
                            " but other rules force at least " + to_string(ir.effectiveMinLength));
    else
        ir.passes.push_back("derive-min-length: effective minimum = " + to_string(ir.effectiveMinLength));

    // PASS 3 - permitted alphabet size and best-case keyspace
    ir.allowedPool = (ir.p.requireUpper != 0 ? 26 : 0) + (ir.p.requireLower != 0 ? 26 : 0) +
                     (ir.p.requireDigit != 0 ? 10 : 0) + (ir.p.requireSpecial != 0 ? 33 : 0);
    ir.minKeyspaceBits = ir.allowedPool > 0 ? ir.effectiveMinLength * pwrt::log2d((double)ir.allowedPool) : 0;
    ir.passes.push_back("keyspace: alphabet " + to_string(ir.allowedPool) + " symbols, best case " +
                        to_string((int)ir.minKeyspaceBits) + " bits at minimum length");

    // PASS 4 - fingerprint of the canonical form
    ir.fingerprint = pwrt::fingerprint(ir.p);
    ir.passes.push_back("fingerprint: sha256 = " + ir.fingerprint.substr(0, 16) + "...");

    return ir;
}
