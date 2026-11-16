#ifndef NEURO_SYMBOLIC_H
#define NEURO_SYMBOLIC_H

#include "ir.h"
#include <string>

// Two cooperating layers:
//   symbolic layer        : exact, explainable policy rules  (pwrt::check)
//   neural-inspired layer : weighted, pattern-aware strength estimation (pwrt::estimate)
// The evaluator runs both and merges them into one verdict.
using NSResult = pwrt::Evaluation;

class NeuroSymbolicEvaluator {
public:
    static NSResult evaluate(const std::string& password, const PolicyIR& ir, const std::string& username);
    static void print(const NSResult& r);
};

#endif
