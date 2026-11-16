#include "neurosymbolic.h"
#include <iostream>

NSResult NeuroSymbolicEvaluator::evaluate(const std::string& password, const PolicyIR& ir,
                                          const std::string& username)
{
    return pwrt::evaluate(password, ir.p, username);
}

void NeuroSymbolicEvaluator::print(const NSResult& r)
{
    pwrt::printEvaluation(r, std::cout);
}
