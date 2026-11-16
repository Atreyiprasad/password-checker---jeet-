CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra
SRC = main.cpp lexer.cpp parser.cpp semantic.cpp ir.cpp ir_analyzer.cpp neurosymbolic.cpp codegen.cpp agentic_ai.cpp ai_guard.cpp

policy_compiler: $(SRC) $(wildcard *.h)
	$(CXX) $(CXXFLAGS) $(SRC) -o $@

clean:
	rm -f policy_compiler generated_validator.cpp validator
