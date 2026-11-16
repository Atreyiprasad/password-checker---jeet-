# Policy Compiler v2 - what changed and why

## Build & run
```
python3 tools/embed_runtime.py      # only needed if you edit pw_runtime.h
make                                # or: g++ -std=c++17 -O2 *.cpp -o policy_compiler   (from this folder, excluding tests/)
./policy_compiler samples/policy_strong.txt --user priya
```
Options: `--out FILE`, `--user NAME`, `--generate [N]`, `--harden FILE`, `--no-prompt`, `--verbose`.
Exit codes: 0 ok / password valid, 1 compile error / password invalid, 2 usage or I/O error (CI friendly).
`token.h` was missing from the upload, so a reconstructed one is included (adds `TokenType::String`). Replace yours with it.

## 1. New policy rules (language extension)
| Rule | Meaning |
|---|---|
| `minUpper/minLower/minDigit/minSpecial N` | at least N characters of that class |
| `maxRepeat N` | no more than N identical characters in a row (`aaaa`) |
| `maxSequence N` | no ascending/descending run longer than N (`abcd`, `4321`) |
| `minUnique N` | at least N distinct characters |
| `minEntropy N` | estimated entropy must be at least N bits (see 4) |
| `blockCommon true` | reject common/breached passwords, incl. `P@ssw0rd`, `Password123!`, `iloveyou` |
| `noKeyboardPatterns true` | reject `qwer`, `asdf`, `1qaz2wsx` walks (forwards and backwards) |
| `noRepeatedBlocks true` | reject `abcabc`, `Xy9Xy9Xy9` |
| `noUserInfo true` | password must not contain the username (or its reverse); pass `--user NAME` |
| `forbidWord "text"` | company/product words that must not appear (repeatable, leetspeak-aware) |

Old rules (`minLength`, `requireUpper` ...) work as before. `true` = required, `false` = forbidden, unset = not enforced.
One deliberate behaviour change: `noSpaces false` now means "spaces allowed", not "a space is required".

## 2. Security hardening of the compiler itself
* **Crash fixes.** `minLength true` or `minLength 99999999999` used to throw an uncaught exception in `stoi`. Values are now type-checked, range-checked (1..1024) and parsed overflow-safely.
* **Unspecified rules are no longer enforced.** `main.cpp` tested `c.requireUpper && ...` with the value `-1` (= unset), which is truthy in C++, so your sample policy silently demanded a special character. All checks now share one engine.
* **DoS limits:** policy file <= 64 KB, <= 500 rules, passwords analysed up to 4096 bytes (longer input is rejected up front).
* **Hidden password entry** (no terminal echo) and a best-effort **memory wipe** of the password after use.
* **Cryptographic generator:** OS CSPRNG (`/dev/urandom`, `rand_s` on Windows), rejection sampling (no modulo bias), Fisher-Yates shuffle, never falls back to a weak PRNG.
* **Policy fingerprint + integrity check:** SHA-256 of the canonical policy is printed and embedded in the generated validator. If someone edits the policy table in the generated `.cpp`, it refuses to run (exit 2). Note this detects edits to the table, it is not a signature against someone who can also edit the fingerprint or the code.
* **UTF-8 aware:** length counts characters, not bytes; the old `isupper(char)` undefined behaviour on negative chars is gone.

## 3. Smarter compile-time analysis
* **Type/duplicate/range errors** with source line + caret, and "Did you mean ...?" for every rule name.
* **Contradiction & unsatisfiability detection:** `requireUpper false` + `minUpper 2`; class minimums that exceed `maxLength`; `minEntropy` higher than the alphabet could ever reach; all classes forbidden.
* **IR passes** (`--verbose`): normalise forbidden words, derive the true effective minimum length, compute alphabet size and best-case keyspace, fingerprint.
* **Policy quality score (0-100, grade A-F)** with findings ranked Critical/Warning/Info, based on NIST SP 800-63B ideas (length over composition, allow 64+ chars, block common passwords). Your original sample scores **10/100 (F)**: length 5 is fixed, ~32 bits of keyspace.
* **`--harden FILE`** writes a stronger policy and lists exactly what changed. Your sample goes from 10 (F) to 87 (B).

## 4. Neuro-symbolic evaluator (two layers)
* **Symbolic layer:** exact rule checks with per-rule error codes, e.g. `[maxRepeat] ...`. Messages never echo the password.
* **Neural-inspired layer** (a hand-weighted model, not a trained network): a zxcvbn-style estimator that prices each chunk of the password the way an attacker's strategy would: dictionary words (+ leetspeak, capitalisation, short digit/symbol suffixes), years, sequences, keyboard walks, repeats, otherwise random characters. Output: entropy bits, score, level, crack-time estimates (offline 10^10 guesses/s and online 100/s), findings and concrete suggestions.

## 5. Code generation
The generated file is still a single standalone C++ file. It contains the compiled policy table, the same runtime engine the compiler uses (so compiler and validator can never disagree), and a CLI: `--user`, `--generate [N]`, hidden stdin input, exit code 0/1. Trade-off: the checks are table-driven rather than one hand-emitted `if` per rule.

## Known limits (be honest in your report)
* The built-in common-password list has ~170 entries. For real use, load a top-100k list.
* Non-ASCII letters (e.g. Devanagari) count as "special" characters.
* Windows paths (`rand_s`, console echo) are written but were not compiled in my environment. Linux (g++ 13) is tested, including ASan/UBSan and unit tests.
* `policy_compiler.html` (the JS demo) and the pipeline diagram were not updated; they still show the v1 rule set.

## v4 additions (dashboard)
* **Batch test runner** (`--json --batch FILE`, `/api/batch`, dashboard page "Batch test runner"): builds 100-200 labelled password cases (`testgen.py`, seeded so runs repeat), plus optional custom passwords, evaluates them against a policy in one engine run, and draws entropy charts (per case, histogram, per category). Reports weak passwords that were accepted and strong ones that were rejected. CSV export included.
* **Vulnerabilities page** (`vulns.json`, `/api/vulns`, `/api/vulncheck`): 10 findings from a security review, each with location, impact and fix. "Run live verification" reproduces 7 of them safely against the real build (generated code is parsed, never executed).
