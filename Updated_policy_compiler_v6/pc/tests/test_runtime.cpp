#include "../pw_runtime.h"
#include <cassert>
using namespace pwrt;
static int fails=0;
#define T(c) do{ if(!(c)){ std::cout<<"FAIL line "<<__LINE__<<": "#c"\n"; fails++; } }while(0)
static bool has(const std::vector<Violation>& v,const char* r){ for(auto&x:v) if(x.rule==r) return true; return false; }
int main(){
    // sha256 vectors
    T(sha256Hex("abc")=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    T(sha256Hex("")=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    T(sha256Hex(std::string(1000,'a'))=="41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3");
    Policy p; p.minLength=8; p.requireUpper=1; p.requireLower=1; p.requireDigit=1;
    T(check("Abcdefg1",p).empty()); // no sequence rule enabled -> valid
    T(check("Xk9mPq2z",p).empty());
    T(has(check("xk9mpq2z",p),"requireUpper"));
    T(has(check("Xk9",p),"minLength"));
    // -1 must NOT mean required (old main.cpp bug)
    Policy q; q.minLength=3; T(check("abc",q).empty());
    // forbidden class
    Policy f; f.requireDigit=0; T(has(check("abc1",f),"requireDigit")); T(check("abcd",f).empty());
    // counts
    Policy m; m.minUpper=2; T(has(check("Abc",m),"minUpper")); T(check("ABc",m).empty());
    // repeat / sequence
    Policy r; r.maxRepeat=2; r.maxSequence=3;
    T(has(check("aaab",r),"maxRepeat")); T(check("aabb",r).empty());
    T(has(check("xabcdy",r),"maxSequence")); T(check("xabcy",r).empty()); T(has(check("x4321y",r),"maxSequence"));
    // common + leet
    Policy c; c.blockCommon=1;
    T(has(check("P@ssw0rd",c),"blockCommon")); T(has(check("Password123!",c),"blockCommon"));
    T(has(check("iloveyou",c),"blockCommon")); T(has(check("MyWelcome2024x",c),"blockCommon"));
    T(check("t7#Qm!vR9z",c).empty());
    // keyboard / blocks
    Policy k; k.noKeyboardPatterns=1; k.noRepeatedBlocks=1;
    T(has(check("xqwertyx",k),"noKeyboardPatterns")); T(has(check("zaq12wsx!",k),"noKeyboardPatterns"));
    T(has(check("abXYabXY",k),"noRepeatedBlocks")); T(has(check("Q1xyzxyzxyz",k),"noRepeatedBlocks"));
    T(check("t7#Qm!vR9z",k).empty());
    // username / forbidden words
    Policy u; u.noUserInfo=1; u.forbiddenWords={"acme"};
    T(has(check("xxPr1yaxx",u,"priya"),"noUserInfo"));
    T(has(check("xxayirP99!",u,"priya"),"noUserInfo")); // reversed username
    T(check("xxayirP99!",u,"").empty());
    T(has(check("my4CMEpass",u),"forbidWord")); // 4->a
    // unique
    Policy un; un.minUnique=5; T(has(check("aabbcc",un),"minUnique"));
    // entropy ordering
    T(estimate("password").bits < 20); T(estimate("Password123!").bits < 30);
    T(estimate("qwertyuiop").bits < 25); T(estimate("aaaaaaaaaaaa").bits < 15);
    T(estimate("t7#Qm!vR9zLp").bits > 70);
    T(estimate("correct horse battery staple").bits > estimate("Tr0ub4dor&3").bits);
    // UTF-8 length counted in characters
    Policy l; l.minLength=4; T(check("\xE0\xA4\xA8\xE0\xA4\xAE\xE0\xA4\xB8\xE0\xA5\x8D\xE0\xA4\xA4\xE0\xA5\x87",l).empty()==true);
    // DoS cap
    T(has(check(std::string(5000,'a'),p),"inputLimit"));
    // generator always satisfies the policy
    Policy g; g.minLength=12; g.requireUpper=1; g.requireLower=1; g.requireDigit=1; g.requireSpecial=1;
    g.blockCommon=1; g.maxRepeat=2; g.maxSequence=3; g.noKeyboardPatterns=1; g.minEntropy=60; g.minUpper=3;
    for(int i=0;i<300;i++){ auto s=generate(g); T(!s.empty()); T(check(s,g).empty()); }
    Policy g2; g2.minLength=5; g2.maxLength=5; g2.requireUpper=1; g2.requireLower=1; g2.requireDigit=1;
    for(int i=0;i<100;i++){ auto s=generate(g2); T(s.size()==5); T(check(s,g2).empty()); }
    Policy imp; imp.minLength=10; imp.maxLength=8; T(generate(imp).empty());
    // fingerprint stable + sensitive
    Policy a1=g, a2=g; T(fingerprint(a1)==fingerprint(a2)); a2.minLength=13; T(fingerprint(a1)!=fingerprint(a2));
    std::cout<<(fails?"TESTS FAILED\n":"all runtime tests passed\n");
    return fails?1:0;
}
