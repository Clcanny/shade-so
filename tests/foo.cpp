// gcc -fPIC -ggdb -O0 -shared
// -Wl,--dynamic-linker=/root/glibc/build/install/lib/ld-linux-x86-64.so.2
// foo.cpp -o libfoo.so
#include <iostream>
void bar();
void bar2();
const char* s1 = "s1";
// const std::string s2 = "s2";
// static std::string s3 = "s3";
// static thread_local std::string s4 = "s4";
void foo() {
    // bar();
    // bar2();
    // std::cout << "foo" << std::endl;
    std::cout << s1 << std::endl;
    // std::cout << s2 << std::endl;
    // std::cout << s3 << std::endl;
    // std::cout << s4 << std::endl;
}
