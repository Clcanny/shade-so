// gcc -fPIC -ggdb -O0 -shared
// -Wl,--dynamic-linker=/root/glibc/build/install/lib/ld-linux-x86-64.so.2
// foo.cpp -o libfoo.so
#include <iostream>
namespace {
int var = 1;

void bar() {
    std::cout << std::endl;
}
}  // namespace
void foo() {
    bar();
}
