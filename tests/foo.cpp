// gcc -fPIC -ggdb -O0 -shared
// -Wl,--dynamic-linker=/root/glibc/build/install/lib/ld-linux-x86-64.so.2
// foo.cpp -o libfoo.so
#include <iostream>
void bar();
void bar2();
void foo() {
    bar();
    bar2();
    std::cout << "foo" << std::endl;
}
