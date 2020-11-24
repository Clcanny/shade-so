// gcc -fPIC -ggdb -O0 -shared
// -Wl,--dynamic-linker=/root/glibc/build/install/lib/ld-linux-x86-64.so.2
// foo.cpp -o libfoo.so
namespace {
int var = 0;
}
void foo() {
}
