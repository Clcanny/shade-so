// gcc main.cpp -O0 -ggdb -L$PWD -Wl,-rpath=$PWD -lfoo -o main
extern void foo();
thread_local int a = 0;
thread_local int b = 1;
int main() {
    foo();
}
