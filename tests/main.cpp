// gcc main.cpp -O0 -ggdb -L$PWD -Wl,-rpath=$PWD -lfoo -o main
extern void foo();
int main() {
    foo();
}
