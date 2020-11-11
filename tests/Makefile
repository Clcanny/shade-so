compile :
	g++ -std=c++11 foo.cpp -O0 -ggdb -shared -fPIC -o libfoo.so
	gcc main.cpp -O0 -ggdb               \
		-L${PWD} -Wl,-rpath=${PWD} -lfoo \
		-Wl,--dynamic-linker=/root/glibc/build/install/lib/ld-linux-x86-64.so.2 -o test.out
