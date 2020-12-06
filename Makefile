all : clean compile run

clean :
	rm -f libfoo.so main merge main-hooked

compile :
	g++ -std=c++11 foo.cpp -O0 -ggdb -shared -fPIC -o libfoo.so
	gcc main.cpp -O0 -ggdb -L${PWD} -Wl,-rpath=${PWD} -lfoo -Wl,--dynamic-linker=/root/glibc/build/install/lib/ld-linux-x86-64.so.2 -o main
	g++ -std=c++11 -O0 -ggdb merge.cpp                                                   \
		-I/usr/include/LIEF-0.11.0-Linux/include -L/usr/lib/LIEF-0.11.0-Linux/lib -lLIEF \
        -I/usr/local/include/Zydis -I/usr/local/include/Zycore -L/usr/local/lib -lZydis  \
        -o merge

run :
	./merge
	chmod u+x main-hooked
	./main-hooked
