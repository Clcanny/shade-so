all : clean compile run

clean :
	rm -f libfoo.so main merge main-hooked

compile :
	gcc -std=c++11 foo.cpp -O0 -ggdb -shared -o libfoo.so
	gcc main.cpp -O0 -ggdb -L${PWD} -Wl,-rpath=${PWD} -lfoo -o main
	g++ -std=c++11 -O0 -ggdb merge.cpp                                                   \
		-I/usr/include/LIEF-0.11.0-Linux/include -L/usr/lib/LIEF-0.11.0-Linux/lib -lLIEF \
        -I/usr/local/include/Zydis -I/usr/local/include/Zycore -L/usr/local/lib -lZydis  \
        -o merge

run :
	./merge
	chmod u+x main-hooked
	./main-hooked
