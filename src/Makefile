compile :
	g++ -std=c++2a -O0 -ggdb -c handle_lazy_symbol_binding.cpp                           \
		-I/usr/include/LIEF-0.11.0-Linux/include -L/usr/lib/LIEF-0.11.0-Linux/lib -lLIEF \
		-I..                                                                             \
        -o handle_lazy_symbol_binding.o
	g++ -std=c++2a -O0 -ggdb -c validate_format.cpp                                      \
		-I/usr/include/LIEF-0.11.0-Linux/include -L/usr/lib/LIEF-0.11.0-Linux/lib -lLIEF \
		-I/usr/local/include/Zydis -I/usr/local/include/Zycore -L/usr/local/lib -lZydis  \
		-I..                                                                             \
        -o validate_format.o
