build-image : build_image.sh Dockerfile
	./build_image.sh

run-container : run_container.sh
	./run_container.sh

compile :
	g++ -std=c++2a -O0 -ggdb -c handle_lazy_symbol_binding.cpp                           \
		-I/usr/include/LIEF-0.11.0-Linux/include -L/usr/lib/LIEF-0.11.0-Linux/lib -lLIEF \
		-I..                                                                             \
        -o handle_lazy_symbol_binding.o
