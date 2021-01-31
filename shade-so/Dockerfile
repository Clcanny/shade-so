FROM debian:unstable-20210111
LABEL maintainer="837940593@qq.com"

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update
RUN apt-get install -y wget git
RUN apt-get install -y build-essential cmake make gcc-10 g++-10 gdb
RUN ln -s /usr/bin/gcc-10 /usr/bin/gcc
RUN ln -s /usr/bin/g++-10 /usr/bin/g++

# Compile linker.
RUN mkdir /root/glibc
WORKDIR /root/glibc
RUN apt-get install -y gawk bison texinfo gettext python3-dev
RUN apt-get upgrade make
RUN wget http://ftp.gnu.org/gnu/libc/glibc-2.31.tar.gz
RUN tar -xzvf glibc-2.31.tar.gz
RUN mkdir build
WORKDIR /root/glibc/build
RUN ../glibc-2.31/configure CFLAGS="-O1 -ggdb -w" --with-tls --enable-add-ons=nptl --prefix="$PWD/install"
RUN make -j8 && make install -j8

# Install tools.
RUN apt-get install -y bsdmainutils

CMD /bin/bash
