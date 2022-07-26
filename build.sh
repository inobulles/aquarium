#!/bin/sh
set -e

mkdir -p bin

# compile library

cc -c src/libbob.c -Isrc -std=c99 -fPIC -o bin/libbob.o

# create static library

ar rc bin/libbob.a bin/libbob.o

# index static library

ranlib bin/libbob.a

# create shared library

cc -shared bin/libbob.o -o bin/libbob.so
