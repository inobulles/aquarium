#!/bin/sh
set -e

# TODO remove redundant entries in `.gitignore`

# compile library

cc -c src/libbob.c -Isrc -std=c99 -fPIC -o bin/libbob.o

# create static library

ar rc bin/libbob.a bin/libbob.o

# index static library

ranlib bin/libbob.a

# create shared library

ld -shared bin/libbob.o -o bin/libbob.so