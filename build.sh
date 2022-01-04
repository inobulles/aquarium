#!/bin/sh
set -e

# TODO remove redundant entries in `.gitignore`

# compile library

cc -std=c99 -fPIC -c src/libbob.c -o bin/libbob.o -I src/

# create static library

ar rc bin/libbob.a bin/libbob.o

# index static library

ranlib bin/libbob.a

# create shared library

ld -shared bin/libbob.o -o bin/libbob.so