#!/usr/bin/env sh
set -e

THREAD_COUNT=$(sysctl -n hw.ncpu)

# build kernel & userspace

echo -n "Compiling kernel and userland ..."
read _

cd /usr/src

make buildkernel -j$THREAD_COUNT
make buildworld -j$THREAD_COUNT WITHOUT_LIB32=yes WITHOUT_TOOLCHAIN=yes WITHOUT_TCSH=yes WITHOUT_FREEBSD_UPDATE=yes

# create root filesystem for final image

# check how things are done for the 'mini-memstick' target of '/usr/src/release/Makefile'
# something like 'make installkernel installworld DESTDIR=...'

# install packages required by some of the added userland programs
# e.g., install required libraries for AQUA devices

# use 'pkg' and its '-r' option