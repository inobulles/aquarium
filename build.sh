#!/bin/sh
set -e

if [ $(id -u) != 0 ]; then
	echo "This script must be run as root 🥕"
	exit 1
fi

set -x

mkdir -p bin

# compile aquarium frontend

cc src/aquarium.c -g -larchive -lfetch -lcrypto -ljail /usr/lib/libcopyfile.a -o bin/aquarium

# add setuid bit to executable

chmod u+s bin/aquarium

# root user owns it

chown root:wheel bin/aquarium
