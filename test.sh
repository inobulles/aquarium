#!/bin/sh
set -xe

rm -rf .build
mkdir -p .build

cd img

for img in $(find . -type d -depth 1); do
	(
		cd $img
		sh build.sh
		cp final.img ../../.build/$img.img
	)
done
