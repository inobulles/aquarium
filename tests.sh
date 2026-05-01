#!/bin/sh
set -e

all_passed=1

for test_dir in tests/img_*/; do
	printf "Running test %s... " "$test_dir"

	if (cd "$test_dir" && sh build.sh > /dev/null 2>&1); then
		echo "PASSED"
	else
		echo "FAILED"
		all_passed=0
	fi
done

if [ $all_passed = 0 ]; then
	echo "TESTS FAILED!" >&2
	exit 1
else
	echo "ALL TESTS PASSED!"
fi
