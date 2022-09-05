#!/bin/sh
set -xe

aquarium="../../bin/aquarium -r /tmp/aquariums"
version="0922a"
pointer="aquarium"
pkg_repo="/usr/local/etc/pkg/repos/FreeBSD.conf"

$aquarium -f

rm -f $pointer
$aquarium -s

$aquarium -c $pointer -t amd64.aquabsd.$version -k amd64.aquabsd.$version

if [ -f $pkg_repo ]; then
	$aquarium -y $pointer $pkg_repo /tmp
fi

$aquarium -y $pointer files/* /tmp
$aquarium -ve $pointer < custom.sh
$aquarium -i $pointer -o final.img

rm $pointer
$aquarium -s
