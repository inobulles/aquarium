#!/bin/sh
set -xe

aquarium="aquarium -r /tmp/aquariums"
version="0.1.0-beta"
pointer="aquarium"
pkg_repo="/usr/local/etc/pkg/repos/FreeBSD.conf"

rm -f $pointer
$aquarium -s

$aquarium -c $pointer -t amd64.aquabsd.$version -k amd64.aquabsd.$version
dir=$($aquarium | grep $(realpath $pointer) | cut -f2-)

echo $dir

if [ -f $pkg_repo ]; then
	$aquarium -y $pointer $pkg_repo /tmp
fi

su -l root -c "bob -p $dir/usr -C $(realpath ../..) install"
$aquarium -ve $pointer < custom.sh
$aquarium -i $pointer -o final.img

rm $pointer
$aquarium -s
