#!/bin/sh
set -xe

prefix="../../bin/aquarium -r /tmp/aquariums"
version="0622a"
pointer="aquarium"
pkg_repo="/usr/local/etc/pkg/repos/FreeBSD.conf"

$prefix -f

rm -f $pointer
$prefix -s

$prefix -c $pointer -t amd64.aquabsd.$version -k amd64.aquabsd.$version

if [ -f $pkg_repo ]; then
	$prefix -y $pointer $pkg_repo /tmp
fi

$prefix -y $pointer files/* /tmp
$prefix -ve $pointer < custom.sh
$prefix -i $pointer -o final.img

rm $pointer
$prefix -s
