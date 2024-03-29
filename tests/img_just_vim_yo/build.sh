#!/bin/sh
set -xe

aquarium="../../bin/aquarium -r /tmp/aquariums"
version="0.1.1-beta"
pointer="aquarium"

rm -f $pointer

$aquarium -c $pointer -t amd64.aquabsd.$version -k amd64.aquabsd.$version
$aquarium -e $pointer < custom.sh
$aquarium -i $pointer -o final.img

rm $pointer
$aquarium -s
