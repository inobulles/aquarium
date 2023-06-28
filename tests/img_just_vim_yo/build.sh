#!/bin/sh
set -xe

aquarium="../../bin/aquarium -r /tmp/aquariums"
version="0.1.0-beta"
pointer="aquarium"

rm -f $pointer
$aquarium -s

$aquarium -c $pointer -t amd64.aquabsd.$version -k amd64.aquabsd.$version
$aquarium -ve $pointer < custom.sh
$aquarium -i $pointer -o final.img

rm $pointer
$aquarium -s
