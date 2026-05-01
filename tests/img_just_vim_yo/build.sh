#!/bin/sh
set -xe

aquarium="aquarium -r /tmp/aquariums"
template="amd64.freebsd.15-0-release"
pointer="aquarium"

rm -f $pointer

$aquarium -t $template -k $template create $pointer
$aquarium enter $pointer < custom.sh
$aquarium image $pointer final.img

rm $pointer
$aquarium sweep
