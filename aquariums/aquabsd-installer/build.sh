#!/bin/sh
set -xe

prefix="../../bin/aquarium -r /tmp/aquarium"
version=0622a
pointer=aquarium

$prefix -f

rm -f $pointer
$prefix -s

$prefix -c $pointer -t amd64.aquabsd.$version -k amd64.aquabsd.$version

# TODO copy files in 'files' directory

$prefix -ve $pointer < custom.sh
$prefix -i $pointer -o final.img

rm $pointer
$prefix -s
