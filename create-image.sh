#!/bin/sh
set -e

out="out"
rootfs=$1

src=$2
. $src/tools/boot/install-boot.sh # include a bunch of helpful functions

rm -rf $out
mkdir $out

# make final UFS filesystem image

echo "[BOB] Creating UFS filesystem image ..."

label="aquabsd-installer"
image="$out/aquabsd.img"

echo "/dev/ufs/$label / ufs ro,noatime 1 1" > $rootfs/etc/fstab
echo "root_rw_mount=\"NO\"" > $rootfs/etc/rc.conf.local

makefs -B little -o label=$label -o version=2 $image.part $rootfs

# make EFI System Partition (ESP)

echo "[BOB] Creating ESP image ..."

esp_image="$out/esp.img"
make_esp_file $esp_image $fat32min $rootfs/boot/loader.efi

# assemble final system image

echo "[BOB] Assembling final image ..."

mkimg -s mbr -b $rootfs/boot/mbr -p efi:=$esp_image -p freebsd:-"mkimg -s bsd -b $rootfs/boot/boot -p freebsd-ufs:=$image.part" -a 2 -o $image

# cleanup

rm $esp_image
rm $image.part

#xz -v -9 -T $(sysctl -n hw.ncpu) $image
echo "[BOB] Done (output is in $image.xz)"