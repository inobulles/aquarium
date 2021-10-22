#!/bin/sh
set -e

rootfs="rootfs/"
src="src/"
out="out/"

mkdir -p $src

rm -rf $rootfs $out
mkdir $rootfs $out

# extract the source (we need some files from there which are not included in the distributions)

tar -xf dist/src.txz -C $src

# extract the kernel and base distributions to our rootfs

tar -xf dist/kernel.txz -C $rootfs
tar -xf dist/base.txz -C $rootfs

# set up all the other stuff we need to create a functionnal installer image

ln -s "/tmp/installer/resolv.conf" $rootfs/etc/resolv.conf
cp $src/usr/src/release/rc.local $rootfs/etc

echo "sendmail_enable=\"NONE\"" > $rootfs/etc/rc.conf
echo "hostid_enable=\"NO\"" >> $rootfs/etc/rc.conf
echo "debug.witness.trace=0" >> $rootfs/etc/sysctl.conf

# set up bootloader

echo "vfs.mountroot.timeout=\"10\"" >> $rootfs/boot/loader.conf
echo "kernels_autodetect=\"NO\"" >> $rootfs/boot/loader.conf
echo "kern.vty=sc" >> $rootfs/boot/loader.conf
echo "autoboot_delay=\"0\"" >> $rootfs/boot/loader.conf

# make final UFS filesystem image

label="aquabsd-install"
image="$out/aquabsd.img"

echo "/dev/ufs/$label / ufs ro,noatime 1 1" > $rootfs/etc/fstab
echo "root_rw_mount=\"NO\"" > $rootfs/etc/rc.conf.local

makefs -B little -o label=$label -o version=2 $image.part $rootfs

# make EFI System Partition (ESP)

. $src/usr/src/tools/boot/install-boot.sh # include a bunch of helpful functions

esp_image="$out/esp.img"
make_esp_file $esp_image $fat32min $rootfs/boot/loader.efi

# assemble final system image

mkimg -s mbr -b $rootfs/boot/mbr -p efi:=$esp_image -p freebsd:-"mkimg -s bsd -b $rootfs/boot/boot -p freebsd-ufs:=$image.part" -a 2 -o $image

# cleanup

rm $esp_image
rm $image.part
