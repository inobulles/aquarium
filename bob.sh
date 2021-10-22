#!/bin/sh
set -e

rootfs="rootfs"
dist="dist"
src="src"
out="out"

# download missing components

mkdir -p $dist

if [ ! -f $dist/kernel.txz ]; then fetch https://github.com/inobulles/aquabsd-core/releases/download/v1021a-beta/kernel.txz -o $dist/kernel.txz; fi
if [ ! -f $dist/base.txz   ]; then fetch https://github.com/inobulles/aquabsd-core/releases/download/v1021a-beta/base.txz   -o $dist/base.txz  ; fi
if [ ! -f $dist/src.tgz    ]; then fetch https://github.com/inobulles/aquabsd-core/archive/refs/tags/v1021a-beta.tar.gz     -o $dist/src.tgz   ; fi

rm -rf $src
mkdir $src

if [ -d $rootfs ]; then
	chflags -R noschg $rootfs
fi

rm -rf $rootfs $out
mkdir $rootfs $out

# extract the source (we need some files from there which are not included in the distributions)

echo "[BOB] Extracting source ..."

tar -xf $dist/src.tgz -C $src
mv $src/*/* $src

# extract the kernel and base distributions to our rootfs

echo "[BOB] Extracting kernel ..."
tar -xf $dist/kernel.txz -C $rootfs

echo "[BOB] Extracting base ..."
tar -xf $dist/base.txz -C $rootfs

# set up all the other stuff we need to create a functionnal installer image

echo "[BOB] Setting up ..."

ln -s "/tmp/installer/resolv.conf" $rootfs/etc/resolv.conf
cp $src/release/rc.local $rootfs/etc

echo "hostname=aquabsd-installer" > $rootfs/etc/rc.conf
echo "sendmail_enable=\"NONE\"" >> $rootfs/etc/rc.conf
echo "hostid_enable=\"NO\"" >> $rootfs/etc/rc.conf
echo "debug.witness.trace=0" >> $rootfs/etc/sysctl.conf

# set up bootloader

echo "vfs.mountroot.timeout=\"10\"" >> $rootfs/boot/loader.conf
echo "kernels_autodetect=\"NO\"" >> $rootfs/boot/loader.conf
echo "kern.vty=sc" >> $rootfs/boot/loader.conf
echo "autoboot_delay=\"0\"" >> $rootfs/boot/loader.conf

# make final UFS filesystem image

echo "[BOB] Creating UFS filesystem image ..."

label="aquabsd-installer"
image="$out/aquabsd.img"

echo "/dev/ufs/$label / ufs ro,noatime 1 1" > $rootfs/etc/fstab
echo "root_rw_mount=\"NO\"" > $rootfs/etc/rc.conf.local

makefs -B little -o label=$label -o version=2 $image.part $rootfs

# make EFI System Partition (ESP)

echo "[BOB] Creating ESP image ..."

. $src/tools/boot/install-boot.sh # include a bunch of helpful functions

esp_image="$out/esp.img"
make_esp_file $esp_image $fat32min $rootfs/boot/loader.efi

# assemble final system image

echo "[BOB] Assembling final image ..."

mkimg -s mbr -b $rootfs/boot/mbr -p efi:=$esp_image -p freebsd:-"mkimg -s bsd -b $rootfs/boot/boot -p freebsd-ufs:=$image.part" -a 2 -o $image

# cleanup

rm $esp_image
rm $image.part

xz -9 -T $(sysctl -n hw.ncpu) $image
echo "[BOB] Done (output is in $image.xz)"