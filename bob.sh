#!/bin/sh
set -e

if [ "$(id -u)" != "0" ]; then
	echo "This script must be run as root"
	exit 1
fi

version="v0422a-beta"
rootfs="rootfs"
dist="dist"
src="src"

core_ver=$version

# download missing components

mkdir -p $dist

if [ ! -f $dist/kernel.txz ]; then fetch https://github.com/inobulles/aquabsd-core/releases/download/$version/kernel.txz -o $dist/kernel.txz; fi
if [ ! -f $dist/base.txz   ]; then fetch https://github.com/inobulles/aquabsd-core/releases/download/$version/base.txz   -o $dist/base.txz  ; fi

if [ -d $rootfs ]; then
	chflags -R noschg $rootfs
fi

rm -rf $rootfs
mkdir $rootfs

# extract the kernel and base distributions to our rootfs

echo "[BOB] Extracting kernel ..."
tar -xf $dist/kernel.txz -C $rootfs

echo "[BOB] Extracting base ..."
tar -xf $dist/base.txz -C $rootfs

# set up all the other stuff we need to create a functionnal installer image

echo "[BOB] Setting up ..."

cp $src/release/rc.local $rootfs/etc

echo "hostname=aquabsd-installer" > $rootfs/etc/rc.conf
echo "sendmail_enable=\"NONE\"" >> $rootfs/etc/rc.conf
echo "hostid_enable=\"NO\"" >> $rootfs/etc/rc.conf
echo "kld_list=\"vesa\"" >> $rootfs/etc/rc.conf # as of commit b8cf1c5, the vesa kernel module isn't statically linked to the kernel in the default configuration ('sys/amd64/conf/GENERIC')
echo "debug.witness.trace=0" >> $rootfs/etc/sysctl.conf

# set up bootloader

echo "vfs.mountroot.timeout=\"10\"" >> $rootfs/boot/loader.conf
echo "kernels_autodetect=\"NO\"" >> $rootfs/boot/loader.conf
echo "kern.vty=sc" >> $rootfs/boot/loader.conf
echo "autoboot_delay=\"0\"" >> $rootfs/boot/loader.conf

# custom setup

echo "[BOB] Running custom setup script in chroot ..."

pkg_repo_conf_dir="/usr/local/etc/pkg/repos/"
pkg_repo_conf="$pkg_repo_conf_dir/FreeBSD.conf"

if [ -f $pkg_repo_conf ]; then
	mkdir -p $rootfs/$pkg_repo_conf_dir
	cp $pkg_repo_conf $rootfs/$pkg_repo_conf
fi

if [ -d files/ ]; then
	cp -r files $rootfs/tmp/files
fi

cp /etc/resolv.conf $rootfs/etc/resolv.conf # so that DNS works in chroot
touch $rootfs/dev/null # to stop pkg-static from complaining

chroot $rootfs /bin/sh < custom.sh

rm $rootfs/dev/null
rm -rf $rootfs/tmp/*

rm $rootfs/etc/resolv.conf
ln -s "/tmp/installer/resolv.conf" $rootfs/etc/resolv.conf

# create final image

sh create-image.sh $rootfs $src
