#!/bin/sh
set -xe

export HOME="/root"

# aquarium setup

cd /tmp
/etc/rc.d/os-release start # important or the aquarium frontend will refuse to create an image

# copy over custom pkg repo (if there is one)

if [ -f FreeBSD.conf ]; then
	mkdir -p /usr/local/etc/pkg/repos
	mv FreeBSD.conf /usr/local/etc/pkg/repos
fi

# set up all the stuff we need to create a functional image

echo export TERM=xterm > /etc/rc.local

echo hostname=aquabsd-installer > /etc/rc.conf
echo sendmail_enable=\"NONE\" >> /etc/rc.conf
echo hostid_enable=\"NO\" >> /etc/rc.conf
echo kld_list=\"vesa\" >> /etc/rc.conf # as of commit b8cf1c5, the vesa kernel module isn't statically linked to the kernel in the default configuration ('sys/amd64/conf/GENERIC')
echo debug.witness.trace=0 >> /etc/sysctl.conf

# set up bootloader

echo vfs.mountroot.timeout=\"10\" >> /boot/loader.conf
echo kernels_autodetect=\"NO\" >> /boot/loader.conf
echo kern.vty=vt >> /boot/loader.conf
echo autoboot_delay=\"0\" >> /boot/loader.conf

# dirty library links

ln -s /usr/lib/libarchive.so /usr/lib/libarchive.so.13
