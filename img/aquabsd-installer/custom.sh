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

# set up all the stuff we need to create a functional installer image

cp rc.local /etc

echo "hostname=aquabsd-installer" > /etc/rc.conf
echo "sendmail_enable=\"NONE\"" >> /etc/rc.conf
echo "hostid_enable=\"NO\"" >> /etc/rc.conf
echo "kld_list=\"vesa\"" >> /etc/rc.conf # as of commit b8cf1c5, the vesa kernel module isn't statically linked to the kernel in the default configuration ('sys/amd64/conf/GENERIC')
echo "debug.witness.trace=0" >> /etc/sysctl.conf

# set up bootloader

echo "vfs.mountroot.timeout=\"10\"" >> /boot/loader.conf
echo "kernels_autodetect=\"NO\"" >> /boot/loader.conf
echo "kern.vty=vt" >> /boot/loader.conf
echo "autoboot_delay=\"0\"" >> /boot/loader.conf

# install external dependencies for the aquaBSD installer

export IGNORE_OSVERSION=yes
export ASSUME_ALWAYS_YES=yes

pkg install pango librsvg2-rust icu

# install necessary packages for the aquaBSD installer

short_version="0222a"
version="v$short_version-beta"
repo_url="https://github.com/inobulles/aquabsd-pkg-repo/releases/download/$version"

pkg_out="packages"
mkdir -p $pkg_out

export SSL_NO_VERIFY_PEER=1

fetch $repo_url/aqua-$short_version.pkg          -o $pkg_out
fetch $repo_url/iar-$short_version.pkg           -o $pkg_out
fetch $repo_url/libcopyfile-$short_version.pkg   -o $pkg_out
fetch $repo_url/libiar-$short_version.pkg        -o $pkg_out
fetch $repo_url/libmkfs_msdos-$short_version.pkg -o $pkg_out

for package in $(find $pkg_out -type f); do
	# our packages are built under 'FreeBSD:13:amd64', so prevent 'pkg' from complaining about that
	ABI="FreeBSD:13:amd64" pkg add -M $package
done

# install aqua root

pkg install git-lite

git clone https://github.com/inobulles/aqua-root --depth 1 -b main ~/.aqua
rm -rf ~/.aqua/.git

pkg remove git-lite
pw userdel git_daemon

# install extra files

mv aquabsd.alps.ui.device /usr/share/aqua/devices/aquabsd.alps.ui.device
mv aquabsd.alps.vga.device /usr/share/aqua/devices/aquabsd.alps.vga.device
mv installer.zpk ~/.aqua/boot.zpk
mv fonts.conf /usr/local/etc/fonts/

# remove all the unncecessary crap that was installed with those packages ('delete -f' means "delete package but not what depends on it")
# use 'pkg info' to see list of all installed packages
# use 'pkg info -l <package name>' to see all files linked to package

rm -rf /usr/local/etc/fonts/conf.d/
rm -rf /usr/share/fonts/

pkg delete -f python39 ||: # entire programs I never asked for
pkg delete -f dejavu encodings font-bh-ttf font-misc-meltho font-misc-ethiopic ||: # fonts I never asked for
# something in here I can't remove
# pkg delete -f libX11 libXau libXdmcp libXext libXft libXrender # X11-related libraries I never asked for
# pkg delete -f xorg-fonts-truetype xorgproto libxcb # XCB-related libraries I never asked for
pkg delete -f mkfontscale ||: # X11-related tools I never asked for

rm -rf /usr/share/man/
rm -rf /usr/share/doc/
rm -rf /usr/share/i18n/

mv /usr/share/locale/C.UTF-8 /C.UTF-8
rm -rf /usr/share/locale/*
mv /C.UTF-8 /usr/share/locale/C.UTF-8

# don't remove /usr/share/misc/ plz

rm -rf /usr/local/man/
rm -rf /usr/local/share/doc/
rm -rf /usr/local/share/gtk-doc/
rm -rf /usr/local/share/gir-1.0/
rm -rf /usr/local/share/glib-2.0/
rm -rf /usr/local/share/mime/
rm -rf /usr/local/share/locale/

rm -rf /usr/lib/debug # TODO this is like 1/3 of the image size lol... where is this coming from?

# TODO a bunch of other questionable stuff to remove that I need to doublecheck

rm -rf /usr/lib/clang/
rm -rf /usr/lib/*.a

rm /usr/local/sbin/pkg-static* # shouldn't need this, right?

rm -rf /usr/local/include

rm /usr/local/lib/*.a

# remove DNS thingy and link it to where the installer is gonna place it

rm /etc/resolv.conf
ln -s "/tmp/installer/resolv.conf" /etc/resolv.conf
