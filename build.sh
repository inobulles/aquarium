#!/usr/bin/env sh
set -e

# options

dist="dist/"
dist_image="dist_image.img"

# TODO check that we are indeed running as root
# TODO check that we are actually running on aquaBSD/FreeBSD
# TODO check that we are on AMD64

# clean up previous build files if there are any

if [ -d $dist ]; then
	echo -n "A previous distribution directory was found ($dist). You can either change the 'dist' option in 'build.sh' to select a different destination, either press enter here to delete the distribution directory ..."
	read _

	# TODO
fi

echo -n "Creating build environment ..."
read _

# create memdisk and ZFS file system on it for the build environment

mkdir $dist

use_memdisk=

if [ $use_memdisk ]; then
	dist_pool="aquabsd_dist" # name of the ZFS pool in which the distribution will be created

	truncate -s 8G $dist_image # probably won't need more than 16 GB
	mdisk_id=$(mdconfig -a -f $dist_image)

	mdisk_dev="/dev/$mdisk_id"
	zpool create $dist_pool $mdisk_dev

	zfs set mountpoint=$(realpath $dist) $dist_pool
	# TODO set ZFS compression and other features?
fi

# set up vanilla FreeBSD jail with only the 'base' & 'src' distributions

jail="$dist/jail/"
mkdir $jail

export DISTRIBUTIONS="base.txz src.txz" # 'lib32' isn't necessary whatsoever for just the build jail
export BSDINSTALL_DISTDIR=$(realpath $dist)
export BSDINSTALL_DISTSITE=ftp://ftp.freebsd.org/pub/FreeBSD/releases/amd64/$(uname -r)
export BSDINSTALL_CHROOT=$(realpath $jail)

#chflags -R noschg $BSDINSTALL_CHROOT # TODO is this necessary?

bsdinstall distfetch
bsdinstall distextract

cp /etc/resolv.conf $jail/etc/resolv.conf # necessary for networking to work inside the jail

# apply necessary configurations and modifications to kernel and base

echo "Applying necessary configurations and modifications to the kernel and userland ..."

# start up the jail and build kernel and base

jail_name="aquabsd_dist"
jail -c name=$jail_name path=$(realpath $jail) exec.start="/bin/sh /etc/rc" exec.stop="/bin/sh /etc/rc.shutdown" mount.devfs allow.nomount host.hostname=$jail_name ip4=inherit ip6=inherit

echo "$jail_name { path = "$(realpath $jail)"; } " >> /etc/jail.conf # TODO is there not a better (more temporary) way to do this? (e.g. take a look at how Poudrière does it)
service jail start $jail_name

# actually enter the jail and run the 'jail-build.sh' script

echo "Entering build environment ..."

rm -rf $jail/files/
cp -r files $jail

chmod +x jail-build.sh
cp jail-build.sh $jail
jexec $jail_name /jail-build.sh

# our system should now be built

mv $jail/aquabsd.img aquabsd.img
echo "Done. Your final image should be available at '$(realpath aquabsd.img)'\n"

# clean up

echo -n "Cleaning up ..."
read _

service jail stop $jail_name

if [ $use_memdisk ]; then
	umount $dist

	zpool destroy $dist_pool
	rm $dist_image

	mdconfig -d -u $mdisk_id
fi

rm -rf $dist