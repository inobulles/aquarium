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

dist_pool="aquabsd_dist" # name of the ZFS pool in which the distribution will be created

truncate -s 4G $dist_image # probably won't need more than 4 GB
mdisk_id=$(mdconfig -a -f $dist_image)

mdisk_dev="/dev/md$mdisk_id"
zpool create $dist_pool $mdisk_dev

mkdir $dist
zfs set mountpoint=$(realpath $dist) $dist_pool

# TODO set ZFS compression and other features?

# set up vanilla FreeBSD jail with only the 'base' & 'src' distributions

jail="$dist/jail/"
mkdir $jail

export DISTRIBUTIONS="base.txz src.txz" # 'lib32' isn't necessary whatsoever for just the build jail
export BSDINSTALL_DISTDIR=$(realpath $dist)
export BSDINSTALL_DISTSITE=ftp://ftp.freebsd.org/pub/FreeBSD/releases/amd64/$(uname -r)
export BSDINSTALL_CHROOT=$(realpath $jail)

chflags -R noschg $BSDINSTALL_CHROOT # TODO is this necessary?

bsdinstall distfetch
bsdinstall distextract

# apply necessary configurations and modifications to kernel and base

echo "Applying necessary configurations and modifications to the kernel and userland ..."

# start up the jail and build kernel and base

jail_name="aquabsd_dist"

echo "$jail_name { path = "$(realpath $jail)"; } " >> /etc/jail.conf # TODO is there not a better (more temporary) way to do this? (e.g. take a look at how Poudrière does it)
service jail start $jail_name

# install extra packages required for building some of the added userland programs
# e.g., install required library headers for AQUA devices
# use the 'pkg -j $jail_name'

echo -n "Installing dependencies required for building ..."
read _

# actually enter the jail and run the 'jail-build.sh' script

echo "Entering build environment ..."

chmod +x jail-build.sh
cp jail-build.sh $jail
jexec $jail_name /jail-build.sh