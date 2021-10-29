#!/bin/sh
set -e

# this is where any custom configuration of the final system goes
# e.g., if you wanted to install 'vim', you'd add the following to this file:

# pkg install -y vim

branch="aquabsd.alps"
version="v1021a-beta"
short_version="1021a"
repo_url="https://github.com/inobulles/aquabsd-pkg-repo/releases/download/$version"

cd /tmp

# install external dependencies for the aquaBSD installer

pkg install -y pango librsvg2

# install necessary packages for the aquaBSD installer

pkg_out="packages"
mkdir -p $pkg_out

fetch $repo_url/aqua-$short_version.pkg          -o $pkg_out
fetch $repo_url/iar-$short_version.pkg           -o $pkg_out
fetch $repo_url/libcopyfile-$short_version.pkg   -o $pkg_out
fetch $repo_url/libiar-$short_version.pkg        -o $pkg_out
fetch $repo_url/libmkfs_msdos-$short_version.pkg -o $pkg_out

for package in $(find $pkg_out); do
	pkg add $package
done

# install aqua root

pkg install -y git-lite

git clone https://github.com/inobulles/aqua-root --depth 1 -b main
mv aqua-root /root/.aqua-root

pkg remove git-lite

# install extra files

mv files/aquabsd.alps.ui.device /usr/share/aqua/devices/aquabsd.alps.ui.device
mv files/installer.zpk /root/.aqua-root/boot.zpk
mv files/fonts.conf /usr/local/etc/fonts/

# remove all the unncecessary crap that was installed with those packages ('delete -f' means "delete package but not what depends on it")
# use 'pkg info' to see list of all installed packages
# use 'pkg info -l <package name>' to see all files linked to package

rm -rf /usr/local/etc/fonts/conf.d/
rm -rf /usr/share/fonts/

pkg delete -f python38 # entire programs I never asked for
pkg delete -f dejavu encodings font-bh-ttf font-misc-meltho font-misc-ethiopic # fonts I never asked for
# something in here I can't remove
# pkg delete -f libX11 libXau libXdmcp libXext libXft libXrender # X11-related libraries I never asked for
# pkg delete -f xorg-fonts-truetype xorgproto libxcb # XCB-related libraries I never asked for
pkg delete -f mkfontscale # X11-related tools I never asked for

rm -rf /usr/share/man/
rm -rf /usr/share/doc/

rm -rf /usr/local/man/
rm -rf /usr/local/share/doc/
rm -rf /usr/local/share/gtk-doc/

rm -rf /usr/lib/debug # TODO this is like 1/3 of the image size lol... where is this coming from?

# TODO a bunch of other questionable stuff to remove that I need to doublecheck

rm -rf /var/*

rm /usr/local/lib/*.a
rm /usr/local/lib/*.so
rm /usr/local/lib/*.so.*.*
