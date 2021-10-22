mkdir -p dist

# install all world components to '/usr/obj/usr/src/amd64.amd64/release/dist/'
# don't forget to pass the same flags to here

mkdir -p /usr/obj/usr/src/amd64.amd64/release/dist # necessary?
cd /usr/src/release/.. && make TARGET_ARCH=amd64 TARGET=amd64 distributeworld DISTDIR=/usr/obj/usr/src/amd64.amd64/release/dist

# for mergemaster, not strictly necessary for right now ...
#sh /usr/src/release/scripts/mm-mtree.sh -m /usr/src/release/.. -F  "TARGET_ARCH=amd64 TARGET=amd64 "  -D "/usr/obj/usr/src/amd64.amd64/release/dist/base"

# not exactly sure yet, I think it's also for updating though
etcupdate extract -B -M "TARGET_ARCH=amd64 TARGET=amd64"  -s /usr/src/release/.. -d "/usr/obj/usr/src/amd64.amd64/release/dist/base/var/db/etcupdate"

# generate 'base.txz' file
# as with 'distributeworld', DON'T pass the same flags here; they're unnecessary

cd /usr/src/release/.. && make TARGET_ARCH=amd64 TARGET=amd64 packageworld DISTDIR=/usr/obj/usr/src/amd64.amd64/release/dist


mv dist/*.txz .
mkdir -p dist
cd /usr/src/release/.. && make TARGET_ARCH=amd64 TARGET=amd64 distributekernel packagekernel DISTDIR=/usr/obj/usr/src/amd64.amd64/release/dist
mv dist/kernel*.txz .
sh /usr/src/release/scripts/make-manifest.sh *.txz > MANIFEST
touch packagesystem
mkdir -p bootonly
cd /usr/src/release/.. && make TARGET_ARCH=amd64 TARGET=amd64 installkernel installworld distribution  DESTDIR=/usr/obj/usr/src/amd64.amd64/release/bootonly MK_AT=no  MK_GAMES=no  MK_INSTALLLIB=no MK_LIB32=no MK_MAIL=no  MK_TOOLCHAIN=no MK_PROFILE=no  MK_RESCUE=no MK_DICT=no  MK_KERNEL_SYMBOLS=no MK_TESTS=no MK_DEBUG_FILES=no  -DDB_FROM_SRC
mkdir -p bootonly/usr/freebsd-dist
cp MANIFEST bootonly/usr/freebsd-dist
ln -fs /tmp/bsdinstall_etc/resolv.conf bootonly/etc/resolv.conf
echo sendmail_enable=\"NONE\" > bootonly/etc/rc.conf
echo hostid_enable=\"NO\" >> bootonly/etc/rc.conf
echo vfs.mountroot.timeout=\"10\" >> bootonly/boot/loader.conf
echo kernels_autodetect=\"NO\" >> bootonly/boot/loader.conf
cp /usr/src/release/rc.local bootonly/etc