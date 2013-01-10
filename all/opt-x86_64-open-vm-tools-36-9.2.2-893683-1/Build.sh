#!/bin/bash

VER=9.2.2-893683
PNAME=x86_64-open-vm-tools36
SRCVER=open-vm-tools-$VER
PKG=opt-$PNAME-$VER-1 # with build version

# PKGDIR is set by 'pkg_build'. Usually "/var/lib/build/all/$PKG".
PKGDIR=${PKGDIR:-/var/lib/build/all/$PKG}
SRC=/var/spool/src/$SRCVER.tar.gz
[ -f /var/spool/src/$SRCVER.tar.bz2 ] && SRC=/var/spool/src/$SRCVER.tar.bz2
BUILDDIR=/var/tmp/src/$SRCVER
DST="/var/tmp/install/$PKG"

#########
# Simple inplace edit with sed.
# Usage: sedit 's/find/replace/g' Filename
function sedit {
    sed "$1" $2 > /tmp/sedit.$$
    cp /tmp/sedit.$$ $2
    rm /tmp/sedit.$$
}

#########
# Fetch sources
./Fetch-source.sh || exit $?
pkg_uninstall # Uninstall any dependencies used by Fetch-source.sh

#########
# Install dependencies:
# pkg_available dependency1-1 dependency2-1
pkg_install fake-libintl-3 || exit 2
pkg_install kernel-x86_64-headers-3.6.0-3 || exit 2

#########
# Unpack sources into dir under /var/tmp/src
cd $(dirname $BUILDDIR); tar xf $SRC

#########
# Patch
cd $BUILDDIR
libtool_fix-1
patch -p0 < $PKGDIR/configure.pat

#sed -i 's/d_alloc_root/d_make_root/' ./modules/linux/vmblock/linux/filesystem.c || exit 1
#sed -i 's/d_alloc_root/d_make_root/' ./modules/linux/vmhgfs/filesystem.c || exit 1

#########
# Configure
OPTPREFIX=opt/$PNAME
B-configure-1 --prefix=/$OPTPREFIX --localstatedir=/var --without-pam --without-procps \
--with-kernel-release=3.6.0 \
   --without-icu --without-x --without-dnet --without-gtk2 --without-gtkmm || exit 1
[ -f config.log ] && cp -p config.log /var/log/config/$PKG-config.log

#########
# Post configure patch
# patch -p0 < $PKGDIR/Makefile.pat

#########
# Compile
cd modules;make V=1 || exit 1

find . -name \*.ko

#########
# Install into dir under /var/tmp/install
rm -rf "$DST"
OPTDIR=$DST/$OPTPREFIX
mkdir -p $OPTDIR/etc/config.flags
mkdir -p $OPTDIR/rc.d
mkdir -p $OPTDIR/modules
echo yes > $OPTDIR/etc/config.flags/$PNAME
echo $PKG > $OPTDIR/pkgversion
cp -p $PKGDIR/rc $OPTDIR/rc.d/rc.$PNAME
chmod +x $OPTDIR/rc.d/rc.$PNAME
[ -f $PKGDIR/README ] && cp -p $PKGDIR/README $OPTDIR
cp ./linux/vmxnet/vmxnet.ko $OPTDIR/modules || exit 1
cp ./linux/vmblock/vmblock.ko  $OPTDIR/modules || exit 1
cp ./linux/vsock/vsock.ko $OPTDIR/modules || exit 1
cp ./linux/vmci/vmci.ko $OPTDIR/modules || exit 1
cp ./linux/vmhgfs/vmhgfs.ko $OPTDIR/modules || exit 1

#########
# Check result
cd $DST || exit 1
# [ -f usr/bin/myprog ] || exit 1
# (ldd sbin/myprog|grep -qs "not a dynamic executable") || exit 1

#########
# Clean up
cd $DST || exit 1
# rm -rf usr/share usr/man
[ -d $OPTPREFIX/bin ] && strip $OPTPREFIX/bin/*
[ -d $OPTPREFIX/usr/bin ] && strip $OPTPREFIX/usr/bin/*

#########
# Make package
cd $DST
tar czf /var/spool/pkg/$PKG.tar.gz .

#########
# Cleanup after a success
cd /var/lib/build
[ "$DEVEL" ] || rm -rf "$DST"
[ "$DEVEL" ] || rm -rf "$BUILDDIR"
pkg_uninstall
exit 0
