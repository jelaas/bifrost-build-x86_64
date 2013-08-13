#!/bin/bash

SRCVER=qemu-1.5.2
PKG=opt-x86_64-$SRCVER-1 # with build version

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
pkg_install musl-0.9.12-1 || exit 2
pkg_install Python-2.7-3 || exit 2
pkg_install musl-pkg-config-0.23-1 || exit 2
pkg_install musl-zlib-1.2.7-1 || exit 2
pkg_install musl-gettext-0.18.1.1-1 || exit 2
pkg_install musl-libiconv-1.13.1-1 || exit 2
pkg_install musl-glib-2.24.2-1 || exit 2
pkg_install m4-1.4.14-1 || exit 2
pkg_install autoconf-2.65-1 || exit 2
pkg_install automake-1.11.1-1 || exit 2
pkg_install perl-5.10.1-1 || exit 2
pkg_install libtool-2.4-1 || exit 2
pkg_install musl-kernel-headers-3.6.0-1 || exit 2
pkg_install bison-2.4.2-1 || exit 2
pkg_install flex-2.5.35-1 || exit 2
export CC=musl-gcc

#########
# Unpack sources into dir under /var/tmp/src
cd $(dirname $BUILDDIR); tar xf $SRC

#########
# Patch
cd $BUILDDIR
libtool_fix-1
# patch -p1 < $PKGDIR/mypatch.pat

sed -i 's/-fPIC//' pixman/configure
sed -i 's/-fPIC//' pixman/aclocal.m4

sed -i 's/defined(__GLIBC__)/1/' util/qemu-openpty.c

sed -i 's,linux/fs.h,sys/mount.h,' nbd.c
mv include/elf.h include/xxelf.h
sed -i 's/"elf.h"/"xxelf.h"/' hw/core/loader.c
sed -i 's/"elf.h"/"xxelf.h"/' tcg/tcg.c

#########
# Configure
OPTPREFIX=opt/qemu
B-configure-2 --prefix=/$OPTPREFIX --localstatedir=/var --target-list=arm-softmmu --static || exit 1
[ -f config.log ] && cp -p config.log /var/log/config/$PKG-config.log

echo ::::: Configure done ::::
sleep 5

#########
# Post configure patch
# patch -p0 < $PKGDIR/Makefile.pat
sed -i 's/-fPIC//' Makefile

#########
# Compile
make V=1|| exit 1

#########
# Install into dir under /var/tmp/install
rm -rf "$DST"
make install DESTDIR=$DST # --with-install-prefix may be an alternative
OPTDIR=$DST/$OPTPREFIX
mkdir -p $OPTDIR/etc/config.flags
mkdir -p $OPTDIR/rc.d
echo yes > $OPTDIR/etc/config.flags/example
echo $PKG > $OPTDIR/pkgversion
cp -p $PKGDIR/rc $OPTDIR/rc.d/rc.example
chmod +x $OPTDIR/rc.d/rc.example
[ -f $PKGDIR/README ] && cp -p $PKGDIR/README $OPTDIR

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
[ -d $OPTPREFIX/libexec ] && strip $OPTPREFIX/libexec/*

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
