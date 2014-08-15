#!/bin/bash

VER=2.20.1
SRCVER=binutils-$VER
PKG=binutils-x86_64-$VER-1 # with build version

PKGDIR=${PKGDIR:-/var/lib/build/all/$PKG}
SRC=/var/spool/src/$SRCVER.tar.bz2
CDIR=/var/tmp/src
DST="/var/tmp/install/$PKG"

#########
# Install dependencies:
# pkg_install dependency-1.1 || exit 1

#########
# Unpack sources into dir under /var/tmp/src
./Fetch-source.sh || exit 1
cd $CDIR; tar xf $SRC

#########
# Patch
cd $CDIR/$SRCVER
libtool_fix-1
patch -p0 < $PKGDIR/bfd-makefile_in.pat

#########
# Configure
mkdir  buildit
cd     buildit
$PKGDIR/B-configure --prefix=/usr --bindir=/bin64 || exit 1

#########
# Post configure patch
# patch -p0 < $PKGDIR/Makefile.pat

#########
# Compile
make -j || exit 1

#########
# Install into dir under /var/tmp/install
rm -rf "$DST"
make install DESTDIR=$DST # --with-install-prefix may be an alternative

#########
# Check result
cd $DST
# [ -f usr/bin/myprog ] || exit 1
# (file usr/bin/myprog | grep -qs "statically linked") || exit 1

#########
# Clean up
cd $DST
rm -rf usr
rm -f ./bin64/c++filt ./bin64/objcopy ./bin64/addr2line ./bin64/gprof ./bin64/as ./bin64/ld
[ -d bin64 ] && strip bin64/*

#########
# Make package
cd $DST
tar czf /var/spool/pkg/$PKG.tar.gz --hard-dereference .

#########
# Cleanup after a success
cd /var/lib/build
[ "$DEVEL" ] || rm -rf "$DST"
[ "$DEVEL" ] || rm -rf "$CDIR/$SRCVER"
pkg_uninstall
exit 0
