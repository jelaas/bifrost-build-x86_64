#!/bin/bash

SRCVER=openssl-1.0.1e
PKG=musl-$SRCVER-1 # with build version

PKGDIR=${PKGDIR:-/var/lib/build/all/$PKG}
SRC=/var/spool/src/$SRCVER.tar.gz
CDIR=/var/tmp/src
DST="/var/tmp/install/$PKG"

#########
# Install dependencies:
pkg_install perl-5.10.1-1 || exit 2
pkg_install musl-0.9.14-1 || exit 2
pkg_install musl-makedepend-1.0.5-1 || exit 2
export CC=musl-gcc

#########
# Unpack sources into dir under /var/tmp/src
./Fetch-source.sh || exit 1
cd $CDIR; tar xf $SRC

#########
# Patch
cd $CDIR/$SRCVER
#libtool_fix-1
patch -p0 < $PKGDIR/openssl.pat || exit 1

#########
# Configure
./Configure linux-x86_64 --prefix=/opt/musl --openssldir=/etc/ssl no-shared no-bf no-cast no-md2 no-mdc2 no-rc2 no-rc5 no-idea no-ripemd no-ec no-dso no-camellia no-jpake no-md4 no-srp

#########
# Post configure patch
# patch -p0 < $PKGDIR/Makefile.pat
sed 's/-O3/-Os/g' Makefile > /tmp/config.$$
cp -f /tmp/config.$$ Makefile
rm -f /tmp/config.$$
sed -i 's/$${LDCMD} $${LDFLAGS} -o/$${LDCMD} $${LDFLAGS} -static -o/g' Makefile.shared

#########
# Compile
make depend
for CIPH in bf cast md2 mdc2 rc2 rc5 rc5 idea ripemd ec camellia jpake md4 srp; do
	rm -rf crypto/$CIPH
done
LDFLAGS="-static" make || exit 1

#########
# Install into dir under /var/tmp/install
rm -rf "$DST"
make INSTALL_PREFIX=$DST install

#########
# Check result
cd $DST
# [ -f usr/bin/myprog ] || exit 1
(ldd opt/musl/bin/openssl|grep -qs "not a dynamic executable") || exit 1

#########
# Clean up
cd $DST || exit 1
rm -rf etc/ssl/man
rm -rf etc/ssl/misc
# rm -rf usr/share usr/man
#[ -d bin ] && strip bin/*
[ -d opt/musl/bin ] && strip opt/musl/bin/*

#########
# Make package
cd $DST
tar czf /var/spool/pkg/$PKG.tar.gz .

#########
# Cleanup after a success
cd /var/lib/build
[ "$DEVEL" ] || rm -rf "$DST"
[ "$DEVEL" ] || rm -rf "$CDIR/$SRCVER"
pkg_uninstall
exit 0
