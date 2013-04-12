#!/bin/bash

# Kernel dependency
V=3.4.39
ARCH=x86_64
KSRCVER=kernel-$V
KBUILDVERSION=1
KPKG=kernel-$ARCH-$V-$KBUILDVERSION # with build version

SRCVER=netmap-20120813
PKG=$SRCVER-$KPKG # with build version

# PKGDIR is set by 'pkg_build'. Usually "/var/lib/build/all/$PKG".
PKGDIR=${PKGDIR:-/var/lib/build/all/$PKG}
SRC=/var/spool/src/$SRCVER.tar.gz
[ -f /var/spool/src/$SRCVER.tar.bz2 ] && SRC=/var/spool/src/$SRCVER.tar.bz2
BUILDDIR=/var/tmp/src/netmap
DST="/var/tmp/install/$PKG"

KPKGDIR=/var/lib/build/all/$KPKG
KSRC=/var/spool/src/$KSRCVER.tar.gz
KBUILDDIR=/var/tmp/src/$KSRCVER



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
pkg_install libpcap-1.1.1-1 || exit 2
pkg_install patch-2.7.1-1 || exit 2
pkg_install kernel-x86_64-3.4.39-1 || exit 2
pkg_install kernel-x86_64-headers-3.6.0-4

# Compile against musl:
# pkg_install musl-0.9.9-2 || exit 2 
# export CC=musl-gcc

#########
# Unpack sources into dir under /var/tmp/src
cd $(dirname $BUILDDIR); tar xf $SRC

# Unpack kernel source and prepare them
cd $(dirname $KBUILDDIR); tar xf $KSRC

# Patch
function dopatch {
        echo "patch $1 < $2"
        patch $1 < $2 || exit 1
}
cd $KBUILDDIR || exit 1
#Add patches
dopatch -p1 $KPKGDIR/ixgbe_sfp_override.pat || exit 1
dopatch -p1 $KPKGDIR/pktgen-rx.pat || exit 1

# Configure
cp -f $KPKGDIR/config .config
# exit 1 # This is a nice place to break if you want to change the kernel config
sed -i "s/BIFROST/1-bifrost-$ARCH/" .config

#prepare kernel
make scripts || exit 1
make prepare || exit 1 
cp /usr/lib/modules/3.6.0/build/Module.symvers .

#########
cd $(dirname $BUILDDIR);
pwd
# Post configure patch
patch -p0 < $PKGDIR/netmap.pat

# Compile
cd netmap/LINUX
make KSRC=$KBUILDDIR || exit 1
make KSRC=$KBUILDDIR apps || exit 1
#########

#########
# Install into dir under /var/tmp/install
rm -rf "$DST"
DESTDIR=$DST/opt/netmap # --with-install-prefix may be an alternative
mkdir -p $DESTDIR

#MODULES
cp netmap_lin.ko $DESTDIR
cp ixgbe/ixgbe.ko $DESTDIR
cp e1000/e1000.ko $DESTDIR
cp forcedeth.ko $DESTDIR
cp igb/igb.ko $DESTDIR


#APPS
cp ../examples/pkt-gen $DESTDIR
cp ../examples/bridge $DESTDIR
cp ../examples/testpcap $DESTDIR


#########
# Convert man-pages
cd $DST || exit 1
# for f in $(find . -path \*man/man\*); do if [ -f $f ]; then groff -T utf8 -man $f > $f.txt; rm $f; fi; done

#########
# Check result
cd $DST || exit 1
# [ -f usr/bin/myprog ] || exit 1
# (ldd sbin/myprog|grep -qs "not a dynamic executable") || exit 1

#########
# Clean up
cd $DST || exit 1
# rm -rf usr/share usr/man
[ -d bin ] && strip bin/*
[ -d usr/bin ] && strip usr/bin/*
[ -d sbin ] && strip sbin/*
[ -d usr/sbin ] && strip usr/sbin/*

#########
# Make package
cd $DST || exit 1
tar czf /var/spool/pkg/$PKG.tar.gz .

#########
# Cleanup after a success
cd /var/lib/build
[ "$DEVEL" ] || rm -rf "$DST"
[ "$DEVEL" ] || rm -rf "$BUILDDIR"
pkg_uninstall
exit 0
