#!/bin/bash

APACHEVER=2.4.4.1
SRCVER=httpd-$APACHEVER
PKG=opt-x86_64-apache-$APACHEVER-2 # with build version

# PKGDIR is set by 'pkg_build'. Usually "/var/lib/build/all/$PKG".
PKGDIR=${PKGDIR:-/var/lib/build/all/$PKG}
SRC=/var/spool/src/$SRCVER.tar.gz
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
./Fetch-source.sh || exit 1
pkg_uninstall # Uninstall any dependencies used by Fetch-source.sh

#########
# Install dependencies:
# pkg_available dependency1-1 dependency2-1
pkg_install musl-zlib-1.2.7-1 || exit 2
pkg_install musl-openssl-0.9.8y-1 || exit 2
pkg_install musl-apr-1.4.6-2 || exit 2
pkg_install musl-apr-util-1.4.1-1 || exit 2
pkg_install musl-pcre-8.30-1 || exit 2
pkg_install musl-libxml2-2.9.0-1 || exit 2
pkg_install musl-0.9.10-1 || exit 2 
export CC=musl-gcc

#########
# Unpack sources into dir under /var/tmp/src
cd $(dirname $BUILDDIR); tar xf $SRC

#########
# Patch
cd $BUILDDIR || exit 1
libtool_fix-1
patch -p1 < $PKGDIR/socache.pat || exit 1
patch -p0 < $PKGDIR/layout.pat || exit 1
patch -p0 < $PKGDIR/mod_proxy_html.pat || exit 1
cp $PKGDIR/mod_limitipconn.c modules/aaa || exit 1
cp $PKGDIR/mod_lbmethod_byip.c modules/proxy || exit 1
cp $PKGDIR/configure .  || exit 1
cp $PKGDIR/PrintPath $PKGDIR/config.sub build  || exit 1
cp $PKGDIR/config.guess build  || exit 1
cp $PKGDIR/ap_config_auto.h.in include || exit 1

# Bump maximum size of socache
sed -i 's/64/1024/' modules/cache/mod_socache_shmcb.c || exit 1

#########
# Configure

B-configure-1 --prefix=/opt/apache --disable-nls --enable-static-support\
 --with-z=/opt/musl\
 --with-apr=/opt/musl/bin/apr-1-config --with-apr-util=/opt/musl/bin/apu-1-config\
 --with-pcre=/opt/musl/bin/pcre-config --with-libxml2=/opt/musl/include/libxml2\
 --with-module=aaa:limitipconn,proxy:lbmethod_byip,cache:cache_socache\
 --enable-lbmethod-byrequests --enable-lbmethod-bybusyness --enable-lbmethod-heartbeat\
 --enable-heartbeat --enable-heartmonitor --enable-proxy-fdpass\
 --with-mpm=event --enable-suexec\
 --enable-mods-static=all --enable-ssl --enable-proxy --enable-proxy-connect\
 --enable-proxy-html\
 --enable-proxy-http --enable-proxy-ajp --enable-proxy-balancer --enable-cgi\
 --disable-shared --enable-static --sysconfdir=/opt/apache/etc\
 --localstatedir=/var || exit 1
[ -f config.log ] && cp -p config.log /var/log/config/$PKG-config.log

#########
# Post configure patch
# patch -p0 < $PKGDIR/Makefile.pat

#########
# Compile
make V=1 || exit 1

#########
# Install into dir under /var/tmp/install
rm -rf "$DST"
make install DESTDIR=$DST # --with-install-prefix may be an alternative
mkdir -p $DST/opt/apache/etc/config.flags
mkdir -p $DST/opt/apache/etc/config.preconf
mkdir -p $DST/opt/apache/rc.d
echo yes > $DST/opt/apache/etc/config.flags/httpd
cp -p $PKGDIR/rc $DST/opt/apache/rc.d/rc.httpd
chmod +x $DST/opt/apache/rc.d/rc.httpd
[ -f $PKGDIR/README ] && cp -p $PKGDIR/README $DST/opt/apache
mv $DST/opt/apache/etc/httpd.conf $DST/opt/apache/etc/config.preconf/httpd.conf
mv $DST/opt/apache/htdocs/index.html $DST/opt/apache/etc/config.preconf/index.html
rm -rf $DST/opt/apache/etc/extra

#########
# Check result
cd $DST
# [ -f usr/bin/myprog ] || exit 1
# (ldd sbin/myprog|grep -qs "not a dynamic executable") || exit 1

#########
# Clean up
cd $DST
rm -rf opt/apache/lib opt/apache/manual opt/apache/man\
 opt/apache/cgi-bin/*\
 opt/apache/icons opt/apache/include var opt/apache/build
strip opt/apache/bin/*

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
