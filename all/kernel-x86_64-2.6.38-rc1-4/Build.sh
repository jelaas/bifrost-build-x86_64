#!/bin/bash

V=2.6.38-rc1
SRCVER=kernel-$V
BUILDVERSION=4
PKG=kernel-x86_64-$V-$BUILDVERSION # with build version

# PKGDIR is set by 'pkg_build'. Usually "/var/lib/build/all/$PKG".
PKGDIR=${PKGDIR:-/var/lib/build/all/$PKG}
SRC=/var/spool/src/$SRCVER.tar.gz
BUILDDIR=/var/tmp/src/$SRCVER
DSTS="/var/tmp/install/supported-$PKG" # supported modules
DSTU="/var/tmp/install/unsupported-$PKG" # unsupported modules

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
pkg_install ncurses-lib-5.7-1 || exit 2
pkg_install perl-5.10.1-1 || exit 2
pkg_install passwd-file-1 || exit 2
pkg_install module-init-tools-3.12-1 || exit 2
pkg_install bifrost-initramfs-1 || exit 2

#########
# Unpack sources into dir under /var/tmp/src
cd $(dirname $BUILDDIR); tar xf $SRC

#########
# Patch
cd $BUILDDIR || exit 1
patch -p0 < $PKGDIR/menuconfig.pat
patch -p1 < $PKGDIR/ixgbe_rss.pat

#########
# Configure
cp -f $PKGDIR/config .config
sed -i "s/bifrost-x86_64/${BUILDVERSION}-bifrost-x86_64/" .config

#########
# Post configure patch
# patch -p0 < $PKGDIR/Makefile.pat

#########
# Compile
make -j 3 || exit 1

#########
# Install into dir under /var/tmp/install
rm -rf "$DSTS"
rm -rf "$DSTU"
mkdir -p $DSTS/boot/grub
mkdir -p $DSTU

make INSTALL_MOD_PATH=$DSTS modules_install
cp arch/x86/boot/bzImage $DSTS/boot/$PKG-bifrost-x86_64
ln -s $PKG-bifrost-x86_64 $DSTS/boot/kernel.default-x86_64
cp System.map  $DSTS/boot/System.map-$PKG-bifrost-x86_64
# cp vmlinux  $DSTS/boot/ # Takes a lot of space!
echo "title   $PKG-bifrost-x86_64" > $DSTS/boot/grub/$PKG-bifrost-x86_64.grub
echo "root    (hd0,0)" >> $DSTS/boot/grub/$PKG-bifrost-x86_64.grub
echo "kernel /boot/$PKG-bifrost-x86_64 rhash_entries=131072 root=/dev/sda1 rootdelay=10" >> $DSTS/boot/grub/$PKG-bifrost-x86_64.grub

# Filter out unsupported modules
function filter_modules {
	while read L; do
		n=0
		if [ -d "$L" ]; then
			mkdir -p $DSTU/$L
			continue
		fi
		for unsup in net/batman-adv net/ceph/libceph.ko; do
			if [[ $L =~ $unsup ]]; then
				mv $L $DSTU/$L || exit 1
			fi
			continue
		done
		for supported in kernel/arch/ kernel/crypto/ kernel/lib/ kernel/net/ \
				loop.ko ; do
			[[ $L =~ $supported ]] && n=1
		done
		[ $n = 1 ] && continue
		for unsup in /drivers/ata/ /drivers/parport/ /block/paride/ /char/agp/ /i2c/ mptfc.ko \
				/mfd/ /scsi/ /target/ /uio/ /usb/gadget/; do
			if [[ $L =~ $unsup ]]; then
				mv $L $DSTU/$L || exit 1
			fi
			continue
		done

		if [[ $L =~ kernel/drivers/ ]]; then
			[[ $L =~ kernel/drivers/net/ ]] || continue
		fi
		for supported in e1000 igb ixgbe tulip veth macvlan tg3 niu ixgb wireless/ath5k; do
			[[ $L =~ $supported ]] && n=1
		done
		[ $n = 1 ] && continue
		mv $L $DSTU/$L || exit 1
	done
}
cd $DSTS

[ -d lib/modules/$V-$BUILDVERSION-bifrost-x86_64/kernel ] || exit 1

find lib/modules/$V-$BUILDVERSION-bifrost-x86_64/kernel|filter_modules

# firmware to unsupported
mv $DSTS/lib/firmware $DSTU/lib || exit 1

#########
# Check result
cd $DSTS || exit 1
# [ -f usr/bin/myprog ] || exit 1
# (ldd sbin/myprog|grep -qs "not a dynamic executable") || exit 1

#########
# Clean up
cd $DSTS || exit 1
# rm -rf usr/share usr/man

#########
# Make package
cd $DSTS || exit 1
tar czf /var/spool/pkg/$PKG.tar.gz .
cd $DSTU || exit 1
tar czf /var/spool/pkg/$PKG-unsup.tar.gz .

#########
# Cleanup after a success
cd /var/lib/build
[ "$DEVEL" ] || rm -rf "$DSTS"
[ "$DEVEL" ] || rm -rf "$DSTU"
[ "$DEVEL" ] || rm -rf "$BUILDDIR"
pkg_uninstall
exit 0
