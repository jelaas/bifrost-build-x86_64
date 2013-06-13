#!/bin/bash

VER=httpd-2.4.4.1
SRC=$VER.tar.gz
DST=/var/spool/src/$SRC

if [ ! -s "$DST" ]; then
	pkg_install passwd-file-1 || exit 2
 	pkg_install git-1.7.1-2 || exit 2
  	pkg_install openssh-5.5p1-1 || exit 2
	cd /tmp
	rm -rf $VER
	/opt/git/bin/git clone git://git.apache.org/httpd.git $VER || exit 1
	cd $VER  || exit 1
	/opt/git/bin/git checkout 8731b17c1ddf2b3867bccd9d7e399afb6e953ebc || exit 1
	cd /tmp
 	tar czf $DST $VER
  	rm -rf $VER
fi
