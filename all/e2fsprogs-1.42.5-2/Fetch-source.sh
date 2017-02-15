#!/bin/bash

SRC=e2fsprogs-1.42.5.tar.gz
DST=/var/spool/src/$SRC

pkg_install curl-7.51.0-1 || exit 2
[ -s "$DST" ] || curl -L -k -o $DST http://downloads.sourceforge.net/project/e2fsprogs/e2fsprogs/v1.42.5/$SRC
