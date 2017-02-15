#!/bin/bash

SRC=e2fsprogs-1.41.11.tar.gz
DST=/var/spool/src/$SRC

pkg_install curl-7.51.0-1 || exit 2
[ -s "$DST" ] || curl -L -k -o $DST http://downloads.sourceforge.net/project/e2fsprogs/e2fsprogs/1.41.11/$SRC
