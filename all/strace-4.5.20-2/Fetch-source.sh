#!/bin/bash

SRC=strace-4.5.20.tar.bz2
DST=/var/spool/src/$SRC

pkg_install curl-7.51.0-1 || exit 2
[ -s "$DST" ] || curl -L -k -o $DST http://downloads.sourceforge.net/project/strace/strace/4.5.20/$SRC

