#!/bin/bash

SRC=zlib-1.2.6.tar.bz2
DST=/tmp/$SRC
VDST=/var/spool/src/$SRC

pkg_install curl-7.51.0-1 || exit 2
if ! [ -s "$VDST" ]; then
    pkg_install tarmd-nocomp-1.2-1 || exit 2
    curl -L -k -o $DST https://downloads.sourceforge.net/project/libpng/zlib/1.2.6/$SRC || exit 1
    bzcat "$DST" | tarmd fc4034156d1b890eaba4a2bf73a1d4b2b2d22807362eccfe2b6697f1b9a9bb39 $VDST
fi
