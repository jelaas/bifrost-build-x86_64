#!/bin/bash

SRC=openssl-0.9.8x.tar.gz
DST=/var/spool/src/$SRC

pkg_install curl-7.51.0-1 || exit 2

[ -s "$DST" ] || curl -L -k -o $DST https://www.openssl.org/source/old/0.9.x/$SRC
