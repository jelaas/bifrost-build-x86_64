#!/bin/bash

SRC=openssl-1.0.2k.tar.gz
DST=/var/spool/src/$SRC
SHA=ec280a4bcc0d1a8803755261179b851eee49d33b8f20c9897f23445a120f421d

pkg_install curl-7.51.0-1 || exit 2
pkg_install tarmd-1.2-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k ftp://ftp.openssl.org/source/$SRC || tarmd $SHA $DST curl -L -k http://ftp.openssl.org/source/old/1.0.2/$SRC
