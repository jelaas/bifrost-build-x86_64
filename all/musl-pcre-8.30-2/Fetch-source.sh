#!/bin/bash

SRC=pcre-8.30.tar.bz2
DST=/var/spool/src/$SRC
SHA=183e40bca3c170611ba46205c950b9ed8385f9c832086e042254e016b04e5db6

pkg_install tarmd-1.2-1 || exit 2
pkg_install curl-7.51.0-1 || exit 2

[ -s "$DST" ] || tarmd $SHA $DST curl -L -k  http://downloads.sourceforge.net/project/pcre/pcre/8.30/$SRC
