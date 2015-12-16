#!/bin/bash

SRC=nghttp2-1.5.0.tar.bz2
DST=/var/spool/src/$SRC

pkg_install wget-1.12-1 || exit 1
[ -s "$DST" ] || wget --no-check-certificate -O $DST https://github.com/tatsuhiro-t/nghttp2/releases/download/v1.5.0/$SRC
