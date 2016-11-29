#!/bin/bash

SRC=pkg-config-0.23.tar.gz
DST=/var/spool/src/$SRC

pkg_install curl-7.51.0-1 || exit 2
[ -s "$DST" ] || curl -L -k -o $DST http://pkg-config.freedesktop.org/releases/$SRC
