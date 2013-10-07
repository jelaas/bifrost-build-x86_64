#!/bin/bash

SRC=makedepend-1.0.5.tar.gz
DST=/var/spool/src/$SRC

[ -s "$DST" ] || wget -O $DST http://xorg.freedesktop.org/releases/individual/util/$SRC
