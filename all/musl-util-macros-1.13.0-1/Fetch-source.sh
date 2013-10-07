#!/bin/bash

SRC=util-macros-1.13.0.tar.bz2
DST=/var/spool/src/$SRC

[ -s "$DST" ] || wget -O $DST http://xorg.freedesktop.org/releases/individual/util/$SRC
