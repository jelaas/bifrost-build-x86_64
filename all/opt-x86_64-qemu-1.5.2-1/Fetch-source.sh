#!/bin/bash

SRC=qemu-1.5.2.tar.bz2
DST=/var/spool/src/$SRC

[ -s "$DST" ] || wget -O $DST http://wiki.qemu-project.org/download/$SRC
