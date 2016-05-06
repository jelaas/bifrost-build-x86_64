#!/bin/bash

SRC=openssl-1.0.2h.tar.gz
DST=/var/spool/src/$SRC

[ -s "$DST" ] || wget -O $DST ftp://ftp.openssl.org/source/$SRC || wget -O $DST http://ftp.openssl.org/source/old/1.0.2/$SRC
