#!/bin/bash

SRC=openssl-1.0.2d.tar.gz
DST=/var/spool/src/$SRC

[ -s "$DST" ] || wget -O $DST http://www.openssl.org/source/$SRC || wget -O $DST http://www.openssl.org/source/old/1.0.2/$SRC
