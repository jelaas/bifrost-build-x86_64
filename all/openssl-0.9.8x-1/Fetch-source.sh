#!/bin/bash

SRC=openssl-0.9.8x.tar.gz
DST=/var/spool/src/$SRC

[ -s "$DST" ] || wget -O $DST http://www.openssl.org/source/$SRC || wget -O $DST https://www.openssl.org/source/old/0.9.x/$SRC
