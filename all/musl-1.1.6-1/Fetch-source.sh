#!/bin/bash

SRC=musl-1.1.6.tar.gz
DST=/var/spool/src/$SRC

[ -s "$DST" ] || wget -O $DST http://www.etalabs.net/musl/releases/$SRC
