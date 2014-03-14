#!/bin/bash

SRC=libxml2-2.9.0.tar.gz
DST=/var/spool/src/$SRC

[ -s "$DST" ] || wget -O $DST ftp://xmlsoft.org/libxml2/$SRC
