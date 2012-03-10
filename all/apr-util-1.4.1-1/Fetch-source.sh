#!/bin/bash

SRC=apr-util-1.4.1.tar.bz2
DST=/var/spool/src/$SRC

[ -s "$DST" ] || wget -O $DST http://archive.apache.org/dist/apr/$SRC

