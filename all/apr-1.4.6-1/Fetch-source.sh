#!/bin/bash

SRC=apr-1.4.6.tar.bz2
DST=/var/spool/src/$SRC

[ -s "$DST" ] || wget -O $DST http://archive.apache.org/dist/apr/$SRC
