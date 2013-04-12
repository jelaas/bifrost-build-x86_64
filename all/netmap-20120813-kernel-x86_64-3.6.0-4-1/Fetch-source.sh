#!/bin/bash

SRC=20120813-netmap.tgz
DST=/var/spool/src/netmap-20120813.tar.gz

[ -s "$DST" ] || wget -O $DST http://info.iet.unipi.it/~luigi/doc/$SRC
