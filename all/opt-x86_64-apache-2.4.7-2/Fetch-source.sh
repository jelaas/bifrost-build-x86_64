#!/bin/bash

SRC=httpd-2.4.7.tar.bz2
DST=/var/spool/src/$SRC

[ -s "$DST" ] || wget -O $DST http://apache.archive.sunet.se/dist/httpd/$SRC
if [ ! -s "$DST" ]; then
	pkg_install wget-1.12-1 || exit 2
	wget --no-check-certificate -O $DST https://archive.apache.org/dist/httpd/$SRC
fi
