#!/bin/bash

SRC=open-vm-tools-9.2.2-893683.tar.gz
DST=/var/spool/src/$SRC

[ -s "$DST" ] || wget -O $DST http://downloads.sourceforge.net/project/open-vm-tools/open-vm-tools/stable-9.2.x/$SRC
