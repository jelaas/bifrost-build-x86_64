#!/bin/bash

SRC=console-data-1999.08.29.tar.gz
DST=/var/spool/src/$SRC

[ -s "$DST" ] || wget -O $DST http://www.ibiblio.org/pub/Linux/system/keyboards/$SRC
