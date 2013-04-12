--- netmap/examples/Makefile	Fri Aug  3 12:45:56 2012
+++ netmap/examples/Makefile	Thu Apr 11 13:17:10 2013
@@ -2,12 +2,12 @@
 # we can just define 'progs' and create custom targets.
 PROGS	=	pkt-gen bridge testpcap libnetmap.so
 #PROGS += pingd
-PROGS	+= testlock testcsum test_select kern_test
+#PROGS	+= testlock testcsum test_select kern_test
 
 CLEANFILES = $(PROGS) pcap.o nm_util.o *.o
 NO_MAN=
 CFLAGS = -O2 -pipe
-CFLAGS += -Werror -Wall
+CFLAGS += -Werror -Wall -static
 CFLAGS += -I ../sys # -I/home/luigi/FreeBSD/head/sys -I../sys
 CFLAGS += -Wextra
 
--- netmap/examples/nm_util.h	Fri Aug  3 12:45:56 2012
+++ netmap/examples/nm_util.h	Thu Apr 11 12:53:58 2013
@@ -39,7 +39,7 @@
 #include <string.h>	/* strcmp */
 #include <fcntl.h>	/* open */
 #include <unistd.h>	/* close */
-#include <ifaddrs.h>	/* getifaddrs */
+//#include <ifaddrs.h>	/* getifaddrs */
 
 #include <sys/mman.h>	/* PROT_* */
 #include <sys/ioctl.h>	/* ioctl */
--- netmap/examples/pkt-gen.c	Wed Aug  8 16:30:02 2012
+++ netmap/examples/pkt-gen.c	Thu Apr 11 13:23:20 2013
@@ -205,6 +205,9 @@
 static int
 source_hwaddr(const char *ifname, char *buf)
 {
+	(void)ifname;
+	(void)buf;
+	/*
 	struct ifaddrs *ifaphead, *ifap;
 	int l = sizeof(ifap->ifa_name);
 
@@ -232,6 +235,8 @@
 	}
 	freeifaddrs(ifaphead);
 	return ifap ? 0 : 1;
+	*/
+	return 0;
 }
 
 
