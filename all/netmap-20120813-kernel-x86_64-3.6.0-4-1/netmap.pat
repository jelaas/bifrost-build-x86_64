--- netmap/examples/Makefile	Fri Apr 12 12:15:04 2013
+++ netmap/examples/Makefile	Fri Apr 12 12:15:15 2013
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
 
--- netmap/examples/nm_util.h	Fri Apr 12 12:15:04 2013
+++ netmap/examples/nm_util.h	Fri Apr 12 12:15:15 2013
@@ -39,7 +39,7 @@
 #include <string.h>	/* strcmp */
 #include <fcntl.h>	/* open */
 #include <unistd.h>	/* close */
-#include <ifaddrs.h>	/* getifaddrs */
+//#include <ifaddrs.h>	/* getifaddrs */
 
 #include <sys/mman.h>	/* PROT_* */
 #include <sys/ioctl.h>	/* ioctl */
--- netmap/examples/pkt-gen.c	Fri Apr 12 12:15:04 2013
+++ netmap/examples/pkt-gen.c	Fri Apr 12 12:16:03 2013
@@ -188,7 +188,7 @@
 
 	return (ncpus);
 #else
-	return 1;
+	return 12;
 #endif /* !__FreeBSD__ */
 }
 
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
 
 
