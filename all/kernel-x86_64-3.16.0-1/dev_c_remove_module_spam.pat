--- net/core/dev_ioctl.c.orig	Thu Aug 14 09:12:32 2014
+++ net/core/dev_ioctl.c	Thu Aug 14 09:12:58 2014
@@ -366,9 +366,7 @@
 	if (no_module && capable(CAP_NET_ADMIN))
 		no_module = request_module("netdev-%s", name);
 	if (no_module && capable(CAP_SYS_MODULE)) {
-		if (!request_module("%s", name))
-			pr_warn("Loading kernel module for a network device with CAP_SYS_MODULE (deprecated).  Use CAP_NET_ADMIN and alias netdev-%s instead.\n",
-				name);
+		request_module("%s", name);
 	}
 }
 EXPORT_SYMBOL(dev_load);
