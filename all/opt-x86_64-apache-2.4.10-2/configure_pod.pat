--- configure.orig	Mon Sep 30 17:45:00 2013
+++ configure	Mon Sep 30 17:45:24 2013
@@ -27049,10 +27049,10 @@
 
 
     if ap_mpm_is_enabled event; then
-        if test -z "event.lo fdqueue.lo "; then
+        if test -z "event.lo fdqueue.lo pod.lo"; then
             objects="event.lo"
         else
-            objects="event.lo fdqueue.lo "
+            objects="event.lo fdqueue.lo pod.lo"
         fi
 
         if test -z ""; then
