--- threads.c~	Tue Sep 11 03:52:46 2012
+++ threads.c	Fri Sep 21 11:50:16 2012
@@ -47,7 +47,7 @@
 #ifdef HAVE_PTHREAD_H
 
 static int libxml_is_threaded = -1;
-#ifdef __GNUC__
+#if 0
 #ifdef linux
 #if (__GNUC__ == 3 && __GNUC_MINOR__ >= 3) || (__GNUC__ > 3)
 extern int pthread_once (pthread_once_t *__once_control,
