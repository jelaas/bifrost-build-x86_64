--- ssl/ssl.h.orig	Fri May  6 11:48:52 2016
+++ ssl/ssl.h	Fri May  6 11:49:54 2016
@@ -339,6 +339,7 @@
  * an application-defined cipher list string starts with 'DEFAULT'.
  */
-# define SSL_DEFAULT_CIPHER_LIST "ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2"
+# define SSL_DEFAULT_CIPHER_LIST "ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2:!RC4:!MD5"
 /*
  * As of OpenSSL 1.0.0, ssl_create_cipher_list() in ssl/ssl_ciph.c always
  * starts with a reasonable order, and all we have to do for DEFAULT is
