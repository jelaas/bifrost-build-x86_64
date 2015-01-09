--- ssl/ssl.h.orig	Thu Apr 24 12:24:00 2014
+++ ssl/ssl.h	Thu Apr 24 12:26:07 2014
@@ -331,7 +331,7 @@
 /* The following cipher list is used by default.
  * It also is substituted when an application-defined cipher list string
  * starts with 'DEFAULT'. */
-#define SSL_DEFAULT_CIPHER_LIST	"ALL:!aNULL:!eNULL:!SSLv2"
+#define SSL_DEFAULT_CIPHER_LIST	"ALL:!aNULL:!eNULL:!SSLv2:!RC4:!MD5"
 /* As of OpenSSL 1.0.0, ssl_create_cipher_list() in ssl/ssl_ciph.c always
  * starts with a reasonable order, and all we have to do for DEFAULT is
  * throwing out anonymous and unencrypted ciphersuites!
