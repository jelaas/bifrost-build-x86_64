--- modules/filters/mod_proxy_html.c~	2012-02-03 20:59:26.000000000 +0100
+++ modules/filters/mod_proxy_html.c	2012-03-13 13:23:15.679200508 +0100
@@ -159,15 +159,8 @@
     saxctxt *ctx = (saxctxt*) ctxt;
     int i;
     int begin;
-    for (begin=i=0; i<length; i++) {
-        switch (chars[i]) {
-        case '&' : FLUSH; ap_fputs(ctx->f->next, ctx->bb, "&amp;"); break;
-        case '<' : FLUSH; ap_fputs(ctx->f->next, ctx->bb, "&lt;"); break;
-        case '>' : FLUSH; ap_fputs(ctx->f->next, ctx->bb, "&gt;"); break;
-        case '"' : FLUSH; ap_fputs(ctx->f->next, ctx->bb, "&quot;"); break;
-        default : break;
-        }
-    }
+    begin=0;
+    i=length;
     FLUSH;
 }
 
