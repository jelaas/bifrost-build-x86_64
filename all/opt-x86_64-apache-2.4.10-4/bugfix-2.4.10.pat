--- modules/proxy/mod_proxy_http.c.orig	Tue Aug 12 12:13:22 2014
+++ modules/proxy/mod_proxy_http.c	Tue Aug 12 12:17:06 2014
@@ -1658,6 +1658,18 @@
             if (!r->header_only && /* not HEAD request */
                 (proxy_status != HTTP_NO_CONTENT) && /* not 204 */
                 (proxy_status != HTTP_NOT_MODIFIED)) { /* not 304 */
+                const char *tmp;
+                /* Add minimal headers needed to allow http_in filter
+                 * detecting end of body without waiting for a timeout. */
+                if ((tmp = apr_table_get(r->headers_out, "Content-Length"))) {
+                    apr_table_set(backend->r->headers_in, "Content-Length", tmp);
+                }
+                else if ((tmp = apr_table_get(r->headers_out, "Transfer-Encoding"))) {
+                    apr_table_set(backend->r->headers_in, "Transfer-Encoding", tmp);
+                }
+                else if (te) {
+                    apr_table_set(backend->r->headers_in, "Transfer-Encoding", te);
+                }
                 ap_discard_request_body(backend->r);
             }
             return proxy_status;
