diff --git a/modules/cache/mod_cache_socache.c b/modules/cache/mod_cache_socache.c
index e75e124..6d84205 100644
--- a/modules/cache/mod_cache_socache.c
+++ b/modules/cache/mod_cache_socache.c
@@ -382,6 +382,7 @@ static int create_entity(cache_handle_t *h, request_rec *r, const char *key,
      * decide whether or not to ignore this attempt to cache,
      * with a small margin just to be sure.
      */
+#if 0
     if (len < 0) {
         ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02346)
                 "URL '%s' had no explicit size, ignoring", key);
@@ -414,7 +415,7 @@ static int create_entity(cache_handle_t *h, request_rec *r, const char *key,
                 key, len, dconf->max);
         return DECLINED;
     }
-
+#endif
     /* Allocate and initialize cache_object_t and cache_socache_object_t */
     h->cache_obj = obj = apr_pcalloc(r->pool, sizeof(*obj));
     obj->vobj = sobj = apr_pcalloc(r->pool, sizeof(*sobj));
@@ -1020,6 +1021,18 @@ static apr_status_t store_body(cache_handle_t *h, request_rec *r,
             continue;
         }
 
+	if((sobj->body_offset+sobj->file_size+length) > dconf->max) {
+		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
+			      "URL %s, %" APR_OFF_T_FMT " too large for cache. max=%" APR_OFF_T_FMT,
+			      h->cache_obj->key,
+			      sobj->body_offset+sobj->file_size+length,
+			      dconf->max
+			);
+		apr_pool_destroy(sobj->pool);
+		sobj->pool = NULL;
+		continue;
+	}
+
         sobj->file_size += length;
         if (sobj->file_size >= sobj->buffer_len - sobj->body_offset) {
             ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02378)
@@ -1101,6 +1114,12 @@ static apr_status_t commit_entity(cache_handle_t *h, request_rec *r)
     apr_status_t rv;
     apr_size_t len;
 
+    if(!sobj->pool) {
+	    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Not caching: %s",
+			  sobj->key);
+	    return DECLINED;
+    }
+
     /* flatten the body into the buffer */
     len = sobj->buffer_len - sobj->body_offset;
     rv = apr_brigade_flatten(sobj->body, (char *) sobj->buffer
