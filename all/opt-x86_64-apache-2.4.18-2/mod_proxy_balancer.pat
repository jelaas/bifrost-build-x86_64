--- httpd/httpd/trunk/modules/proxy/mod_proxy_balancer.c	2015/08/21 12:33:44	1696959
+++ httpd/httpd/trunk/modules/proxy/mod_proxy_balancer.c	2015/08/21 12:34:02	1696960
@@ -761,8 +761,11 @@
         char *id;
         proxy_balancer *balancer;
         ap_slotmem_type_t type;
+        apr_size_t attached_size;
+        unsigned int attached_num;
         void *sconf = s->module_config;
         conf = (proxy_server_conf *)ap_get_module_config(sconf, &proxy_module);
+
         /*
          * During create_proxy_config() we created a dummy id. Now that
          * we have identifying info, we can create the real id
@@ -794,11 +797,39 @@
                          (int)ALIGNED_PROXY_BALANCER_SHARED_SIZE,
                          (int)conf->balancers->nelts, conf->max_balancers);
 
-            rv = storage->create(&new, conf->id,
-                                 ALIGNED_PROXY_BALANCER_SHARED_SIZE,
-                                 conf->max_balancers, type, pconf);
+            /* First try to attach() since the number of configured balancers
+             * may have changed during restart, and we don't want create() to
+             * fail because the overall size * number of entries is not stricly
+             * identical to the previous run.  There may still be enough room
+             * for this new run thanks to bgrowth margin, so if attach()
+             * succeeds we can only check for the number of available entries
+             * to be *greater or* equal to what we need now.  If attach() fails
+             * we simply fall back to create().
+             */
+            rv = storage->attach(&new, conf->id,
+                                 &attached_size, &attached_num,
+                                 pconf);
+            if (rv != APR_SUCCESS) {
+                rv = storage->create(&new, conf->id,
+                                     ALIGNED_PROXY_BALANCER_SHARED_SIZE,
+                                     conf->max_balancers, type, pconf);
+            }
+            else {
+                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(02964)
+                             "Balancers attached: %d, %d (%d)",
+                             (int)ALIGNED_PROXY_BALANCER_SHARED_SIZE,
+                             (int)attached_num, conf->max_balancers);
+                if (attached_size == ALIGNED_PROXY_BALANCER_SHARED_SIZE
+                        && attached_num >= conf->balancers->nelts) {
+                    conf->max_balancers = attached_num;
+                }
+                else {
+                    rv = APR_ENOSPC;
+                }
+            }
             if (rv != APR_SUCCESS) {
-                ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, APLOGNO(01179) "balancer slotmem_create failed");
+                ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, APLOGNO(01179)
+                             "balancer slotmem create or attach failed");
                 return !OK;
             }
             conf->bslot = new;
@@ -864,11 +895,32 @@
                          (int)ALIGNED_PROXY_WORKER_SHARED_SIZE,
                          (int)balancer->max_workers, i);
 
-            rv = storage->create(&new, balancer->s->sname,
-                                 ALIGNED_PROXY_WORKER_SHARED_SIZE,
-                                 balancer->max_workers, type, pconf);
+            /* try to attach first (see rationale from balancers above) */
+            rv = storage->attach(&new, balancer->s->sname,
+                                 &attached_size, &attached_num,
+                                 pconf);
+            if (rv != APR_SUCCESS) {
+                rv = storage->create(&new, balancer->s->sname,
+                                     ALIGNED_PROXY_WORKER_SHARED_SIZE,
+                                     balancer->max_workers, type, pconf);
+            }
+            else {
+                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(02965)
+                             "Workers attached: %s (%s), %d, %d (%d) [%u]",
+                             balancer->s->name, balancer->s->sname,
+                             (int)ALIGNED_PROXY_WORKER_SHARED_SIZE,
+                             (int)attached_num, balancer->max_workers, i);
+                if (attached_size == ALIGNED_PROXY_WORKER_SHARED_SIZE
+                        && attached_num >= balancer->workers->nelts) {
+                    balancer->max_workers = attached_num;
+                }
+                else {
+                    rv = APR_ENOSPC;
+                }
+            }
             if (rv != APR_SUCCESS) {
-                ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, APLOGNO(01185) "worker slotmem_create failed");
+                ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, APLOGNO(01185)
+                             "worker slotmem create or attach failed");
                 return !OK;
             }
             balancer->wslot = new;
