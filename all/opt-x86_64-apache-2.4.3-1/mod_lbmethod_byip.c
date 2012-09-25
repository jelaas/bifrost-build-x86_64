/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mod_proxy.h"
#include "scoreboard.h"
#include "ap_mpm.h"
#include "apr_version.h"
#include "ap_hooks.h"

module AP_MODULE_DECLARE_DATA lbmethod_byip_module;

static int (*ap_proxy_retry_worker_fn)(const char *proxy_function,
        proxy_worker *worker, server_rec *s) = NULL;

/*
 * The idea behind the find_best_byrequests scheduler is the following:
 *
 * lbfactor is "how much we expect this worker to work", or "the worker's
 * normalized work quota".
 *
 * lbstatus is "how urgent this worker has to work to fulfill its quota
 * of work".
 *
 * We distribute each worker's work quota to the worker, and then look
 * which of them needs to work most urgently (biggest lbstatus).  This
 * worker is then selected for work, and its lbstatus reduced by the
 * total work quota we distributed to all workers.  Thus the sum of all
 * lbstatus does not change.(*)
 *
 * If some workers are disabled, the others will
 * still be scheduled correctly.
 *
 * If a balancer is configured as follows:
 *
 * worker     a    b    c    d
 * lbfactor  25   25   25   25
 *
 * And b gets disabled, the following schedule is produced:
 *
 *    a c d a c d a c d ...
 *
 * Note that the above lbfactor setting is the *exact* same as:
 *
 * worker     a    b    c    d
 * lbfactor   1    1    1    1
 *
 * Asymmetric configurations work as one would expect. For
 * example:
 *
 * worker     a    b    c    d
 * lbfactor   1    1    1    2
 *
 * would have a, b and c all handling about the same
 * amount of load with d handling twice what a or b
 * or c handles individually. So we could see:
 *
 *   b a d c d a c d b d ...
 *
 */

static unsigned int _client_hash(char *u)
{
        unsigned int h = 0;
        if(!u) return 0;

	while(*u) h += *u++;
        return h;
}

static proxy_worker *find_best_byip(proxy_balancer *balancer,
                                request_rec *r)
{
	int i, n = 0, n_repl;
	int total_factor = 0;
	proxy_worker **worker;
	proxy_worker *mycandidate = NULL;
	int cur_lbset = 0;
	int max_lbset = 0;
	int checking_standby;
	int checked_standby;
	unsigned int hash;
	
	if (!ap_proxy_retry_worker_fn) {
		ap_proxy_retry_worker_fn =
			APR_RETRIEVE_OPTIONAL_FN(ap_proxy_retry_worker);
		if (!ap_proxy_retry_worker_fn) {
			/* can only happen if mod_proxy isn't loaded */
			return NULL;
		}
	}
	
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, APLOGNO(01207)
		     "proxy: Entering byip for BALANCER (%s)",
		     balancer->s->name);
	
	hash = _client_hash(r->useragent_ip);
	if(balancer->workers->nelts)
		n = hash % balancer->workers->nelts;
	n_repl = n;
	if(balancer->workers->nelts > 1) {
		n_repl = hash % (balancer->workers->nelts-1);
	}
	
	/* First try to see if we have available candidate */
	do {
		checking_standby = checked_standby = 0;
		while (!mycandidate && !checked_standby) {
			worker = (proxy_worker **)balancer->workers->elts;
			for (i = 0; i < balancer->workers->nelts; i++, worker++) {
				if (!checking_standby) {    /* first time through */
					if ((*worker)->s->lbset > max_lbset)
						max_lbset = (*worker)->s->lbset;
				}
				if (
					((*worker)->s->lbset != cur_lbset) ||
					(checking_standby ? !PROXY_WORKER_IS_STANDBY(*worker) : PROXY_WORKER_IS_STANDBY(*worker)) ||
					(PROXY_WORKER_IS_DRAINING(*worker))
					) {
					continue;
				}
				
				/* If the worker is in error state run
				 * retry on that worker. It will be marked as
				 * operational if the retry timeout is elapsed.
				 * The worker might still be unusable, but we try
				 * anyway.
				 */
				if (!PROXY_WORKER_IS_USABLE(*worker))
					ap_proxy_retry_worker_fn("BALANCER", *worker, r->server);
				/* Take into calculation only the workers that are
				 * not in error state or not disabled.
				 */
				if (PROXY_WORKER_IS_USABLE(*worker)) {
					if(i == n) {
						mycandidate = *worker;
						break;
					}
					if(i == n_repl) {
						mycandidate = *worker;
					} else {
						if(!mycandidate) mycandidate = *worker;
					}
				}
			}
			checked_standby = checking_standby++;
		}
		cur_lbset++;
	} while (cur_lbset <= max_lbset && !mycandidate);
	
	if (mycandidate) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, APLOGNO(01208)
			     "proxy: byip selected worker \"%s\" for %s hash %u %% %d = %d",
			     mycandidate->s->name, r->useragent_ip, hash, balancer->workers->nelts, n);
		
	}
    
    return mycandidate;
}

/* assumed to be mutex protected by caller */
static apr_status_t reset(proxy_balancer *balancer, server_rec *s) {
    int i;
    proxy_worker **worker;
    worker = (proxy_worker **)balancer->workers->elts;
    for (i = 0; i < balancer->workers->nelts; i++, worker++) {
        (*worker)->s->lbstatus = 0;
    }
    return APR_SUCCESS;
}

static apr_status_t age(proxy_balancer *balancer, server_rec *s) {
        return APR_SUCCESS;
}

/*
 * How to add additional lbmethods:
 *   1. Create func which determines "best" candidate worker
 *      (eg: find_best_bytraffic, above)
 *   2. Register it as a provider.
 */
static const proxy_balancer_method byip =
{
    "byip",
    &find_best_byip,
    NULL,
    &reset,
    &age
};

static void register_hook(apr_pool_t *p)
{
    /* Only the mpm_winnt has child init hook handler.
     * make sure that we are called after the mpm
     * initializes and after the mod_proxy
     */
    ap_register_provider(p, PROXY_LBMETHOD, "byip", "0", &byip);
}

AP_DECLARE_MODULE(lbmethod_byip) = {
    STANDARD20_MODULE_STUFF,
    NULL,       /* create per-directory config structure */
    NULL,       /* merge per-directory config structures */
    NULL,       /* create per-server config structure */
    NULL,       /* merge per-server config structures */
    NULL,       /* command apr_table_t */
    register_hook /* register hooks */
};
