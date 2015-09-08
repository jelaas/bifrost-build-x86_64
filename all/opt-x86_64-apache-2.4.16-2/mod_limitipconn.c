/*
   mod_limitipconn 0.24
   Copyright (C) 2000-2012 David Jao and Niklas Edmundsson

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_core.h"
#include "http_main.h"
#include "http_log.h"
#include "ap_mpm.h"
#include "apr_strings.h"
#include "scoreboard.h"

#define MODULE_NAME "mod_limitipconn"
#define MODULE_VERSION "0.24"

module AP_MODULE_DECLARE_DATA limitipconn_module;

static int server_limit, thread_limit;

typedef struct {
    signed int limit;       /* max number of connections per IP */

    /* array of MIME types exempt from limit checking */
    apr_array_header_t *no_limit;

    /* array of MIME types to limit check; all other types are exempt */
    apr_array_header_t *excl_limit;

} limitipconn_config;

static limitipconn_config *create_config(apr_pool_t *p)
{
    limitipconn_config *cfg = (limitipconn_config *)
                               apr_pcalloc(p, sizeof (*cfg));

    /* default configuration: no limit, and both arrays are empty */
    cfg->limit = 0;
    cfg->no_limit = apr_array_make(p, 0, sizeof(char *));
    cfg->excl_limit = apr_array_make(p, 0, sizeof(char *));

    return cfg;
}

/* Create per-server configuration structure. Used by the quick handler. */
static void *limitipconn_create_config(apr_pool_t *p, server_rec *s)
{
    return create_config(p);
}

/* Create per-directory configuration structure. Used by the normal handler. */
static void *limitipconn_create_dir_config(apr_pool_t *p, char *path)
{
    return create_config(p);
}

/* Generic function to check a request against a config. */
static int check_limit(request_rec *r, limitipconn_config *cfg)
{
    /* convert Apache arrays to normal C arrays */
    char **nolim = (char **) cfg->no_limit->elts;
    char **exlim = (char **) cfg->excl_limit->elts;

    const char *address;

    /* loop index variables */
    int i;
    int j;

    /* running count of number of connections from this address */
    int ip_count = 0;

    /* Content-type of the current request */
    const char *content_type;

    /* scoreboard data structure */
    worker_score *ws_record;

    /* We decline to handle subrequests: otherwise, in the next step we
     * could get into an infinite loop. */
    if (!ap_is_initial_req(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                     "mod_limitipconn: SKIPPED: Not initial request");
        return DECLINED;
    }

    /* A limit value of 0 or less, by convention, means no limit. */
    if (cfg->limit <= 0) {
        return DECLINED;
    }

#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
    address = r->useragent_ip;
#else
    address = r->connection->remote_ip;
#endif

    /* Only check the MIME-type if we have MIME-type stuff in our config.
       The extra subreq can be quite expensive. */
    if(cfg->no_limit->nelts > 0 || cfg->excl_limit->nelts > 0) {
        /* Look up the Content-type of this request. We need a subrequest
         * here since this module might be called before the URI has been
         * translated into a MIME type. */
        content_type = ap_sub_req_lookup_uri(r->uri, r, NULL)->content_type;

#if !AP_MODULE_MAGIC_AT_LEAST(20090131, 0)
        /* If there's no Content-type, use the default. */
        if (!content_type) {
            content_type = ap_default_type(r);
        }
#endif

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "mod_limitipconn: uri: %s  Content-Type: %s", 
                r->uri, content_type);

        /* Cycle through the exempt list; if our content_type is exempt,
         * return OK */
#if AP_MODULE_MAGIC_AT_LEAST(20090131, 0)
        if (content_type)
#endif
        for (i = 0; i < cfg->no_limit->nelts; i++) {
            if ((ap_strcasecmp_match(content_type, nolim[i]) == 0)
                || (strncmp(nolim[i], content_type, strlen(nolim[i])) == 0)) 
            {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                             "mod_limitipconn: OK: %s exempt", content_type);
                return DECLINED;
            }
        }

        /* Cycle through the exclusive list, if it exists; if our MIME type
         * is not present, bail out */
        if (cfg->excl_limit->nelts) {
            int excused = 1;

#if AP_MODULE_MAGIC_AT_LEAST(20090131, 0)
            if (content_type)
#endif
            for (i = 0; i < cfg->excl_limit->nelts; i++) {
                if ((ap_strcasecmp_match(content_type, exlim[i]) == 0)
                    || 
                    (strncmp(exlim[i], content_type, strlen(exlim[i])) == 0)) 
                {
                    excused = 0;
                }
            }
            if (excused) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                             "mod_limitipconn: OK: %s not excluded", 
                             content_type);
                return DECLINED;
            }
        }
    }

    /* Count up the number of connections we are handling right now from
     * this IP address */
    for (i = 0; i < server_limit; ++i) {
      for (j = 0; j < thread_limit; ++j) {
#if AP_MODULE_MAGIC_AT_LEAST(20071023, 0)
        ws_record = ap_get_scoreboard_worker_from_indexes(i, j);
#else
        ws_record = ap_get_scoreboard_worker(i, j);
#endif
        switch (ws_record->status) {
            case SERVER_BUSY_READ:
            case SERVER_BUSY_WRITE:
            case SERVER_BUSY_KEEPALIVE:
            case SERVER_BUSY_LOG:
            case SERVER_BUSY_DNS:
            case SERVER_CLOSING:
            case SERVER_GRACEFUL:
                if (strcmp(address, ws_record->client) == 0)
                    ip_count++;
                break;
            default:
                break;
        }
      }
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "mod_limitipconn: vhost: %s  uri: %s  current: %d  limit: %d", 
            r->server->server_hostname, r->uri, ip_count, cfg->limit);

    if (ip_count > cfg->limit) {
      ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, 
                    "Rejected, too many connections from this host.");
      /* set an environment variable */
      apr_table_setn(r->subprocess_env, "LIMITIP", "1");
      /* return 503 */
      return HTTP_SERVICE_UNAVAILABLE;
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                     "mod_limitipconn: OK: Passed all checks");
        return DECLINED;
    }
}

/* Normal handler. This function is invoked to handle limitipconn
   directives within a per-directory context. */
static int limitipconn_handler(request_rec *r)
{
    /* get configuration information */
    limitipconn_config *cfg = (limitipconn_config *)
        ap_get_module_config(r->per_dir_config, &limitipconn_module);

    int result;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
		  "mod_limitipconn: Entering normal handler");
    result = check_limit(r, cfg);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
		  "mod_limitipconn: Exiting normal handler");
    return result;
}

/* Quick handler. This function is invoked to handle limitipconn
   directives within a per-server context. 

   The handler runs as a quick handler so we can arrange for it to be
   called before mod_cache. Being a quick handler means that we have a
   lot of limitations, the basic ones are that the only thing we know
   is the URL and that if we return OK it means that we handle the
   entire reply of the request including populating the brigades with
   data.

   Because this is a quick handler, it _CANNOT_ process per-directory
   configuration directives. Therefore, if you have any per-directory
   configuration directives, they will _NOT_ be handled here, and
   mod_cache will get to them first.
*/
static int limitipconn_quick_handler(request_rec *r, int lookup)
{
    /* get configuration information */
    limitipconn_config *cfg = (limitipconn_config *)
      ap_get_module_config(r->server->module_config, &limitipconn_module);

    int result;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
		  "mod_limitipconn: Entering quick handler");
    result = check_limit(r, cfg);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
		  "mod_limitipconn: Exiting quick handler");
    return result;
}

/* Parse the MaxConnPerIP directive */
static const char *limit_config_cmd(cmd_parms *parms, void *mconfig,
                                    const char *arg)
{
    limitipconn_config *cfg = (limitipconn_config *) mconfig;
    limitipconn_config *scfg = (limitipconn_config *)
      ap_get_module_config(parms->server->module_config, &limitipconn_module);

    signed long int limit = strtol(arg, (char **) NULL, 10);

    /* No reasonable person would want more than 2^16. Better would be
       to use LONG_MAX but that causes portability problems on win32 */
    if ((limit > 65535) || (limit < 0)) {
        return "Integer overflow or invalid number";
    }

    if (parms->path != NULL) {
      /* Per-directory context */
      cfg->limit = limit;
    } else {
      /* Per-server context */
      scfg->limit = limit;
    }
    return NULL;
}

/* Parse the NoIPLimit directive */
static const char *no_limit_config_cmd(cmd_parms *parms, void *mconfig,
                                       const char *arg)
{
    limitipconn_config *cfg = (limitipconn_config *) mconfig;
    limitipconn_config *scfg = (limitipconn_config *)
      ap_get_module_config(parms->server->module_config, &limitipconn_module);

    if (parms->path != NULL) {
      /* Per-directory context */
      *(char **) apr_array_push(cfg->no_limit) =
	apr_pstrdup(parms->pool, arg);
    } else {
      /* Per-server context */
      *(char **) apr_array_push(scfg->no_limit) =
	apr_pstrdup(parms->pool, arg);
    }
    return NULL;
}

/* Parse the OnlyIPLimit directive */
static const char *excl_limit_config_cmd(cmd_parms *parms, void *mconfig,
                                         const char *arg)
{
    limitipconn_config *cfg = (limitipconn_config *) mconfig;
    limitipconn_config *scfg = (limitipconn_config *)
      ap_get_module_config(parms->server->module_config, &limitipconn_module);

    if (parms->path != NULL) {
      /* Per-directory context */
      *(char **) apr_array_push(cfg->excl_limit) =
	apr_pstrdup(parms->pool, arg);
    } else {
      /* Per-server context */
      *(char **) apr_array_push(scfg->excl_limit) =
	apr_pstrdup(parms->pool, arg);
    }
    return NULL;
}

/* Array describing structure of configuration directives */
static command_rec limitipconn_cmds[] = {
    AP_INIT_TAKE1("MaxConnPerIP", limit_config_cmd, NULL, OR_LIMIT|RSRC_CONF,
     "maximum simultaneous connections per IP address"),
    AP_INIT_ITERATE("NoIPLimit", no_limit_config_cmd, NULL, OR_LIMIT|RSRC_CONF,
     "MIME types for which limit checking is disabled"),
    AP_INIT_ITERATE("OnlyIPLimit", excl_limit_config_cmd, NULL,
     OR_LIMIT|RSRC_CONF, "restrict limit checking to these MIME types only"),
    {NULL},
};

/* Set up startup-time initialization */
static int limitipconn_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                 MODULE_NAME " " MODULE_VERSION " started.");
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &server_limit);
    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    static const char * const after_me[] = { "mod_cache.c", NULL };

    ap_hook_post_config(limitipconn_init, NULL, NULL, APR_HOOK_MIDDLE);
    /* We check against the per-server configuration directives in a
       quick handler so that we can deny connections before mod_cache
       gets to them.  This method does not work for per-directory
       configuration directives.  If you are using mod_cache, please
       avoid per-directory configuration directives for limitipconn.
    */
    ap_hook_quick_handler(limitipconn_quick_handler,NULL,after_me,
                          APR_HOOK_FIRST);
    ap_hook_access_checker(limitipconn_handler,NULL,NULL,APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA limitipconn_module = {
    STANDARD20_MODULE_STUFF,
    limitipconn_create_dir_config, /* create per-dir config structures */
    NULL,                       /* merge  per-dir    config structures */
    limitipconn_create_config,  /* create per-server config structures */
    NULL,                       /* merge  per-server config structures */
    limitipconn_cmds,           /* table of config file commands       */
    register_hooks
};
