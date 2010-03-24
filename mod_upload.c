#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
 
#define UNSET (-1)
#define DISABLED (0)
#define ENABLED (1)
 
#define UPLOAD "X-Upload-File"
static const char VERSION[] = "mod_upload/0.1";
static const char X_UPLOAD[] = UPLOAD;
 
module AP_MODULE_DECLARE_DATA upload_module;
 
#define AP_LOG_DEBUG(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, rec, fmt, ##__VA_ARGS__)
#define AP_LOG_INFO(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, rec, "[upload] " fmt, ##__VA_ARGS__)
#define AP_LOG_WARN(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_WARNING,0, rec, "[upload] " fmt, ##__VA_ARGS__)
#define AP_LOG_ERR(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, rec, "[upload] " fmt, ##__VA_ARGS__)
 
// Config store.
typedef struct {
  apr_pool_t* pool;
  int   enabled;
  char* url_base;
  char* dir_base;
} upload_conf;
 
 
// Callbacks context.
typedef struct {
  upload_conf* conf;
  char* separator;
  char* filename;
  int fd;
} context;
 
 
// apr_table_do() callback proc: Copy headers from apache-request to curl-request.
static int each_headers_proc(void* rec_, const char* key, const char* value)
{
  apr_file_t* file = (apr_file_t*)rec_;
  apr_file_printf(file, "[Header] %s: %s\n", key, value);
  return TRUE;
}
 
//
// Main functions.
//
// Save to tmpfile
static apr_status_t save_to_file(request_rec* rec, const char* filename)
{
  apr_file_t* file = NULL;
  apr_status_t status, s_close;
  apr_off_t length = 0, count = 0;
  const char* hdr;

  // get content-length 
  hdr = apr_table_get(rec->headers_in, "Content-Length");
  length = (hdr)? apr_atoi64(hdr): LLONG_MAX;
  AP_LOG_DEBUG(rec, " Content-Length: %lu", length);

  // create file.
  status = apr_file_open(&file, filename, APR_WRITE|APR_CREATE|APR_TRUNCATE, APR_FPROT_OS_DEFAULT, rec->pool);
  if(status!=APR_SUCCESS) goto FINALLY;
 
  // save to file.
  status = ap_setup_client_block(rec, REQUEST_CHUNKED_DECHUNK);
  if(status==OK) {
    char buf[32768];
    apr_size_t bytes;

    while(((bytes=ap_get_client_block(rec, buf, sizeof(buf)))>0) && (length>count)) {
      apr_size_t  wr = 0;
      if(count+bytes>length) {
        AP_LOG_WARN(rec, "Illegal Content-Length : %llu", length);
        bytes = length - count;
      }
      while(wr<bytes) {
        apr_size_t w = bytes - wr;
        status = apr_file_write(file, buf, &w);
        if(status!=APR_SUCCESS) goto FINALLY;
        wr += w;
      }
      count += bytes;
    }
  }
 
FINALLY:
  if(file) {
    s_close = apr_file_close(file);
    if(s_close!=APR_SUCCESS) {
      AP_LOG_ERR(rec, "Failed to close file(%s)(%d).", filename, s_close);
      status = s_close;
    }
  }
  if(status!=APR_SUCCESS) {
    apr_file_remove(filename, rec->pool);
    ap_rprintf(rec, "Write failed: %s : %s(%d)\n", filename, strerror(status), status);
    AP_LOG_ERR(rec, "Write failed: %s : %s(%d)", filename, strerror(status), status);
  } else {
    ap_rprintf(rec, "Saved: %s (%lu)\n", filename, count);
    AP_LOG_DEBUG(rec, "%lu bytes read.", count);
  }
  return status;
}
 
 
// Direct upload handler
static int direct_upload_handler(request_rec *rec)
{
  upload_conf* conf = (upload_conf*)ap_get_module_config(rec->per_dir_config, &upload_module);
  apr_status_t status = APR_SUCCESS;
  char* filename = rec->uri;
  int   u;
 
  if(!conf || !conf->enabled) return DECLINED;
 
  AP_LOG_DEBUG(rec, "Incomming %s Enabled=%d %s", __FUNCTION__, conf->enabled, rec->method);
  AP_LOG_DEBUG(rec, "  url_base=%s dir_base=%s", conf->url_base, conf->dir_base);
  AP_LOG_DEBUG(rec, "  URI=%s", rec->uri);
  if((rec->method_number & (M_POST|M_PUT))==0) return DECLINED; // Handled 'PUT', 'POST' only.
  if(strcasecmp(rec->handler, "upload")) return DECLINED;
 
  rec->content_type = "plain/text";
  u = strlen(conf->url_base);
  if(strncmp(rec->uri, conf->url_base, u)==0) {
    filename = apr_pstrcat(rec->pool, conf->dir_base, rec->uri + u, NULL);
  }
  status = save_to_file(rec, filename);

  switch(status) {
  case OK:
    rec->status = HTTP_CREATED;
    break;
  case EEXIST:
  case ENOTDIR:
    rec->status = HTTP_BAD_REQUEST;
    break;
  case EACCES:
    rec->status = HTTP_FORBIDDEN;
    break;
  default:
    rec->status = HTTP_BAD_REQUEST;
    break;
  }
  return OK;
}
 
 
// apr_table_do() callback proc: Copy headers from apache-request to curl-request.
static int each_headers_proc_0(void* _rec, const char* key, const char* value)
{
  request_rec *rec = (request_rec*)_rec;
  AP_LOG_DEBUG(rec, "++ %s: %s", key, value);
  return TRUE;
}
 
static int dump_headers(request_rec *rec)
{
  apr_table_do(each_headers_proc_0, rec, rec->headers_in, NULL);
  return OK;
}
 
//
// Configurators, and Register.
//
static void* config_create(apr_pool_t* p, char* path)
{
  upload_conf* conf = apr_palloc(p, sizeof(upload_conf));
  conf->pool = p;
  conf->enabled = FALSE;
  conf->url_base = "";
  conf->dir_base = "";
  return conf;
}

static const char* upload_option(cmd_parms* cmd, void* _conf, const char* param1, const char* param2)
{
  upload_conf* conf = _conf;
  conf->url_base = apr_pstrdup(conf->pool, param1);
  conf->dir_base = apr_pstrdup(conf->pool, param2);
  return NULL;
}
 
static const command_rec config_cmds[] = {
  AP_INIT_FLAG("Upload", ap_set_flag_slot, (void*)APR_OFFSETOF(upload_conf, enabled), OR_OPTIONS, "{On|Off}"),
  AP_INIT_TAKE2("Upload_base", upload_option, NULL, OR_OPTIONS, "Rename URL to file."),
  { NULL },
};
 
static void register_hooks(apr_pool_t *p)
{
  ap_hook_handler(direct_upload_handler, NULL, NULL, APR_HOOK_MIDDLE);
  // ap_hook_fixups(dump_headers, NULL, NULL, APR_HOOK_MIDDLE);
}
 
/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA upload_module = {
  STANDARD20_MODULE_STUFF,
  config_create, /* create per-dir config structures */
  NULL, /* merge per-dir config structures */
  NULL, /* create per-server config structures */
  NULL, /* merge per-server config structures */
  config_cmds, /* table of config file commands */
  register_hooks /* register hooks */
};
