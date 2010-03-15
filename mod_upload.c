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
#include <error.h>

#define UNSET     (-1)
#define DISABLED  (0)
#define ENABLED   (1)

#define UPLOAD    "X-Direct-Upload-File"
static const char VERSION[] = "mod_direct_upload/0.1";
static const char DIRECT_UPLOAD[] = UPLOAD;

module AP_MODULE_DECLARE_DATA direct_upload_module;

#define AP_LOG_DEBUG(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_DEBUG,  0, rec, fmt, ##__VA_ARGS__)
#define AP_LOG_INFO(rec, fmt, ...)  ap_log_rerror(APLOG_MARK, APLOG_INFO,   0, rec, "[upload] " fmt, ##__VA_ARGS__)
#define AP_LOG_WARN(rec, fmt, ...)  ap_log_rerror(APLOG_MARK, APLOG_WARNING,0, rec, "[upload] " fmt, ##__VA_ARGS__)
#define AP_LOG_ERR(rec, fmt, ...)   ap_log_rerror(APLOG_MARK, APLOG_ERR,    0, rec, "[upload] " fmt, ##__VA_ARGS__)

// Config store.
typedef struct {
  apr_pool_t*  pool;
  char* base;
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
static apr_file_t* save_to_file(request_rec* rec, apr_off_t* read_bytes)
{
  #define BUFLEN    (8192)
  apr_file_t* file = NULL;
  int eos = FALSE;
  const char* buf;
  apr_status_t  status;
  apr_size_t bytes;
  apr_bucket* b;
  apr_bucket_brigade* bb = NULL;
  apr_off_t zero = 0, count = 0;
  const char* tmpdir;
  char* tmpl;

  // create temp file.
  status = apr_temp_dir_get(&tmpdir, rec->pool);
  if(status!=APR_SUCCESS) {
    AP_LOG_ERR(rec, "No temp directory(%u).", (unsigned)status);
    return NULL;
  }
  status = apr_filepath_merge(&tmpl, tmpdir, __FILE__ ".XXXXXX", APR_FILEPATH_NATIVE, rec->pool);
  if(status!=APR_SUCCESS) {
    AP_LOG_ERR(rec, "Failed to create template(%u).", (unsigned)status);
    return NULL;
  }
  status = apr_file_mktemp(&file, tmpl, 0, rec->pool);
  if(status!=APR_SUCCESS) {
    AP_LOG_ERR(rec, "Failed to open tempfile(%s)(%u).", tmpl, (unsigned)status);
    return NULL;
  }
  AP_LOG_DEBUG(rec, "  Save to %s", tmpl);
  ap_rprintf(rec, "Saving to %s.\n", tmpl);
  apr_file_remove("/tmp/save_file", rec->pool);
  link(tmpl, "/tmp/save_file");

  // save to file.
  bb = apr_brigade_create(rec->pool, rec->connection->bucket_alloc);
  do {
    status = ap_get_brigade(rec->input_filters, bb, AP_MODE_READBYTES, APR_BLOCK_READ, BUFLEN);
    if(status==APR_SUCCESS) {
      for(b=APR_BRIGADE_FIRST(bb); b!=APR_BRIGADE_SENTINEL(bb); b=APR_BUCKET_NEXT(b)) {
        if(APR_BUCKET_IS_EOS(b)) {
          eos = TRUE;
          break;
        } else
        if(APR_BUCKET_IS_METADATA(b)) {
          continue;
        }
        bytes = BUFLEN;
        status = apr_bucket_read(b, &buf, &bytes, APR_BLOCK_READ);
        count += bytes;
        apr_file_write(file, buf, &bytes);
      }
    }
  } while(!eos && (status==APR_SUCCESS));
  apr_brigade_cleanup(bb);

  apr_file_flush(file);
  apr_file_seek(file, APR_SET, &zero);
  ap_rprintf(rec, "%llu bytes read.\n", count);
  if(read_bytes) *read_bytes = count;

  return file;
}


// Direct upload handler
static int direct_upload_handler(request_rec *rec)
{
  upload_conf* conf = (upload_conf*)ap_get_module_config(rec->per_dir_config, &direct_upload_module);
  const char* hdr;
  apr_file_t* file = NULL;
  apr_off_t read_bytes = 0;

  if(!conf->base[0]) return DECLINED;

  AP_LOG_DEBUG(rec, "Incomming %s Base=%s", __FUNCTION__, conf->base);
  AP_LOG_DEBUG(rec, "  %s %s %s", rec->method, rec->uri, rec->handler);
  if((rec->method_number & (M_POST|M_PUT))==0) return OK; // Handled 'PUT', 'POST' only.

  hdr = apr_table_get(rec->headers_in, "Content-Length");
  AP_LOG_DEBUG(rec, "  Content-Length: %s", hdr);

  hdr = apr_table_get(rec->headers_in, "Content-Type");
  AP_LOG_DEBUG(rec, "  Content-Type: %s", hdr);

  apr_table_do(each_headers_proc, file, rec->headers_in, NULL);
  file = save_to_file(rec, &read_bytes);

  if(file) apr_table_set(rec->headers_in, "Content-Length", apr_psprintf(rec->pool, "%llu", read_bytes));

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
  conf->base = "";

  return conf;
}

static const command_rec config_cmds[] = {
  AP_INIT_TAKE1("DirectUpload", ap_set_string_slot, (void*)APR_OFFSETOF(upload_conf, base), OR_FILEINFO, "Upload path."),
  { NULL },
};

static void register_hooks(apr_pool_t *p)
{
  ap_hook_handler(direct_upload_handler, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_fixups(dump_headers, NULL, NULL, APR_HOOK_MIDDLE);
  //ap_hook_access_checker(direct_upload_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA direct_upload_module = {
  STANDARD20_MODULE_STUFF, 
  config_create, /* create per-dir    config structures */
  NULL,          /* merge  per-dir    config structures */
  NULL,          /* create per-server config structures */
  NULL,          /* merge  per-server config structures */
  config_cmds,   /* table of config file commands       */
  register_hooks /* register hooks                      */
};
