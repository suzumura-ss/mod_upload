/* 
 * Copyright 2010 Toshiyuki Suzumura
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_file_info.h"
#include "apr_file_io.h"
#include "ap_mpm.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <curl/curl.h> 

#define UNSET (-1)
#define DISABLED (0)
#define ENABLED (1)
 
#define UPLOAD "X-Upload-File"
static const char VERSION[] = "mod_upload/0.3";
static const char X_UPLOAD[] = UPLOAD;
static const char X_LOCATION[] = "X-Upload-From";
static const char X_DIRCTRL[] = "X-Upload-DirCtrl";
 
module AP_MODULE_DECLARE_DATA upload_module;
 
#define AP_LOG_DEBUG(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, rec, fmt, ##__VA_ARGS__)
#define AP_LOG_INFO(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, rec, "[upload] " fmt, ##__VA_ARGS__)
#define AP_LOG_WARN(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_WARNING,0, rec, "[upload] " fmt, ##__VA_ARGS__)
#define AP_LOG_ERR(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, rec, "[upload] " fmt, ##__VA_ARGS__)
#define AP_ERR_RESPONSE(rec, fmt, ...) \
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, rec, "[upload] " fmt, ##__VA_ARGS__); \
                ap_rprintf(rec, fmt "\n", ##__VA_ARGS__)
 
// Config store.
typedef struct {
  apr_pool_t* pool;
  int   enabled;
  char* url_base;
  char* dir_base;
} upload_conf;
 
 
// Callbacks context.
typedef struct {
  apr_status_t http_status;
  apr_status_t file_status;
  apr_file_t* file;
  apr_off_t   count;
} context;
 
 
//
// Main functions.
//

//
// Save to specified file from rec.
//
static apr_status_t save_to_file(request_rec* rec, const char* filename)
{
  apr_file_t* file = NULL;
  apr_status_t status, s_close;
  apr_off_t length = 0, count = 0;
  const char* hdr;

  // get content-length 
  hdr = apr_table_get(rec->headers_in, "Content-Length");
  length = (hdr)? apr_atoi64(hdr): LLONG_MAX;
  AP_LOG_DEBUG(rec, " Content-Length: %llu", length);

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
      AP_LOG_ERR(rec, "Close failed: %s : %s(%d)", filename, strerror(s_close), s_close);
      status = s_close;
    }
  }
  if(status!=APR_SUCCESS) {
    apr_file_remove(filename, rec->pool);
    AP_ERR_RESPONSE(rec, "Write failed: %s : %s(%d)", filename, strerror(status), status);
  } else {
    ap_rprintf(rec, "Saved: %s (%llu)\n", filename, count);
    AP_LOG_DEBUG(rec, "%llu bytes read.", count);
  }
  return status;
}



//
// Save to specified file from URL.
//

// CURL header callback.
static size_t upload_curl_header_callback(const void* ptr, size_t size, size_t nmemb, void* _context)
{
  context* ct = (context*)_context;

  if(strncmp(ptr, "HTTP/1.", sizeof("HTTP/1.")-1)==0) {
    int mv, status;
    if(sscanf(ptr, "HTTP/1.%d %d ", &mv, &status)==2 && status!=200) {
      ct->http_status = status;
    }
  }
  return nmemb;
}

// CURL write callback.
static size_t upload_curl_write_callback(const void* ptr, size_t size, size_t nmemb, void* _context)
{
  context* ct = (context*)_context;
  apr_size_t w = size*nmemb;

  ct->file_status = apr_file_write(ct->file, ptr, &w);
  ct->count += w;
  return nmemb;
}

// save to file from URL.
static apr_status_t save_to_file_from_url(request_rec* rec, const char* url, const char* filename)
{
  CURL* curl = curl_easy_init();
  CURLcode ret = 0;
  context ct = { .http_status=200, .file_status=APR_SUCCESS, .file=NULL, .count=0 };
  int threaded_mpm;

  // create file.
  ct.file_status = apr_file_open(&ct.file, filename, \
                      APR_WRITE|APR_CREATE|APR_TRUNCATE, APR_FPROT_OS_DEFAULT, rec->pool);
  if(ct.file_status!=APR_SUCCESS) goto FINALLY;

  // setup curl and request.
  ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded_mpm);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, threaded_mpm);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
  curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &ct);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, upload_curl_header_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ct);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, upload_curl_write_callback);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, apr_psprintf(rec->pool, "%s %s", VERSION, curl_version()));
  ap_should_client_block(rec);
  ret = curl_easy_perform(curl);
  curl_easy_cleanup(curl);
 
FINALLY:
  if(ct.file) {
    apr_status_t s_close = apr_file_close(ct.file);
    if(s_close!=APR_SUCCESS) {
      AP_LOG_ERR(rec, "Close failed: %s : %s(%d)", filename, strerror(s_close), s_close);
      ct.file_status = s_close;
    }
    if(ct.file_status!=APR_SUCCESS) {
      apr_file_remove(filename, rec->pool);
      AP_ERR_RESPONSE(rec, "Write failed: %s : %s(%d)", filename, strerror(ct.file_status), ct.file_status);
      ct.count = (apr_off_t)-1;
    }
  }
  if(ret!=0) {
    apr_file_remove(filename, rec->pool);
    AP_ERR_RESPONSE(rec, "libcurl failed: %s : %d", url, ret);
    ct.count = (apr_off_t)-1;
  }
  if(ct.http_status!=200) {
    apr_file_remove(filename, rec->pool);
    AP_ERR_RESPONSE(rec, "libcurl HTTP request failed: %s : %d", url, ct.http_status);
    rec->status = ct.http_status;
    ct.file_status = -1;
  } else if(ct.count!=(apr_off_t)-1) {
    ap_rprintf(rec, "Saved: %s (%llu)\n", filename, ct.count);
    AP_LOG_DEBUG(rec, "%llu bytes read.", ct.count);
  }
  return ct.file_status;
}


//
// directory control.
//

// normalize pathname
static apr_status_t normalize_pathname(request_rec* rec, char** path)
{
  char* newpath = "", *tok, *toklast;

  tok = apr_strtok(*path, "/", &toklast);
  while(tok!=NULL) {
    newpath = apr_pstrcat(rec->pool, newpath, "/", tok, NULL);
    tok = apr_strtok(NULL, "/", &toklast);
  }
  *path = newpath;
  return (*newpath=='\0')? APR_EBADPATH: APR_SUCCESS;
}
static char *split_pathname(char* path)
{
  char* tok = strrchr(path, '/');
  if(tok>path) {
    *(tok++) = '\0';
    return tok;
  }
  return ++tok;
}
static apr_status_t file_perms_set_recursive(request_rec*rec,\
                       const char* dirname, apr_fileperms_t dperms, apr_fileperms_t fperms)
{
  char* fname;
  apr_finfo_t finfo;
  apr_dir_t* dir;
  apr_status_t status = apr_dir_open(&dir, dirname, rec->pool);
  if(status!=APR_SUCCESS) return status;

  while((status=apr_dir_read(&finfo, APR_FINFO_NAME|APR_FINFO_TYPE, dir))==APR_SUCCESS) {
    if((strcmp(finfo.name, ".")==0) || (strcmp(finfo.name, "..")==0)) continue;
    fname = apr_pstrcat(rec->pool, dirname, "/", finfo.name, NULL);
    switch(finfo.filetype) {
    case APR_DIR:
      status = file_perms_set_recursive(rec, fname, dperms, fperms);
      if(status==APR_SUCCESS) {
        status = apr_file_perms_set(fname, dperms);
      }
      break;
    case APR_REG:
      status = apr_file_perms_set(fname, fperms);
      break;
    case APR_LNK:
    default:
      break;
    }
    if(status!=APR_SUCCESS) goto FINALLY;
  }
  status = APR_SUCCESS;

FINALLY:
  AP_LOG_DEBUG(rec, "file_perms_set_recursive: status=%d : %s", status, dirname);
  apr_dir_close(dir);
  return status;
}

// mvdir
static apr_status_t directory_mvdir(request_rec* rec,\
                      const char* from_dir, const char* _to_dir, apr_fileperms_t perm)
{
  upload_conf* conf = (upload_conf*)ap_get_module_config(rec->per_dir_config, &upload_module);
  const char* to_dir;
  char* fbase, *fname, *tbase, *tname;
  apr_status_t status;
  apr_finfo_t finfo;
  int u;

  if((from_dir==NULL) || (_to_dir==NULL)) return APR_EBADPATH;

  // build replaced 'to_dir'.
  u = strlen(conf->url_base);
  if(strncmp(_to_dir, conf->url_base, u)==0) {
    to_dir = apr_pstrcat(rec->pool, conf->dir_base, _to_dir + u, NULL);
  } else {
    return EACCES;
  }

  // check from_dir.
  if((status=apr_stat(&finfo, from_dir, APR_FINFO_TYPE, rec->pool))!=APR_SUCCESS) return status;
  if(finfo.filetype!=APR_DIR) return ENOTDIR;

  // build path names.
  fbase = apr_pstrdup(rec->pool, from_dir);
  if(normalize_pathname(rec, &fbase)!=APR_SUCCESS) return APR_EBADPATH;
  if(*(fname=split_pathname(fbase))=='\0') return APR_EBADPATH;
  
  tbase = apr_pstrdup(rec->pool, to_dir);
  if(normalize_pathname(rec, &tbase)!=APR_SUCCESS) return APR_EBADPATH;
  if(*(tname=split_pathname(tbase))=='\0') return APR_EBADPATH;

  // make t_base (base dir of to_dir).
  if((status=apr_dir_make_recursive(tbase, perm, rec->pool))!=APR_SUCCESS) {
    AP_ERR_RESPONSE(rec, "Mvdir: mkdir(base) failed: %s : %s(%d)", tbase, strerror(status), status);
    return status;
  }

  // move from_dir to to_dir.
  if((status=apr_file_rename(from_dir, to_dir, rec->pool))!=APR_SUCCESS) {
    AP_ERR_RESPONSE(rec, "Mvdir: move failed: %s=>%s : %s(%d)", from_dir, to_dir, strerror(status), status);
    return status;
  }

  // change permission.
  file_perms_set_recursive(rec, to_dir, perm| 0x111, perm& 0x666);

  return status;
}

// command exec
static apr_status_t director_control(request_rec* rec, const char* command, const char* dirname)
{
  apr_status_t status = APR_SUCCESS;
  apr_fileperms_t perm = APR_FPROT_OS_DEFAULT;
  char* toklast;
  char* str = apr_pstrdup(rec->pool, command);
  char* cmd = apr_strtok(str, "; ", &toklast);
  char* arg1 = apr_strtok(NULL, "; ", &toklast);
  char* arg2 = apr_strtok(NULL, "; ", &toklast);
  int t;

  AP_LOG_DEBUG(rec, "director_control: %s => %s, '%s', '%s'", command, cmd, arg1, arg2);
  if(strcasecmp(cmd, "mkdir")==0) {
    if((arg1!=NULL) && (t=apr_strtoi64(arg1, NULL, 16))!=0) perm = t;
    if((status=apr_dir_make_recursive(dirname, APR_FPROT_OS_DEFAULT, rec->pool))==APR_SUCCESS) {
      apr_file_perms_set(dirname, perm);
      rec->status = HTTP_CREATED;
    } else {
      AP_ERR_RESPONSE(rec, "Mkdir failed: %s : %s(%d)\n", dirname, strerror(status), status);
    }
  } else
  if(strcasecmp(cmd, "rmdir")==0) {
    if((status=apr_dir_remove(dirname, rec->pool))==APR_SUCCESS) {
      rec->status = HTTP_OK;
    } else {
      AP_ERR_RESPONSE(rec, "Rmdir failed: %s : %s(%d)\n", dirname, strerror(status), status);
    }
  } else
  if(strcasecmp(cmd, "mvdir")==0) {
    if((arg2!=NULL) && (t=apr_strtoi64(arg2, NULL, 16))!=0) perm = t;
    if((status=directory_mvdir(rec, dirname, arg1, perm))==APR_SUCCESS) {
      rec->status = HTTP_MOVED_PERMANENTLY;
      apr_table_set(rec->headers_out, "Location", arg1);
    } else {
      AP_ERR_RESPONSE(rec, "Mvdir failed: %s=>%s : %s(%d)", dirname, arg1, strerror(status), status);
    }
  } else {
    status = APR_BADARG;
    AP_ERR_RESPONSE(rec, "Invalid command: %s", command);
  }

  return status;
}

 
// Direct upload handler
static int direct_upload_handler(request_rec *rec)
{
  upload_conf* conf = (upload_conf*)ap_get_module_config(rec->per_dir_config, &upload_module);
  apr_status_t status, success_status;
  const char* x_from, *x_dirc;
 
  if(!conf || !conf->enabled) return DECLINED;
 
  AP_LOG_DEBUG(rec, "Incomming %s Enabled=%d %s", __FUNCTION__, conf->enabled, rec->method);
  AP_LOG_DEBUG(rec, "  url_base=%s dir_base=%s", conf->url_base, conf->dir_base);
  AP_LOG_DEBUG(rec, "  URI=%s", rec->uri);
  AP_LOG_DEBUG(rec, "  filename/path_info=%s%s", rec->filename, rec->path_info);
  if((rec->method_number & (M_POST|M_PUT))==0) return DECLINED; // Handled 'PUT', 'POST' only.
  if(strcasecmp(rec->handler, "upload")) return DECLINED;

  // setup content-type of response.
  rec->content_type = "plain/text";
 
  // get extent headers: 'X-Upload-From', 'X-Upload-DirCtrl'.
  x_from = apr_table_get(rec->headers_in, X_LOCATION);
  x_dirc = apr_table_get(rec->headers_in, X_DIRCTRL);
  AP_LOG_DEBUG(rec, "  %s=%s, %s=%s", X_LOCATION, x_from, X_DIRCTRL, x_dirc);

  // do request.
  if(x_dirc) {
    status = director_control(rec, x_dirc, rec->filename);
    success_status = rec->status;
  } else if(x_from) {
    status = save_to_file_from_url(rec, x_from, rec->filename);
    success_status = HTTP_CREATED;
  } else {
    status = save_to_file(rec, rec->filename);
    success_status = HTTP_CREATED;
  }

  switch(status) {
  case -1:
    break;  // path thru.
  case OK:
    rec->status = success_status;
    break;
  case EACCES:
    rec->status = HTTP_FORBIDDEN;
    break;
  case ENOENT:
    rec->status = HTTP_NOT_FOUND;
    break;
  case ENOTEMPTY:
    rec->status = HTTP_CONFLICT;
    break;
  case APR_EBADPATH:
  case EEXIST:
  case ENOTDIR:
  default:
    rec->status = HTTP_BAD_REQUEST;
    break;
  }
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
