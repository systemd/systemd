/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

#if HAVE_LIBCURL
#include <curl/curl.h>            /* IWYU pragma: export */

#include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(curl_easy_cleanup);
extern DLSYM_PROTOTYPE(curl_easy_getinfo);
extern DLSYM_PROTOTYPE(curl_easy_init);
extern DLSYM_PROTOTYPE(curl_easy_perform);
extern DLSYM_PROTOTYPE(curl_easy_setopt);
extern DLSYM_PROTOTYPE(curl_easy_strerror);
#if LIBCURL_VERSION_NUM >= 0x075300
extern DLSYM_PROTOTYPE(curl_easy_header);
#endif
extern DLSYM_PROTOTYPE(curl_getdate);
extern DLSYM_PROTOTYPE(curl_slist_append);
extern DLSYM_PROTOTYPE(curl_slist_free_all);

#define easy_setopt(curl, log_level, opt, value) ({                         \
        CURLcode code = sym_curl_easy_setopt(ASSERT_PTR(curl), opt, value); \
        if (code)                                                           \
                log_full(log_level,                                         \
                         "curl_easy_setopt %s failed: %s",                  \
                         #opt, sym_curl_easy_strerror(code));               \
        code == CURLE_OK;                                                   \
})

typedef struct CurlGlue CurlGlue;

typedef struct CurlGlue {
        sd_event *event;
        CURLM *curl;
        sd_event_source *timer;
        Hashmap *ios;
        sd_event_source *defer;

        void (*on_finished)(CurlGlue *g, CURL *curl, CURLcode code);
        void *userdata;
} CurlGlue;

int curl_glue_new(CurlGlue **glue, sd_event *event);
CurlGlue* curl_glue_unref(CurlGlue *glue);

DEFINE_TRIVIAL_CLEANUP_FUNC(CurlGlue*, curl_glue_unref);

int curl_glue_make(CURL **ret, const char *url, void *userdata);
int curl_glue_add(CurlGlue *g, CURL *c);
void curl_glue_remove_and_free(CurlGlue *g, CURL *c);

struct curl_slist *curl_slist_new(const char *first, ...) _sentinel_;
int curl_header_strdup(const void *contents, size_t sz, const char *field, char **value);
int curl_parse_http_time(const char *t, usec_t *ret);
int curl_append_to_header(struct curl_slist **list, char **headers);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(CURL*, sym_curl_easy_cleanup, curl_easy_cleanupp, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(struct curl_slist*, sym_curl_slist_free_all, curl_slist_free_allp, NULL);

#endif

int dlopen_curl(int log_level);
