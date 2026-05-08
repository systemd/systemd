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

typedef int (*curl_finished_t)(CurlSlot *slot, CURL *curl, CURLcode code, void *userdata);

int curl_glue_new(CurlGlue **glue, sd_event *event);
CurlGlue* curl_glue_ref(CurlGlue *glue);
CurlGlue* curl_glue_unref(CurlGlue *glue);

DEFINE_TRIVIAL_CLEANUP_FUNC(CurlGlue*, curl_glue_unref);

/* Build a CURL easy handle with sane defaults. The caller configures any
 * additional options (headers, write callbacks, …) before handing it off to
 * curl_glue_perform_async(). */
int curl_glue_make(CURL **ret, const char *url);

/* Hand a configured CURL easy handle off to the multi for execution. The slot
 * takes ownership of the easy handle: once the slot is released (the callback
 * has fired, the caller has dropped its last ref, or the glue is being freed),
 * the handle is removed from the multi and freed.
 *
 * If ret_slot is NULL the slot is allocated as floating: the glue keeps it
 * alive until the callback fires or the glue is torn down. Otherwise a
 * reference is returned to the caller; releasing that reference cancels the
 * call. */
int curl_glue_perform_async(
                CurlGlue *g,
                CURL *easy,
                curl_finished_t cb,
                void *userdata,
                CurlSlot **ret_slot);

CURL* curl_slot_get_easy(CurlSlot *slot);
CurlGlue* curl_slot_get_glue(CurlSlot *slot);

CurlSlot* curl_slot_ref(CurlSlot *slot);
CurlSlot* curl_slot_unref(CurlSlot *slot);

DEFINE_TRIVIAL_CLEANUP_FUNC(CurlSlot*, curl_slot_unref);

struct curl_slist *curl_slist_new(const char *first, ...) _sentinel_;
int curl_header_strdup(const void *contents, size_t sz, const char *field, char **value);
int curl_parse_http_time(const char *t, usec_t *ret);
int curl_append_to_header(struct curl_slist **list, char **headers);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(CURL*, sym_curl_easy_cleanup, curl_easy_cleanupp, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(struct curl_slist*, sym_curl_slist_free_all, curl_slist_free_allp, NULL);

#endif

int dlopen_curl(int log_level);
