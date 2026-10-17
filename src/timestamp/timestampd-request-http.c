/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "curl-util.h"
#include "log.h"
#include "timestampd.h"
#include "timestampd-request-internal.h"
#include "web-util.h"

typedef struct TimestampRequestHTTP {
        TimestampRequest base;

        CurlSlot *curl_slot;
        struct curl_slist *request_headers;
        uint8_t *response;
        size_t response_size;

        /* Why the write callback aborted the transfer, if it did. */
        int write_errno;
        bool response_too_large;
} TimestampRequestHTTP;

static TimestampRequestHTTP* HTTP(TimestampRequest *req) {
        assert(req);
        assert(req->vtable == &http_vtable);

        return (TimestampRequestHTTP*) req;
}

static void http_done(TimestampRequest *req) {
        TimestampRequestHTTP *http = HTTP(req);

        http->curl_slot = curl_slot_unref(http->curl_slot);

        if (http->request_headers) {
                sym_curl_slist_free_all(http->request_headers);
                http->request_headers = NULL;
        }

        http->response = mfree(http->response);
        http->response_size = 0;
}

static size_t http_write_callback(void *contents, size_t size, size_t nmemb, void *userdata) {
        TimestampRequestHTTP *http = ASSERT_PTR(userdata);
        size_t sz = size * nmemb;

        if (http->response_size + sz > RESPONSE_MAX) {
                log_warning("Timestamp response from authority too large, refusing.");
                http->response_too_large = true;
                return 0; /* abort the transfer */
        }

        if (!GREEDY_REALLOC(http->response, http->response_size + sz)) {
                http->write_errno = log_oom();
                return 0;
        }

        memcpy(http->response + http->response_size, contents, sz);
        http->response_size += sz;
        return sz;
}

/* Curl collapses many distinct failures into few codes, so this is necessarily coarse: anything we cannot
 * place is reported as a connection failure, which is what most CURLE_* codes in fact are. */
static TimestampFailure http_failure_from_curl(CURLcode code) {
        switch (code) {

        case CURLE_COULDNT_RESOLVE_HOST:
        case CURLE_COULDNT_RESOLVE_PROXY:
                return TIMESTAMP_FAILURE_NAME_RESOLUTION;

        case CURLE_OPERATION_TIMEDOUT:
                return TIMESTAMP_FAILURE_TIMEOUT;

        case CURLE_URL_MALFORMAT:
        case CURLE_UNSUPPORTED_PROTOCOL:
                return TIMESTAMP_FAILURE_INVALID_AUTHORITY;

        case CURLE_GOT_NOTHING:
                return TIMESTAMP_FAILURE_INVALID_RESPONSE;

        default:
                return TIMESTAMP_FAILURE_CONNECTION;
        }
}

static int http_on_finished(CurlSlot *slot, CURL *curl, CURLcode result, void *userdata) {
        TimestampRequestHTTP *http = ASSERT_PTR(userdata);
        _cleanup_(timestamp_request_unrefp) _unused_ TimestampRequest *ref = timestamp_request_ref(REQUEST(http));
        long status;

        http->curl_slot = curl_slot_unref(http->curl_slot);

        if (result != CURLE_OK) {
                if (http->write_errno != 0)
                        timestamp_request_fail_errno(REQUEST(http), http->write_errno);
                else if (http->response_too_large)
                        timestamp_request_fail(REQUEST(http), TIMESTAMP_FAILURE_INVALID_RESPONSE,
                                               "Response from authority too large");
                else
                        timestamp_request_fail(REQUEST(http), http_failure_from_curl(result),
                                               sym_curl_easy_strerror(result));
                return 0;
        }

        if (sym_curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK) {
                timestamp_request_fail(REQUEST(http), TIMESTAMP_FAILURE_INVALID_RESPONSE,
                                       "Could not determine HTTP status");
                return 0;
        }

        if (status != 200) {
                timestamp_request_fail(REQUEST(http), TIMESTAMP_FAILURE_INVALID_RESPONSE,
                                       "Authority returned a non-200 HTTP status");
                return 0;
        }

        timestamp_request_succeed(REQUEST(http), http->response, http->response_size);
        return 0;
}

static int manager_ensure_curl(Manager *m) {
        int r;

        assert(m);

        if (m->curl_glue)
                return 0;

        r = curl_glue_new(&m->curl_glue, m->event);
        if (r < 0)
                return r;

        return 0;
}

static int http_start(TimestampRequest *req) {
        TimestampRequestHTTP *http = HTTP(req);
        Manager *m = ASSERT_PTR(req->manager);
        _cleanup_(curl_easy_cleanupp) CURL *easy = NULL;
        int r;

        r = dlopen_curl(LOG_DEBUG);
        if (r < 0)
                return r;

        r = manager_ensure_curl(m);
        if (r < 0)
                return r;

        http->request_headers = curl_slist_new(
                        "Content-Type: application/timestamp-query",
                        "Accept: application/timestamp-reply",
                        NULL);
        if (!http->request_headers)
                return log_oom();

        r = curl_glue_make(&easy, req->authority);
        if (r < 0)
                return r;

        if (!easy_setopt(easy, LOG_ERR, CURLOPT_POST, 1L) ||
            !easy_setopt(easy, LOG_ERR, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t) req->request_der_size) ||
            !easy_setopt(easy, LOG_ERR, CURLOPT_POSTFIELDS, req->request_der) ||
            !easy_setopt(easy, LOG_ERR, CURLOPT_HTTPHEADER, http->request_headers) ||
            !easy_setopt(easy, LOG_ERR, CURLOPT_WRITEFUNCTION, http_write_callback) ||
            !easy_setopt(easy, LOG_ERR, CURLOPT_WRITEDATA, http))
                return log_error_errno(r, "Failed to set curl request options: %m");

        r = curl_glue_perform_async(m->curl_glue, easy, http_on_finished, http, &http->curl_slot);
        if (r < 0)
                return log_error_errno(r, "Failed to start curl request: %m");

        TAKE_PTR(easy); /* the slot took ownership */
        return 0;
}

static const char* const http_schemes[] = {
        "http://",
        "https://",
        NULL,
};

const TransportVTable http_vtable = {
        .name = "HTTP",
        .schemes = http_schemes,
        .object_size = sizeof(TimestampRequestHTTP),
        .validate = http_url_is_valid,
        .done = http_done,
        .start = http_start,
};
