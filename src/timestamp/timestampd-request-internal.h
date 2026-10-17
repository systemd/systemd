/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "timestampd.h"

/* Sanity limit: RFC 3161 tokens are a few kilobytes at most. */
#define RESPONSE_MAX (128U*U64_KB)

typedef struct TransportVTable TransportVTable;

/* The transport independent part of a request. Each transport defines its own request object
 * which embeds this as its first member, see TimestampRequestHTTP and TimestampRequestTCP. */
struct TimestampRequest {
        unsigned n_ref;

        const TransportVTable *vtable;

        /* Set as long as the request is registered with the manager, i.e. until it is completed. */
        Manager *manager;
        sd_varlink *link;

        char *authority;

        void *request_der;
        size_t request_der_size;

        sd_event_source *timeout_event_source;
};

struct TransportVTable {
        /* Human readable name of this transport. */
        const char *name;

        /* The authority URL schemes this transport is responsible for, NULL terminated. */
        const char * const *schemes;

        /* How much memory a request object of this transport needs. */
        size_t object_size;

        /* Initializes the transport specific fields. Called on zero-initialized memory. */
        void (*init)(TimestampRequest *req);

        /* Releases all transport specific resources. Must be idempotent. */
        void (*done)(TimestampRequest *req);

        /* Returns true if the URL is valid for this transport. */
        bool (*validate)(const char *authority);

        /* Start the request. The reply is sent asynchronously once the authority answers.
         * Returns a negative errno if the request could not be started at all. */
        int (*start)(TimestampRequest *req);
};

#define REQUEST(req) (&ASSERT_PTR(req)->base)

DECLARE_TRIVIAL_REF_UNREF_FUNC(TimestampRequest, timestamp_request);
DEFINE_TRIVIAL_CLEANUP_FUNC(TimestampRequest*, timestamp_request_unref);

#if HAVE_LIBCURL
extern const TransportVTable http_vtable;
#endif
extern const TransportVTable tcp_vtable;

/* The kinds of failure a transport can report. Each maps to one Varlink error, see
 * timestamp_failure_error_id[]. */
typedef enum TimestampFailure {
        TIMESTAMP_FAILURE_INVALID_AUTHORITY,   /* the authority URL is not usable */
        TIMESTAMP_FAILURE_NAME_RESOLUTION,     /* the authority's host name did not resolve */
        TIMESTAMP_FAILURE_CONNECTION,          /* could not communicate with authority */
        TIMESTAMP_FAILURE_TIMEOUT,             /* the authority did not answer in time */
        TIMESTAMP_FAILURE_INVALID_RESPONSE,    /* the authority returned an invalid response */
        _TIMESTAMP_FAILURE_MAX,
        _TIMESTAMP_FAILURE_INVALID = -EINVAL,
} TimestampFailure;

/* Hands a result back to the client and unregisters the request. Pass _TIMESTAMP_FAILURE_INVALID together
 * with the DER the authority sent to report success. */
void timestamp_request_complete(
                TimestampRequest *req,
                TimestampFailure failure,
                const char *reason,
                const void *der,
                size_t der_size);

/* Reports a failure of the connection or authority for the request, with an optional reason. */
static inline void timestamp_request_fail(TimestampRequest *req, TimestampFailure failure, const char *reason) {
        assert(failure >= 0 && failure < _TIMESTAMP_FAILURE_MAX);

        timestamp_request_complete(req, failure, reason, /* der= */ NULL, /* der_size= */ 0);
}

/* Reports a failure of ours. */
void timestamp_request_fail_errno(TimestampRequest *req, int error);

static inline void timestamp_request_succeed(TimestampRequest *req, const void *der, size_t der_size) {
        timestamp_request_complete(req, _TIMESTAMP_FAILURE_INVALID, /* reason= */ NULL, der, der_size);
}
