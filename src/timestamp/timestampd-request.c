/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "crypto-util.h"
#include "json-util.h"
#include "log.h"
#include "macro.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "timestampd.h"
#include "timestampd-request.h"
#include "timestampd-request-internal.h"
#include "timestampd-tsp.h"

static TimestampRequest* timestamp_request_free(TimestampRequest *req) {
        if (!req)
                return NULL;

        /* Normally all of this already happened in timestamp_request_detach(), but a request that failed
         * before it was ever registered is freed directly. */
        if (req->manager)
                set_remove(req->manager->requests, req);

        assert(req->vtable);
        if (req->vtable->done)
                req->vtable->done(req);

        sd_event_source_unref(req->timeout_event_source);

        sd_varlink_unref(req->link);

        free(req->authority);
        free(req->request_der);

        return mfree(req);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(TimestampRequest, timestamp_request, timestamp_request_free);

static void timestamp_request_detach(TimestampRequest *req) {
        assert(req);

        if (!req->manager) /* Already detached. */
                return;

        assert(req->vtable);
        if (req->vtable->done)
                req->vtable->done(req);

        req->timeout_event_source = sd_event_source_unref(req->timeout_event_source);

        set_remove(req->manager->requests, req);
        req->manager = NULL;

        timestamp_request_unref(req);
}

/* Cancels all in-flight requests. Called during manager shutdown. */
void manager_cancel_all_requests(Manager *m) {
        TimestampRequest *req;

        assert(m);

        while ((req = set_first(m->requests)))
                timestamp_request_detach(req);
}

static void request_reply_token(TimestampRequest *req, const char *pem) {
        int r;

        assert(req);
        assert(pem);

        r = sd_varlink_replybo(req->link, SD_JSON_BUILD_PAIR_STRING("token", pem));
        if (r < 0)
                log_error_errno(r, "Failed to send Varlink reply, ignoring: %m");

        timestamp_request_detach(req);
}

static void request_reply_error(TimestampRequest *req, const char *error_id, const char *reason) {
        assert(req);
        assert(error_id);

        (void) sd_varlink_errorbo(req->link, error_id, JSON_BUILD_PAIR_STRING_NON_EMPTY("reason", reason));

        timestamp_request_detach(req);
}

static void request_reply_errno(TimestampRequest *req, int error) {
        assert(req);
        assert(error < 0);

        (void) sd_varlink_error_errno(req->link, error);

        timestamp_request_detach(req);
}

void timestamp_request_fail_errno(TimestampRequest *req, int error) {
        request_reply_errno(req, error);
}

static int failure_info_to_json(const TspResponse *resp, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(resp);
        assert(ret);

        FOREACH_ARRAY(bit, resp->failure_info, resp->n_failure_info) {
                r = sd_json_variant_append_arrayb(&v, SD_JSON_BUILD_INTEGER(*bit));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static void request_reply_tsa_error(TimestampRequest *req, const TspResponse *resp) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *failure_info = NULL;
        int r;

        assert(req);
        assert(resp);

        r = failure_info_to_json(resp, &failure_info);
        if (r < 0)
                log_error_errno(r, "Failed to marshal failure info, ignoring: %m");

        (void) sd_varlink_errorbo(
                        req->link,
                        TIMESTAMP_ERROR("TimestampAuthorityError"),
                        SD_JSON_BUILD_PAIR_INTEGER("status", resp->status),
                        SD_JSON_BUILD_PAIR_CONDITION(!!resp->status_string, "statusString", SD_JSON_BUILD_STRING(resp->status_string)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!failure_info, "failureInfo", SD_JSON_BUILD_VARIANT(failure_info)));

        timestamp_request_detach(req);
}

static const char* const timestamp_failure_error_id[_TIMESTAMP_FAILURE_MAX] = {
        [TIMESTAMP_FAILURE_INVALID_AUTHORITY]  = TIMESTAMP_ERROR("InvalidAuthority"),
        [TIMESTAMP_FAILURE_NAME_RESOLUTION]    = TIMESTAMP_ERROR("NameResolutionFailure"),
        [TIMESTAMP_FAILURE_CONNECTION]         = TIMESTAMP_ERROR("ConnectionFailure"),
        [TIMESTAMP_FAILURE_TIMEOUT]            = TIMESTAMP_ERROR("TimedOut"),
        [TIMESTAMP_FAILURE_INVALID_RESPONSE]   = TIMESTAMP_ERROR("InvalidResponse"),
};

/* Complete a request, returning the result back to the client. On success, pass _TIMESTAMP_FAILURE_INVALID
 * and the DER-encoded TimeStampResp the authority sent. This takes care of freeing the request object, so
 * the caller must not touch it after this returns. */
void timestamp_request_complete(
                TimestampRequest *req,
                TimestampFailure failure,
                const char *reason,
                const void *der,
                size_t der_size) {

        _cleanup_(timestamp_request_unrefp) _unused_ TimestampRequest *ref = timestamp_request_ref(req);
        _cleanup_(tsp_response_done) TspResponse resp = {};
        int r;

        assert(req);

        if (failure >= 0) {
                assert(failure < _TIMESTAMP_FAILURE_MAX);

                return request_reply_error(req,
                                           timestamp_failure_error_id[failure],
                                           failure == TIMESTAMP_FAILURE_TIMEOUT ? NULL : reason);
        }

        assert(der);

        r = tsp_parse_response(der, der_size, req->request_der, req->request_der_size, &resp);
        if (r < 0)
                return request_reply_error(req, TIMESTAMP_ERROR("InvalidResponse"),
                                           "Could not parse the response returned by the authority");

        if (!IN_SET(resp.status, TS_STATUS_GRANTED, TS_STATUS_GRANTED_WITH_MODS))
                return request_reply_tsa_error(req, &resp);

        assert(resp.token_pem); /* tsp_parse_response() guarantees this if the status is granted. */

        return request_reply_token(req, resp.token_pem);
}

static int request_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        TimestampRequest *req = ASSERT_PTR(userdata);
        _cleanup_(timestamp_request_unrefp) _unused_ TimestampRequest *ref = timestamp_request_ref(req);

        timestamp_request_fail(req, TIMESTAMP_FAILURE_TIMEOUT, /* reason= */ NULL);
        return 0;
}

static const TransportVTable * const transport_vtables[] = {
#if HAVE_LIBCURL
        &http_vtable,
#endif
        &tcp_vtable,
};

static const TransportVTable* transport_vtable_for_authority(const char *authority) {
        if (!authority)
                return NULL;

        FOREACH_ELEMENT(v, transport_vtables)
                STRV_FOREACH(scheme, (*v)->schemes)
                        if (startswith(authority, *scheme))
                                return *v;

        return NULL;
}

/* Checks that the authority URL is one that can actually be used. Returns 0 if so,
 * -EOPNOTSUPP if no transport handles its scheme, or -EINVAL if the URL is malformed. */
int timestamp_authority_validate(const char *authority) {
        const TransportVTable *vtable = transport_vtable_for_authority(authority);
        if (!vtable)
                return -EOPNOTSUPP;

        if (vtable->validate && !vtable->validate(authority))
                return -EINVAL;

        return 0;
}

/* Start an asynchronous RFC 3161 request against `authority`, taking ownership of the DER-encoded request
 * buffer `request_der`. The eventual Varlink reply, whether success or error, is sent on `link`.
 * Returns 0 once the request is under way, or a negative errno if it could not be started at all (in
 * which case the caller replies). */
int timestamp_request_start(
                Manager *m,
                sd_varlink *link,
                const char *authority,
                void *request_der,
                size_t request_der_size) {

        int r;

        assert(m);
        assert(link);
        assert(authority);
        assert(request_der);

        const TransportVTable *vtable = transport_vtable_for_authority(authority);
        if (!vtable) {
                free(request_der);
                return -EOPNOTSUPP;
        }

        assert(vtable->object_size >= sizeof(TimestampRequest));
        assert(vtable->start);

        /* malloc0 here so that the transport-specific fields are zeroed. */
        _cleanup_(timestamp_request_unrefp) TimestampRequest *req = malloc0(vtable->object_size);
        if (!req) {
                free(request_der); /* We always consume this. */
                return log_oom();
        }

        *req = (TimestampRequest) {
                .n_ref = 1,
                .vtable = vtable,
                .manager = m,
                .link = sd_varlink_ref(link),
                .request_der = TAKE_PTR(request_der),
                .request_der_size = request_der_size,
        };

        if (vtable->init)
                vtable->init(req);

        req->authority = strdup(authority);
        if (!req->authority)
                return log_oom();

        r = set_ensure_put(&m->requests, /* hash_ops= */ NULL, req);
        if (r < 0)
                return r;

        if (m->connection_timeout_usec != USEC_INFINITY) {
                r = sd_event_add_time_relative(
                                m->event, &req->timeout_event_source, CLOCK_MONOTONIC,
                                m->connection_timeout_usec, /* accuracy= */ 0, request_timeout, req);
                if (r < 0)
                        return r;
        }

        r = vtable->start(req);
        if (r < 0) {
                log_error_errno(r, "Failed to start %s request against '%s': %m", vtable->name, authority);
                timestamp_request_fail_errno(TAKE_PTR(req), r);
                return 0;
        }

        TAKE_PTR(req);
        return 0;
}
