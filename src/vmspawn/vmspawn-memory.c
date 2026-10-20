/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "format-util.h"
#include "log.h"
#include "qmp-client.h"
#include "string-util.h"
#include "vmspawn-memory.h"
#include "vmspawn-qmp.h"

int vmspawn_memory_setup(VmspawnQmpBridge *bridge, uint64_t configured, bool balloon) {
        _cleanup_(vmspawn_memory_freep) VmspawnMemory *m = NULL;

        assert(bridge);
        assert(!bridge->memory);

        m = new(VmspawnMemory, 1);
        if (!m)
                return log_oom();

        *m = (VmspawnMemory) {
                .bridge = bridge,
                .configured = configured,
                .target = configured,
                .actual = balloon ? 0 : configured,
                .balloon = balloon,
        };

        bridge->memory = TAKE_PTR(m);
        return vmspawn_memory_refresh(bridge->memory);
}

VmspawnMemory* vmspawn_memory_free(VmspawnMemory *m) {
        if (!m)
                return NULL;

        return mfree(m);
}

static int memory_update_actual(VmspawnMemory *m, sd_json_variant *v) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "actual", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, 0, SD_JSON_MANDATORY },
                {}
        };
        uint64_t actual;
        int r;

        assert(m);

        r = sd_json_dispatch(v, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &actual);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse balloon size reported by QEMU, ignoring: %m");

        if (actual != m->actual)
                log_debug("Guest memory size is now %s (target %s).", FORMAT_BYTES(actual), FORMAT_BYTES(m->target));

        m->actual = actual;
        return 0;
}

static int on_query_balloon_complete(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        VmspawnMemory *m = ASSERT_PTR(userdata);

        assert(client);

        if (error < 0) {
                log_debug_errno(error, "query-balloon failed, ignoring: %s", strna(error_desc));
                return 0;
        }

        (void) memory_update_actual(m, result);
        return 0;
}

typedef struct SetTargetRequest {
        VmspawnMemory *m;
        sd_varlink *link;       /* ref'd, may be NULL */
        uint64_t bytes;
} SetTargetRequest;

static SetTargetRequest* set_target_request_free(SetTargetRequest *req) {
        if (!req)
                return NULL;

        sd_varlink_unref(req->link);
        return mfree(req);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(SetTargetRequest*, set_target_request_free);

static int on_balloon_complete(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        _cleanup_(set_target_request_freep) SetTargetRequest *req = ASSERT_PTR(userdata);

        assert(client);

        if (error < 0) {
                if (!req->link)
                        return log_debug_errno(error, "balloon command failed: %s", strna(error_desc));

                return vmspawn_qmp_reply_error(req->link, error_desc, error);
        }

        req->m->target = req->bytes;
        log_debug("Requested guest memory size %s.", FORMAT_BYTES(req->bytes));

        if (!req->link)
                return 0;

        return sd_varlink_reply(req->link, NULL);
}

int vmspawn_memory_refresh(VmspawnMemory *m) {
        assert(m);
        assert(m->bridge);

        if (!m->balloon)
                return 0;

        return qmp_client_invoke(m->bridge->qmp,
                                 /* ret_slot= */ NULL,
                                 "query-balloon",
                                 /* args= */ NULL,
                                 on_query_balloon_complete,
                                 m);
}

int vmspawn_memory_set_target(VmspawnMemory *m, sd_varlink *link, uint64_t bytes) {
        _cleanup_(set_target_request_freep) SetTargetRequest *req = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        int r;

        assert(m);
        assert(m->bridge);

        if (!m->balloon)
                return -EOPNOTSUPP;
        if (bytes == 0 || bytes > m->configured)
                return -ERANGE;

        r = sd_json_buildo(&args, SD_JSON_BUILD_PAIR_UNSIGNED("value", bytes));
        if (r < 0)
                return r;

        req = new(SetTargetRequest, 1);
        if (!req)
                return -ENOMEM;

        *req = (SetTargetRequest) {
                .m = m,
                .link = sd_varlink_ref(link),
                .bytes = bytes,
        };

        r = qmp_client_invoke(m->bridge->qmp,
                              /* ret_slot= */ NULL,
                              "balloon",
                              QMP_CLIENT_ARGS(args),
                              on_balloon_complete,
                              req);
        if (r < 0)
                return r;

        TAKE_PTR(req);
        return 0;
}

int vmspawn_memory_dispatch_event(VmspawnMemory *m, const char *event, sd_json_variant *data) {
        assert(m);
        assert(event);

        if (!streq(event, "BALLOON_CHANGE"))
                return 0;

        if (!data)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "BALLOON_CHANGE event without payload, ignoring.");

        (void) memory_update_actual(m, data);
        return 1;
}

int vmspawn_memory_build_json(VmspawnMemory *m, sd_json_variant **ret) {
        assert(m);
        assert(ret);

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_UNSIGNED("configuredBytes", m->configured),
                        SD_JSON_BUILD_PAIR_UNSIGNED("targetBytes", m->target),
                        SD_JSON_BUILD_PAIR_CONDITION(m->actual > 0, "actualBytes", SD_JSON_BUILD_UNSIGNED(m->actual)));
}
