/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

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
