/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-device.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "blockdev-list.h"
#include "device-util.h"
#include "json-util.h"
#include "repart-list-candidate-devices.h"

typedef struct ListCandidateDevicesContext {
        sd_varlink *link;                  /* Owned ref; freed in list_candidate_devices_context_free(). */
        sd_device_monitor *monitor;
        BlockDevListFlags flags;
        dev_t root_devno, whole_root_devno;
} ListCandidateDevicesContext;

static ListCandidateDevicesContext* list_candidate_devices_context_free(ListCandidateDevicesContext *c) {
        if (!c)
                return NULL;

        sd_device_monitor_unref(c->monitor);
        sd_varlink_unref(c->link);
        return mfree(c);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(ListCandidateDevicesContext*, list_candidate_devices_context_free);

static void vl_on_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        assert(server);
        assert(link);

        list_candidate_devices_context_free(sd_varlink_set_userdata(link, NULL));
}

static int list_candidate_devices_send_remove(sd_varlink *link, sd_device *dev) {
        int r;

        assert(link);
        assert(dev);

        const char *node;
        r = sd_device_get_devname(dev, &node);
        if (r < 0) {
                log_device_debug_errno(dev, r, "Failed to acquire device node of removed block device, ignoring: %m");
                return 0;
        }

        return sd_varlink_notifybo(link,
                        SD_JSON_BUILD_PAIR("action", JSON_BUILD_CONST_STRING("remove")),
                        SD_JSON_BUILD_PAIR_STRING("node", node));
}

static int list_candidate_devices_send_add(sd_varlink *link, const BlockDevice *d, bool with_action) {
        int r;

        assert(link);
        assert(d);

        /* In subscribe mode we tag every reply with action=add so the discriminator is meaningful;
         * in plain enumeration mode we omit it (older clients don't know the field). */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        r = sd_json_buildo(
                        &v,
                        SD_JSON_BUILD_PAIR_CONDITION(with_action, "action", JSON_BUILD_CONST_STRING("add")),
                        SD_JSON_BUILD_PAIR_STRING("node", d->node),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("symlinks", d->symlinks),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("diskseq", d->diskseq, UINT64_MAX),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("sizeBytes", d->size, UINT64_MAX),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("model", d->model),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("vendor", d->vendor),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("subsystem", d->subsystem));
        if (r < 0)
                return r;

        /* Subscribe mode sets no sentinel, so a final reply would terminate the streaming call after
         * the first device; use intermediate notify messages to keep it open. Plain enumeration relies
         * on the sentinel mechanism, which buffers and chains replies. */
        return with_action ? sd_varlink_notify(link, v) : sd_varlink_reply(link, v);
}

static int list_candidate_devices_on_uevent(sd_device_monitor *monitor, sd_device *dev, void *userdata) {
        ListCandidateDevicesContext *c = ASSERT_PTR(userdata);
        int r;

        assert(dev);

        sd_device_action_t action;
        r = sd_device_get_action(dev, &action);
        if (r < 0) {
                log_device_debug_errno(dev, r, "Failed to acquire uevent action of block device, ignoring: %m");
                return 0;
        }

        if (action == SD_DEVICE_REMOVE)
                (void) list_candidate_devices_send_remove(c->link, dev);
        else {
                /* All non-REMOVE actions are treated as "device exists afterwards". Re-run the full
                 * filter set; the tri-state distinguishes "ignore entirely" (static-filtered) from
                 * "client should treat this as a removal" (dynamic-filtered, e.g. size became 0 or
                 * read-only became 1). */
                _cleanup_(block_device_done) BlockDevice d = BLOCK_DEVICE_NULL;
                r = blockdev_list_one(dev, c->flags, c->root_devno, c->whole_root_devno, &d);
                if (r < 0)
                        return r;

                switch (r) {
                case BLOCKDEV_LIST_MATCH_NO:
                case BLOCKDEV_LIST_MATCH_SKIPPED:
                        break;

                case BLOCKDEV_LIST_MATCH_FILTERED:
                        (void) list_candidate_devices_send_remove(c->link, dev);
                        break;

                case BLOCKDEV_LIST_MATCH_YES:
                        (void) list_candidate_devices_send_add(c->link, &d, /* with_action= */ true);
                        break;

                default:
                        assert_not_reached();
                }
        }

        /* Push out any notifications we just queued so the client doesn't have to wait for the next
         * event-loop tick to receive them. */
        (void) sd_varlink_flush(c->link);
        return 0;
}

int vl_method_list_candidate_devices(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        struct {
                bool ignore_root;
                bool ignore_empty;
                bool subscribe;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "ignoreRoot",  SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, voffsetof(p, ignore_root),  0 },
                { "ignoreEmpty", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, voffsetof(p, ignore_empty), 0 },
                { "subscribe",   SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, voffsetof(p, subscribe),    0 },
                {}
        };

        int r;

        assert(link);
        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE));

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        const BlockDevListFlags listflags =
                BLOCKDEV_LIST_SHOW_SYMLINKS|
                BLOCKDEV_LIST_REQUIRE_PARTITION_SCANNING|
                BLOCKDEV_LIST_IGNORE_ZRAM|
                BLOCKDEV_LIST_METADATA|
                BLOCKDEV_LIST_IGNORE_READ_ONLY|
                (p.ignore_empty ? BLOCKDEV_LIST_IGNORE_EMPTY : 0)|
                (p.ignore_root ? BLOCKDEV_LIST_IGNORE_ROOT : 0);

        _cleanup_(list_candidate_devices_context_freep) ListCandidateDevicesContext *c = NULL;

        if (p.subscribe) {
                /* Start the monitor *before* the initial enumeration so we don't lose events that fire
                 * during the enumeration window. Duplicate add events for the same device are
                 * legitimate and documented; clients upsert by identifier. */

                c = new(ListCandidateDevicesContext, 1);
                if (!c)
                        return -ENOMEM;

                *c = (ListCandidateDevicesContext) {
                        .flags = listflags,
                };

                (void) blockdev_list_get_root_devnos(listflags, &c->root_devno, &c->whole_root_devno);

                r = sd_device_monitor_new(&c->monitor);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate block device monitor: %m");

                (void) sd_device_monitor_set_description(c->monitor, "repart-candidate-devices");

                r = sd_device_monitor_filter_add_match_subsystem_devtype(c->monitor, "block", /* devtype= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to configure block device monitor filter: %m");

                r = sd_device_monitor_attach_event(c->monitor, sd_varlink_get_event(link));
                if (r < 0)
                        return log_error_errno(r, "Failed to attach block device monitor to event loop: %m");

                r = sd_device_monitor_start(c->monitor, list_candidate_devices_on_uevent, c);
                if (r < 0)
                        return log_error_errno(r, "Failed to start block device monitor: %m");
        } else {
                /* Non-subscribing: the sentinel fires if no replies were sent. */
                r = sd_varlink_set_sentinel(link, "io.systemd.Repart.NoCandidateDevices");
                if (r < 0)
                        return r;
        }

        BlockDevice *l = NULL;
        size_t n = 0;
        CLEANUP_ARRAY(l, n, block_device_array_free);

        r = blockdev_list(listflags, &l, &n);
        if (r < 0)
                return r;

        FOREACH_ARRAY(d, l, n) {
                r = list_candidate_devices_send_add(link, d, /* with_action= */ p.subscribe);
                if (r < 0)
                        return r;
        }

        if (!p.subscribe)
                return 0;

        /* Subscribing: a single "ready" sentinel marks the boundary between initial enumeration and
         * live events. The call stays open after we return; live events flow through
         * list_candidate_devices_on_uevent(). */
        r = sd_varlink_notifybo(link, SD_JSON_BUILD_PAIR("action", JSON_BUILD_CONST_STRING("ready")));
        if (r < 0)
                return r;

        /* Install the on-disconnect handler lazily, only once we actually have a subscription to clean
         * up. The call is idempotent for the same callback. */
        r = sd_varlink_server_bind_disconnect(sd_varlink_get_server(link), vl_on_disconnect);
        if (r < 0)
                return r;

        /* Hand ownership of the context to the link; vl_on_disconnect() frees it. */
        c->link = sd_varlink_ref(link);
        sd_varlink_set_userdata(link, TAKE_PTR(c));

        return 0;
}
