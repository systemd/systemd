/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-future.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "log.h"
#include "string-util.h"
#include "varlink-future.h"

VarlinkReply* varlink_reply_free(VarlinkReply *reply) {
        if (!reply)
                return NULL;

        sd_json_variant_unref(reply->parameters);
        free(reply->error_id);
        return mfree(reply);
}

static void varlink_observe_channel_item_destroy(void *p) {
        varlink_reply_free(p);
}

static void varlink_observe_channel_slot_destroy(void *p) {
        sd_varlink *link = ASSERT_PTR(p);

        /* The reply callback gets the channel pointer without a reference. We unbind the callback before
         * the channel is freed. Otherwise a later reply on the link would call it with a freed channel. */
        (void) sd_varlink_bind_reply(link, NULL);
        (void) sd_varlink_set_userdata(link, NULL);
        sd_varlink_close_unref(link);
}

static int varlink_observe_channel_handler(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        sd_channel *c = ASSERT_PTR(userdata);
        int r;

        _cleanup_(varlink_reply_freep) VarlinkReply *reply = new(VarlinkReply, 1);
        if (!reply) {
                log_oom_debug();
                (void) sd_channel_close(c);
                return 0;
        }

        *reply = (VarlinkReply) {
                .parameters = sd_json_variant_ref(parameters),
                .flags = flags,
        };

        if (strdup_to(&reply->error_id, error_id) < 0) {
                log_oom_debug();
                (void) sd_channel_close(c);
                return 0;
        }

        r = sd_channel_try_push(c, reply);
        if (r >= 0)
                TAKE_PTR(reply);
        else if (r == -ENOBUFS)
                log_debug("Varlink observe channel full, dropping reply.");
        else
                log_debug_errno(r, "Failed to enqueue varlink reply, dropping: %m");

        /* The call is over after the final reply or an error reply. Closing the channel closes the link.
         * A receive that finds the closed channel empty fails with -EPIPE. */
        if (error_id || !FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES))
                (void) sd_channel_close(c);

        return 0;
}

static int varlink_observe_channel_start(
                sd_varlink *link,
                sd_channel *c,
                const char *method,
                sd_json_variant *parameters) {

        int r;

        assert(link);
        assert(c);
        assert(method);

        r = sd_varlink_bind_reply(link, varlink_observe_channel_handler);
        if (r < 0)
                return r;

        void *old_userdata = sd_varlink_set_userdata(link, c);

        r = sd_varlink_observe(link, method, parameters);
        if (r < 0) {
                (void) sd_varlink_bind_reply(link, NULL);
                (void) sd_varlink_set_userdata(link, old_userdata);
                return r;
        }

        /* A new channel isn't closed and has no slot yet, so sd_channel_set_slot() can't fail here. */
        assert_se(sd_channel_set_slot(c, sd_varlink_ref(link), varlink_observe_channel_slot_destroy) >= 0);
        return 0;
}

int varlink_observe_channel_new(
                sd_varlink *link,
                const char *method,
                sd_json_variant *parameters,
                size_t capacity,
                sd_channel **ret) {

        int r;

        assert(link);
        assert(method);
        assert(ret);

        sd_event *e = sd_varlink_get_event(link);
        if (!e)
                return -ENOPKG;

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        r = sd_channel_new(e, capacity, SD_CHANNEL_OVERFLOW_WAIT, varlink_observe_channel_item_destroy, &c);
        if (r < 0)
                return r;

        r = varlink_observe_channel_start(link, c, method, parameters);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(c);
        return 0;
}

int varlink_observe_channel_new_conflated(
                sd_varlink *link,
                const char *method,
                sd_json_variant *parameters,
                sd_channel **ret) {

        int r;

        assert(link);
        assert(method);
        assert(ret);

        sd_event *e = sd_varlink_get_event(link);
        if (!e)
                return -ENOPKG;

        _cleanup_(sd_channel_unrefp) sd_channel *c = NULL;
        r = sd_channel_new_conflated(e, varlink_observe_channel_item_destroy, &c);
        if (r < 0)
                return r;

        r = varlink_observe_channel_start(link, c, method, parameters);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(c);
        return 0;
}
