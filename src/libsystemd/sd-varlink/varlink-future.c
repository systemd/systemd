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

typedef struct VarlinkObserve {
        sd_varlink *link;
        sd_channel *channel;
        bool done;
} VarlinkObserve;

static void varlink_observe_channel_slot_destroy(void *p) {
        VarlinkObserve *o = ASSERT_PTR(p);

        /* The reply callback gets the VarlinkObserve object without a reference. We unbind the callback
         * before the object is freed. Otherwise a later reply on the link would call it with a freed object. */
        (void) sd_varlink_bind_reply(o->link, /* reply= */ NULL);
        sd_varlink_set_userdata(o->link, /* userdata= */ NULL);

        /* A call that is still running only ends when the link closes. After the final reply, the link
         * stays open, so that the caller can start another call on it. */
        if (o->done)
                sd_varlink_unref(o->link);
        else
                sd_varlink_close_unref(o->link);

        free(o);
}

static int varlink_observe_channel_handler(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        VarlinkObserve *o = ASSERT_PTR(userdata);
        sd_channel *c = o->channel;
        bool done = error_id || !FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES);
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
        if (r == -ENOBUFS && done) {
                /* The consumer needs the final reply or the error reply to learn how the call ended. We
                 * drop the oldest buffered notification to make room for it. */
                void *oldest;
                if (sd_channel_try_pop(c, &oldest) >= 0)
                        varlink_reply_free(oldest);

                r = sd_channel_try_push(c, reply);
        }
        if (r >= 0)
                TAKE_PTR(reply);
        else if (r == -ENOBUFS)
                log_debug("Varlink observe channel full, dropping reply.");
        else
                log_debug_errno(r, "Failed to enqueue varlink reply, dropping: %m");

        if (done) {
                o->done = true;
                (void) sd_channel_close(c);
        }

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

        /* sd_varlink_bind_reply() accepts the handler of another channel on the same link. The rollback
         * below would then unbind the handler of the other channel. */
        r = sd_varlink_is_idle(link);
        if (r < 0)
                return r;
        if (r == 0)
                return -EBUSY;

        _cleanup_free_ VarlinkObserve *o = new(VarlinkObserve, 1);
        if (!o)
                return -ENOMEM;

        *o = (VarlinkObserve) {
                .link = link,
                .channel = c,
        };

        r = sd_varlink_bind_reply(link, varlink_observe_channel_handler);
        if (r < 0)
                return r;

        void *old_userdata = sd_varlink_set_userdata(link, o);

        r = sd_varlink_observe(link, method, parameters);
        if (r < 0) {
                (void) sd_varlink_bind_reply(link, /* reply= */ NULL);
                sd_varlink_set_userdata(link, old_userdata);
                return r;
        }

        sd_varlink_ref(link);

        /* A new channel isn't closed and has no slot yet, so sd_channel_set_slot() can't fail here. */
        assert_se(sd_channel_set_slot(c, TAKE_PTR(o), varlink_observe_channel_slot_destroy) >= 0);
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
