/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-future.h"

#include "alloc-util.h"
#include "list.h"
#include "macro.h"

/* Both pending senders and pending receivers share the same shape: an entry in one of the
 * channel's pending lists, the future the caller awaits, and an item that may or may not
 * have changed ownership. One sd_future_ops drives both. */

typedef struct ChannelWaiter ChannelWaiter;

struct ChannelWaiter {
        LIST_FIELDS(ChannelWaiter, pending);
        sd_channel *channel;    /* strong ref */
        sd_future *future;      /* borrowed: this struct IS this future's private data */
        void *item;             /* send: the item to deliver; recv: the delivered value. */
        ChannelWaiter **list;   /* head of the list we're queued on (recv_pending /
                                 * send_pending), or NULL if not queued. */
};

struct sd_channel {
        unsigned n_ref;

        sd_event *event;

        size_t capacity;
        sd_channel_destroy_t destroy;

        void **buffer;
        size_t n_items;
        size_t head;
        size_t tail;

        /* Invariant under capacity > 0:
         *   recv_pending non-empty  ⇒  buffer empty AND send_pending empty
         *   send_pending non-empty  ⇒  buffer full  AND recv_pending empty
         * Maintained by the direct-handoff in try_push/try_pop. */
        LIST_HEAD(ChannelWaiter, recv_pending);
        LIST_HEAD(ChannelWaiter, send_pending);

        void *slot;
        sd_channel_destroy_t slot_destroy;

        bool closed;
};

static const sd_future_ops channel_ops;

int sd_channel_new(sd_event *e, size_t capacity, sd_channel_destroy_t destroy, sd_channel **ret) {
        assert_return(e, -EINVAL);
        assert_return(capacity > 0, -EINVAL);
        assert_return(ret, -EINVAL);

        sd_channel *c = new(sd_channel, 1);
        if (!c)
                return -ENOMEM;

        *c = (sd_channel) {
                .n_ref = 1,
                .event = sd_event_ref(e),
                .capacity = capacity,
                .destroy = destroy,
        };

        c->buffer = new(void*, capacity);
        if (!c->buffer) {
                sd_event_unref(c->event);
                free(c);
                return -ENOMEM;
        }

        *ret = c;
        return 0;
}

static void channel_drop_slot(sd_channel *c) {
        if (!c->slot_destroy)
                return;

        sd_channel_destroy_t destroy = TAKE_PTR(c->slot_destroy);
        void *slot = TAKE_PTR(c->slot);
        destroy(slot);
}

static sd_channel* channel_free(sd_channel *p) {
        assert(p);

        /* Pending waiter structs hold strong channel refs, so reaching the final unref means
         * the queues are empty by construction. */
        assert(!p->recv_pending);
        assert(!p->send_pending);

        channel_drop_slot(p);

        if (p->destroy)
                for (size_t i = 0; i < p->n_items; i++)
                        p->destroy(p->buffer[(p->head + i) % p->capacity]);

        free(p->buffer);
        sd_event_unref(p->event);
        return mfree(p);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_channel, sd_channel, channel_free);

static void* channel_waiter_alloc(void) {
        return new0(ChannelWaiter, 1);
}

static void channel_waiter_free(sd_future *f) {
        ChannelWaiter *w = ASSERT_PTR(sd_future_get_private(f));

        if (w->list) {
                LIST_REMOVE(pending, *w->list, w);
                w->list = NULL;
        }

        /* A non-NULL item means we still own it: either a sender whose item never made it
         * into the channel, or a receiver that was handed a value the caller never extracted.
         * Either way, hand it back through the channel's destroy callback rather than leak. */
        if (w->item && w->channel->destroy)
                w->channel->destroy(w->item);

        sd_channel_unref(w->channel);
        free(w);
}

static int channel_waiter_cancel(sd_future *f) {
        ChannelWaiter *w = ASSERT_PTR(sd_future_get_private(f));

        /* sd_future_cancel only invokes ops->cancel for PENDING futures, and PENDING means
         * the waiter is parked in its list. */
        LIST_REMOVE(pending, *w->list, w);
        w->list = NULL;

        return sd_future_resolve(f, -ECANCELED);
}

static const sd_future_ops channel_ops = {
        .size = sizeof(sd_future_ops),
        .alloc = channel_waiter_alloc,
        .free = channel_waiter_free,
        .cancel = channel_waiter_cancel,
};

int sd_channel_try_push(sd_channel *c, void *item) {
        assert_return(c, -EINVAL);

        if (c->closed)
                return -EPIPE;

        /* Direct handoff: a receiver is already waiting. By invariant the buffer is empty
         * and no sender is parked, so we can hand the item off directly. */
        if (c->recv_pending) {
                assert(c->n_items == 0);
                assert(!c->send_pending);
                ChannelWaiter *w = c->recv_pending;
                LIST_REMOVE(pending, *w->list, w);
                w->list = NULL;
                w->item = item;
                (void) sd_future_resolve(w->future, 0);
                return 1;
        }

        if (c->n_items >= c->capacity)
                return -ENOBUFS;

        /* By invariant: room in the buffer ⇒ no sender is parked. A parked sender would
         * have been promoted into the buffer as soon as the slot opened up. */
        assert(!c->send_pending);

        c->buffer[c->tail] = item;
        c->tail = (c->tail + 1) % c->capacity;
        c->n_items++;
        return 1;
}

int sd_channel_try_pop(sd_channel *c, void **ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (c->n_items == 0)
                return c->closed ? -EPIPE : -ENODATA;

        /* By invariant: n_items > 0 ⇒ no receiver is parked. A parked receiver would have
         * been handed any incoming item directly via the try_push handoff, so the buffer
         * can't be both non-empty and have waiters at the same time. */
        assert(!c->recv_pending);

        *ret = c->buffer[c->head];
        c->head = (c->head + 1) % c->capacity;
        c->n_items--;

        /* The pop opened a slot; promote one pending sender into the buffer if any. */
        if (c->send_pending) {
                ChannelWaiter *s = c->send_pending;
                c->buffer[c->tail] = s->item;
                c->tail = (c->tail + 1) % c->capacity;
                c->n_items++;
                LIST_REMOVE(pending, *s->list, s);
                s->list = NULL;
                s->item = NULL;
                (void) sd_future_resolve(s->future, 0);
        }

        return 1;
}

int sd_channel_send(sd_channel *c, void *item, sd_future **ret) {
        int r;

        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (c->closed)
                return -EPIPE;

        _cleanup_(sd_future_cancel_unrefp) sd_future *f = NULL;
        r = sd_future_new(c->event, &channel_ops, &f);
        if (r < 0)
                return r;

        ChannelWaiter *w = sd_future_get_private(f);
        *w = (ChannelWaiter) {
                .channel = sd_channel_ref(c),
                .future = f,
                .item = item,
        };

        r = sd_channel_try_push(c, item);
        if (r > 0) {
                w->item = NULL;       /* item is now in the buffer or with a receiver */
                (void) sd_future_resolve(f, 0);
        } else {
                /* The only other path here is -ENOBUFS (full) since we checked !closed
                 * above. Park until a receiver pops an item out of the buffer. */
                assert(r == -ENOBUFS);
                LIST_APPEND(pending, c->send_pending, w);
                w->list = &c->send_pending;
        }

        *ret = TAKE_PTR(f);
        return 0;
}

int sd_channel_recv(sd_channel *c, sd_future **ret) {
        int r;

        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (c->closed && c->n_items == 0)
                return -EPIPE;

        _cleanup_(sd_future_cancel_unrefp) sd_future *f = NULL;
        r = sd_future_new(c->event, &channel_ops, &f);
        if (r < 0)
                return r;

        ChannelWaiter *w = sd_future_get_private(f);
        *w = (ChannelWaiter) {
                .channel = sd_channel_ref(c),
                .future = f,
        };

        void *item;
        r = sd_channel_try_pop(c, &item);
        if (r > 0) {
                w->item = item;
                (void) sd_future_resolve(f, 0);
        } else {
                /* Only other path here is -ENODATA (empty) since we checked !(closed && empty)
                 * above. Park until a sender pushes. */
                assert(r == -ENODATA);
                LIST_APPEND(pending, c->recv_pending, w);
                w->list = &c->recv_pending;
        }

        *ret = TAKE_PTR(f);
        return 0;
}

int sd_channel_recv_get(sd_future *f, void **ret) {
        int r;

        assert_return(f, -EINVAL);
        assert_return(ret, -EINVAL);
        assert_return(sd_future_get_ops(f) == &channel_ops, -EINVAL);

        if (sd_future_state(f) != SD_FUTURE_RESOLVED)
                return -EAGAIN;

        r = sd_future_result(f);
        if (r < 0)
                return r;

        ChannelWaiter *w = ASSERT_PTR(sd_future_get_private(f));
        /* A resolved future must have been unlinked already — either by the dispatch path
         * (deliver/cancel/close all clear w->list) or never queued in the first place
         * (immediate-success path). */
        assert(!w->list);

        if (!w->item)
                return -ESTALE;

        *ret = w->item;
        w->item = NULL;
        return 0;
}

int sd_channel_push(sd_channel *c, void *item) {
        int r;

        assert_return(c, -EINVAL);
        assert_return(sd_fiber_is_running(), -ESRCH);

        _cleanup_(sd_future_cancel_wait_unrefp) sd_future *f = NULL;
        r = sd_channel_send(c, item, &f);
        if (r < 0)
                return r;

        return sd_fiber_await(f);
}

int sd_channel_pop(sd_channel *c, void **ret) {
        int r;

        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);
        assert_return(sd_fiber_is_running(), -ESRCH);

        _cleanup_(sd_future_cancel_wait_unrefp) sd_future *f = NULL;
        r = sd_channel_recv(c, &f);
        if (r < 0)
                return r;

        r = sd_fiber_await(f);
        if (r < 0)
                return r;

        return sd_channel_recv_get(f, ret);
}

int sd_channel_pop_latest(sd_channel *c, void **ret) {
        int r;

        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);
        assert_return(sd_fiber_is_running(), -ESRCH);

        void *item;
        r = sd_channel_pop(c, &item);
        if (r < 0)
                return r;

        /* Drain whatever else is sitting in the buffer right now, discarding each stale item
         * via the channel's destroy callback. We do NOT block for more items here — pop_latest
         * commits to "freshest at the moment we returned from the blocking pop". Fresh items
         * that arrive *after* this drain are the next caller's problem. */
        for (;;) {
                void *next;
                r = sd_channel_try_pop(c, &next);
                if (r == -ENODATA || r == -EPIPE)
                        break;
                if (r < 0) {
                        if (c->destroy)
                                c->destroy(item);
                        return r;
                }

                if (c->destroy)
                        c->destroy(item);
                item = next;
        }

        *ret = item;
        return 0;
}

int sd_channel_close(sd_channel *c) {
        assert_return(c, -EINVAL);

        if (c->closed)
                return 0;

        c->closed = true;

        /* Tear down the producer source first so no new pushes can race with the wake-up
         * loops below. After this returns, the slot (and whatever callbacks it owned) are
         * gone, and no further try_push calls will reach us. */
        channel_drop_slot(c);

        /* Reject pending senders: their items are still in w->item, so the future's free
         * path will hand them back through destroy. */
        ChannelWaiter *w;
        while ((w = LIST_POP(pending, c->send_pending))) {
                w->list = NULL;
                (void) sd_future_resolve(w->future, -EPIPE);
        }

        /* Reject pending receivers: no item to extract. */
        while ((w = LIST_POP(pending, c->recv_pending))) {
                w->list = NULL;
                (void) sd_future_resolve(w->future, -EPIPE);
        }

        return 0;
}

int sd_channel_set_slot(sd_channel *c, void *slot, sd_channel_destroy_t destroy) {
        assert_return(c, -EINVAL);
        assert_return(!!slot == !!destroy, -EINVAL);

        if (c->closed && slot)
                return -EPIPE;

        /* Replacing an existing slot: destroy the previous one immediately so we don't leak
         * it. NULL/NULL clears. */
        channel_drop_slot(c);

        c->slot = slot;
        c->slot_destroy = destroy;
        return 0;
}
