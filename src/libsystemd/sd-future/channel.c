/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-future.h"

#include "alloc-util.h"
#include "list.h"
#include "macro.h"

/* Send futures and receive futures use ChannelWaiter as private data and share channel_ops. In a
 * send future, `item` is the item to deliver. In a receive future, `item` is the item it received. */

typedef struct ChannelWaiter ChannelWaiter;

struct ChannelWaiter {
        LIST_FIELDS(ChannelWaiter, pending);
        sd_channel *channel;
        /* The future owns this struct as its private data, so this pointer holds no reference. */
        sd_future *future;
        void *item;
        /* This points to &channel->recv_pending or &channel->send_pending while the waiter is queued. */
        ChannelWaiter **list;
};

struct sd_channel {
        unsigned n_ref;

        sd_event *event;

        size_t capacity;
        sd_channel_overflow_t overflow;
        sd_channel_destroy_t destroy;

        void **buffer;
        size_t n_items;
        size_t head;
        size_t tail;

        /* A receive only waits while the buffer is empty, and a send only waits while the buffer is
         * full. sd_channel_try_push() gives an item to a waiting receive future directly instead of
         * buffering it. sd_channel_try_pop() moves the item of a waiting send into the buffer as soon
         * as it frees a slot. A channel with a drop policy never queues a send. */
        LIST_HEAD(ChannelWaiter, recv_pending);
        LIST_HEAD(ChannelWaiter, send_pending);

        void *slot;
        sd_channel_destroy_t slot_destroy;

        bool closed;
};

static const sd_future_ops channel_ops;

int sd_channel_new(sd_event *e, size_t capacity, sd_channel_overflow_t overflow, sd_channel_destroy_t destroy, sd_channel **ret) {
        assert_return(e, -EINVAL);
        assert_return(capacity > 0, -EINVAL);
        assert_return(IN_SET(overflow, SD_CHANNEL_OVERFLOW_WAIT, SD_CHANNEL_OVERFLOW_DROP_OLDEST, SD_CHANNEL_OVERFLOW_DROP_LATEST), -EINVAL);
        assert_return(ret, -EINVAL);

        sd_channel *c = new(sd_channel, 1);
        if (!c)
                return -ENOMEM;

        *c = (sd_channel) {
                .n_ref = 1,
                .event = sd_event_ref(e),
                .capacity = capacity,
                .overflow = overflow,
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

int sd_channel_new_conflated(sd_event *e, sd_channel_destroy_t destroy, sd_channel **ret) {
        return sd_channel_new(e, /* capacity= */ 1, SD_CHANNEL_OVERFLOW_DROP_OLDEST, destroy, ret);
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

        /* A queued ChannelWaiter holds a reference to the channel, so the lists are empty here. */
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

        /* The future owns `item` if the send never reached the channel, or if the caller never took
         * the received item with sd_channel_recv_get(). Destroy the item so that it doesn't leak. */
        if (w->item && w->channel->destroy)
                w->channel->destroy(w->item);

        sd_channel_unref(w->channel);
        free(w);
}

static int channel_waiter_cancel(sd_future *f) {
        ChannelWaiter *w = ASSERT_PTR(sd_future_get_private(f));

        /* sd_future_cancel() only calls this for a pending future, and a pending ChannelWaiter is
         * always queued. */
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
                switch (c->overflow) {

                case SD_CHANNEL_OVERFLOW_WAIT:
                        /* sd_channel_send() queues its future when it gets -ENOBUFS. */
                        return -ENOBUFS;

                case SD_CHANNEL_OVERFLOW_DROP_LATEST:
                        /* The channel owns the item once the push succeeds, so destroy it here. */
                        if (c->destroy)
                                c->destroy(item);
                        return 1;

                case SD_CHANNEL_OVERFLOW_DROP_OLDEST: {
                        void *dropped = c->buffer[c->head];
                        c->head = (c->head + 1) % c->capacity;
                        c->n_items--;
                        if (c->destroy)
                                c->destroy(dropped);
                        break;
                }

                default:
                        assert_not_reached();
                }

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

        assert(!c->recv_pending);

        *ret = c->buffer[c->head];
        c->head = (c->head + 1) % c->capacity;
        c->n_items--;

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
                /* The channel owns the item now, so channel_waiter_free() must not destroy it. */
                w->item = NULL;
                (void) sd_future_resolve(f, 0);
        } else {
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
        /* Every path that resolves a ChannelWaiter removes it from its list first. */
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

        r = sd_fiber_await(f);
        if (r < 0)
                return r;

        return sd_future_result(f);
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

int sd_channel_close(sd_channel *c) {
        assert_return(c, -EINVAL);

        if (c->closed)
                return 0;

        c->closed = true;

        /* The slot usually owns the event source that pushes items into the channel. Destroy the slot
         * first, so that the source stops before the waiting futures are resolved below. */
        channel_drop_slot(c);

        /* A waiting send still owns its item. channel_waiter_free() destroys the item when the future
         * is freed. */
        ChannelWaiter *w;
        while ((w = LIST_POP(pending, c->send_pending))) {
                w->list = NULL;
                (void) sd_future_resolve(w->future, -EPIPE);
        }

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

        channel_drop_slot(c);

        c->slot = slot;
        c->slot_destroy = destroy;
        return 0;
}
