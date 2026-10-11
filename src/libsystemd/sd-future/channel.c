/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-future.h"

#include "alloc-util.h"
#include "event-util.h"
#include "list.h"
#include "macro.h"

/* Send futures and receive futures use ChannelWaiter as private data and share channel_ops. In a
 * send future, `item` is the item to deliver. In a receive future, `item` is the item it received. */

typedef struct ChannelWaiter ChannelWaiter;

struct ChannelWaiter {
        LIST_FIELDS(ChannelWaiter, pending);
        sd_channel *channel;
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

        /* The producer attaches the source that pushes items into the channel as `slot`, for example
         * the sd_bus_slot of a D-Bus match. The channel calls slot_destroy when it is closed or freed.
         * Without that call, the D-Bus match callback would push items into the channel after it was
         * freed. */
        void *slot;
        sd_channel_destroy_t slot_destroy;

        bool closed;
};

static void channel_waiter_unlink(ChannelWaiter *w) {
        assert(w);
        assert(w->list);

        LIST_REMOVE(pending, *w->list, w);
        w->list = NULL;
}

static void channel_waiter_enqueue(ChannelWaiter *w, ChannelWaiter **list) {
        assert(w);
        assert(!w->list);
        assert(list);

        LIST_APPEND(pending, *list, w);
        w->list = list;
}

static ChannelWaiter* channel_waiter_pop(ChannelWaiter **list) {
        assert(list);

        ChannelWaiter *w = LIST_POP(pending, *list);
        if (w)
                w->list = NULL;

        return w;
}

static void channel_destroy_item(sd_channel *c, void *item) {
        assert(c);

        if (c->destroy)
                c->destroy(item);
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

        for (size_t i = 0; i < p->n_items; i++)
                channel_destroy_item(p, p->buffer[(p->head + i) % p->capacity]);

        free(p->buffer);
        sd_event_unref(p->event);
        return mfree(p);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_channel, sd_channel, channel_free);

int sd_channel_new(sd_event *e, size_t capacity, sd_channel_overflow_t overflow, sd_channel_destroy_t destroy, sd_channel **ret) {
        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(capacity > 0, -EINVAL);
        assert_return(IN_SET(overflow,
                             SD_CHANNEL_OVERFLOW_WAIT,
                             SD_CHANNEL_OVERFLOW_DROP_OLDEST,
                             SD_CHANNEL_OVERFLOW_DROP_LATEST), -EINVAL);
        assert_return(ret, -EINVAL);

        _cleanup_(sd_channel_unrefp) sd_channel *c = new(sd_channel, 1);
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
        if (!c->buffer)
                return -ENOMEM;

        *ret = TAKE_PTR(c);
        return 0;
}

int sd_channel_new_conflated(sd_event *e, sd_channel_destroy_t destroy, sd_channel **ret) {
        return sd_channel_new(e, /* capacity= */ 1, SD_CHANNEL_OVERFLOW_DROP_OLDEST, destroy, ret);
}

static void channel_waiter_free(sd_future *f) {
        ChannelWaiter *w = ASSERT_PTR(sd_future_get_private(f));

        /* sd-future only frees resolved futures, and every path that resolves a ChannelWaiter removes it
         * from its list first. */
        assert(!w->list);

        /* The future owns `item` if the send never reached the channel, or if the caller never took
         * the received item with sd_channel_recv_get(). Destroy the item so that it doesn't leak. */
        if (w->item)
                channel_destroy_item(w->channel, w->item);

        sd_channel_unref(w->channel);
}

static int channel_waiter_cancel(sd_future *f) {
        ChannelWaiter *w = ASSERT_PTR(sd_future_get_private(f));

        /* sd_future_cancel() only calls this for a pending future, and a pending ChannelWaiter is
         * always queued. */
        channel_waiter_unlink(w);

        return sd_future_resolve(f, -ECANCELED);
}

static const sd_future_ops channel_ops = {
        .size = sizeof(sd_future_ops),
        .private_size = sizeof(ChannelWaiter),
        .free = channel_waiter_free,
        .cancel = channel_waiter_cancel,
};

int sd_channel_try_push(sd_channel *c, void *item) {
        assert_return(c, -EINVAL);
        assert_return(item, -EINVAL);

        if (c->closed)
                return -EPIPE;

        ChannelWaiter *w = channel_waiter_pop(&c->recv_pending);
        if (w) {
                assert(c->n_items == 0);
                assert(!c->send_pending);
                w->item = item;
                assert_se(sd_future_resolve(sd_future_from_private(w), 0) >= 0);
                return 1;
        }

        if (c->n_items >= c->capacity)
                switch (c->overflow) {

                case SD_CHANNEL_OVERFLOW_WAIT:
                        /* sd_channel_send() queues its future when it gets -ENOBUFS. */
                        return -ENOBUFS;

                case SD_CHANNEL_OVERFLOW_DROP_LATEST:
                        /* The channel owns the item once the push succeeds, so destroy it here. */
                        channel_destroy_item(c, item);
                        return 1;

                case SD_CHANNEL_OVERFLOW_DROP_OLDEST: {
                        void *dropped = c->buffer[c->head];
                        c->head = (c->head + 1) % c->capacity;
                        c->n_items--;
                        channel_destroy_item(c, dropped);
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

        ChannelWaiter *s = channel_waiter_pop(&c->send_pending);
        if (s) {
                c->buffer[c->tail] = TAKE_PTR(s->item);
                c->tail = (c->tail + 1) % c->capacity;
                c->n_items++;
                assert_se(sd_future_resolve(sd_future_from_private(s), 0) >= 0);
        }

        return 1;
}

int sd_channel_send(sd_channel *c, void *item, sd_future **ret) {
        int r;

        assert_return(c, -EINVAL);
        assert_return(item, -EINVAL);
        assert_return(ret, -EINVAL);

        if (c->closed) {
                channel_destroy_item(c, item);
                return -EPIPE;
        }

        _cleanup_(sd_future_cancel_unrefp) sd_future *f = NULL;
        r = sd_future_new(c->event, &channel_ops, &f);
        if (r < 0) {
                channel_destroy_item(c, item);
                return r;
        }

        ChannelWaiter *w = sd_future_get_private(f);
        *w = (ChannelWaiter) {
                .channel = sd_channel_ref(c),
                .item = item,
        };

        r = sd_channel_try_push(c, item);
        if (r > 0) {
                /* The channel owns the item now, so channel_waiter_free() must not destroy it. */
                w->item = NULL;
                assert_se(sd_future_resolve(f, 0) >= 0);
        } else {
                assert(r == -ENOBUFS);
                channel_waiter_enqueue(w, &c->send_pending);
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
        };

        void *item;
        r = sd_channel_try_pop(c, &item);
        if (r > 0) {
                w->item = item;
                assert_se(sd_future_resolve(f, 0) >= 0);
        } else {
                assert(r == -ENODATA);
                channel_waiter_enqueue(w, &c->recv_pending);
        }

        *ret = TAKE_PTR(f);
        return 0;
}

int sd_channel_recv_get(sd_future *f, void **ret) {
        int r;

        assert_return(f, -EINVAL);
        assert_return(ret, -EINVAL);
        assert_return(sd_future_get_ops(f) == &channel_ops, -EINVAL);

        assert_return(sd_future_state(f) == SD_FUTURE_RESOLVED, -EBUSY);

        r = sd_future_result(f);
        if (r < 0)
                return r;

        ChannelWaiter *w = ASSERT_PTR(sd_future_get_private(f));
        assert(!w->list);

        if (!w->item)
                return -ESTALE;

        *ret = TAKE_PTR(w->item);
        return 1;
}

int sd_channel_push(sd_channel *c, void *item) {
        int r;

        assert_return(c, -EINVAL);
        assert_return(item, -EINVAL);
        assert_return(sd_fiber_is_running(), -ESRCH);

        r = sd_fiber_interrupted();
        if (r < 0) {
                channel_destroy_item(c, item);
                return r;
        }

        /* Only allocate a send future if the push has to wait for room. */
        r = sd_channel_try_push(c, item);
        if (r > 0)
                return 0;
        if (r != -ENOBUFS) {
                channel_destroy_item(c, item);
                return r;
        }

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

        r = sd_fiber_interrupted();
        if (r < 0)
                return r;

        /* Only allocate a receive future if the pop has to wait for an item. */
        r = sd_channel_try_pop(c, ret);
        if (r > 0)
                return 0;
        if (r != -ENODATA)
                return r;

        _cleanup_(sd_future_cancel_wait_unrefp) sd_future *f = NULL;
        r = sd_channel_recv(c, &f);
        if (r < 0)
                return r;

        r = sd_fiber_await(f);
        if (r < 0)
                return r;

        r = sd_channel_recv_get(f, ret);
        if (r < 0)
                return r;

        return 0;
}

int sd_channel_close(sd_channel *c) {
        assert_return(c, -EINVAL);

        if (c->closed)
                return 0;

        /* The slot destroy callback can drop the last reference to the channel and free it. Hold a
         * reference so that the channel stays allocated until this function returns. */
        _unused_ _cleanup_(sd_channel_unrefp) sd_channel *ref = sd_channel_ref(c);

        c->closed = true;

        channel_drop_slot(c);

        /* channel_waiter_free() destroys the item of a rejected send when its future is freed. */
        ChannelWaiter *w;
        while ((w = channel_waiter_pop(&c->send_pending)))
                assert_se(sd_future_resolve(sd_future_from_private(w), -EPIPE) >= 0);

        while ((w = channel_waiter_pop(&c->recv_pending)))
                assert_se(sd_future_resolve(sd_future_from_private(w), -EPIPE) >= 0);

        return 0;
}

int sd_channel_set_slot(sd_channel *c, void *slot, sd_channel_destroy_t destroy) {
        assert_return(c, -EINVAL);
        assert_return(!!slot == !!destroy, -EINVAL);

        if (c->closed && slot)
                return -EPIPE;

        /* The slot destroy callback can drop the last reference to the channel and free it. Hold a
         * reference so that the channel stays allocated until this function returns. */
        _unused_ _cleanup_(sd_channel_unrefp) sd_channel *ref = sd_channel_ref(c);

        channel_drop_slot(c);

        c->slot = slot;
        c->slot_destroy = destroy;
        return 0;
}
