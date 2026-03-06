/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/filter.h>
#include <poll.h>
#include <stdlib.h>

#include "sd-event.h"
#include "sd-netlink.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "io-util.h"
#include "log.h"
#include "netlink-genl.h"
#include "netlink-internal.h"
#include "netlink-slot.h"
#include "netlink-util.h"
#include "ordered-set.h"
#include "prioq.h"
#include "process-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "time-util.h"

/* Some really high limit, to catch programming errors */
#define REPLY_CALLBACKS_MAX UINT16_MAX

static int netlink_new(sd_netlink **ret) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *nl = NULL;

        assert_return(ret, -EINVAL);

        nl = new(sd_netlink, 1);
        if (!nl)
                return -ENOMEM;

        *nl = (sd_netlink) {
                .n_ref = 1,
                .fd = -EBADF,
                .sockaddr.nl.nl_family = AF_NETLINK,
                .original_pid = getpid_cached(),
                .protocol = -1,

                /* Kernel change notification messages have sequence number 0. We want to avoid that with our
                 * own serials, in order not to get confused when matching up kernel replies to our earlier
                 * requests.
                 *
                 * Moreover, when using netlink socket activation (i.e. where PID 1 binds an AF_NETLINK
                 * socket for us and passes it to us across execve()) and we get restarted multiple times
                 * while the socket sticks around we might get confused by replies from earlier runs coming
                 * in late — which is pretty likely if we'd start our sequence numbers always from 1. Hence,
                 * let's start with a value based on the system clock. This should make collisions much less
                 * likely (though still theoretically possible). We use a 32 bit μs counter starting at boot
                 * for this (and explicitly exclude the zero, see above). This counter will wrap around after
                 * a bit more than 1h, but that's hopefully OK as the kernel shouldn't take that long to
                 * reply to our requests.
                 *
                 * We only pick the initial start value this way. For each message we simply increase the
                 * sequence number by 1. This means we could enqueue 1 netlink message per μs without risking
                 * collisions, which should be OK.
                 *
                 * Note this means the serials will be in the range 1…UINT32_MAX here.
                 *
                 * (In an ideal world we'd attach the current serial counter to the netlink socket itself
                 * somehow, to avoid all this, but I couldn't come up with a nice way to do this) */
                .serial = (uint32_t) (now(CLOCK_MONOTONIC) % UINT32_MAX) + 1,
        };

        *ret = TAKE_PTR(nl);
        return 0;
}

int sd_netlink_open_fd(sd_netlink **ret, int fd) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *nl = NULL;
        int r, protocol = 0; /* Avoid maybe-uninitialized false positive */

        assert_return(ret, -EINVAL);
        assert_return(fd >= 0, -EBADF);

        r = netlink_new(&nl);
        if (r < 0)
                return r;

        r = getsockopt_int(fd, SOL_SOCKET, SO_PROTOCOL, &protocol);
        if (r < 0)
                return r;

        nl->fd = fd;
        nl->protocol = protocol;

        r = setsockopt_int(fd, SOL_NETLINK, NETLINK_EXT_ACK, true);
        if (r < 0)
                log_debug_errno(r, "sd-netlink: Failed to enable NETLINK_EXT_ACK option, ignoring: %m");

        r = setsockopt_int(fd, SOL_NETLINK, NETLINK_GET_STRICT_CHK, true);
        if (r < 0)
                log_debug_errno(r, "sd-netlink: Failed to enable NETLINK_GET_STRICT_CHK option, ignoring: %m");

        r = socket_bind(nl);
        if (r < 0) {
                nl->fd = -EBADF; /* on failure, the caller remains owner of the fd, hence don't close it here */
                nl->protocol = -1;
                return r;
        }

        *ret = TAKE_PTR(nl);

        return 0;
}

int sd_netlink_open(sd_netlink **ret) {
        return netlink_open_family(ret, NETLINK_ROUTE);
}

int sd_netlink_increase_rxbuf(sd_netlink *nl, size_t size) {
        assert_return(nl, -EINVAL);
        assert_return(!netlink_pid_changed(nl), -ECHILD);

        return fd_increase_rxbuf(nl->fd, size);
}

static sd_netlink *netlink_free(sd_netlink *nl) {
        sd_netlink_slot *s;

        assert(nl);

        hashmap_free(nl->ignored_serials);

        ordered_set_free(nl->rqueue);
        hashmap_free(nl->rqueue_by_serial);
        hashmap_free(nl->rqueue_partial_by_serial);
        free(nl->rbuffer);

        while ((s = nl->slots)) {
                assert(s->floating);
                netlink_slot_disconnect(s, true);
        }
        hashmap_free(nl->reply_callbacks);
        prioq_free(nl->reply_callbacks_prioq);

        sd_event_source_unref(nl->io_event_source);
        sd_event_source_unref(nl->time_event_source);
        sd_event_unref(nl->event);

        hashmap_free(nl->broadcast_group_refs);

        genl_clear_family(nl);

        safe_close(nl->fd);
        return mfree(nl);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_netlink, sd_netlink, netlink_free);

static usec_t netlink_now(sd_netlink *nl, clock_t clock) {
        assert(nl);

        usec_t now_usec;
        if (nl->event && sd_event_now(nl->event, clock, &now_usec) > 0)
                return now_usec;

        return now(clock);
}

static usec_t timespan_to_timestamp(sd_netlink *nl, usec_t usec) {
        static bool default_timeout_set = false;
        static usec_t default_timeout;
        int r;

        assert(nl);

        if (usec == 0) {
                if (!default_timeout_set) {
                        const char *e;

                        default_timeout_set = true;
                        default_timeout = NETLINK_DEFAULT_TIMEOUT_USEC;

                        e = secure_getenv("SYSTEMD_NETLINK_DEFAULT_TIMEOUT");
                        if (e) {
                                r = parse_sec(e, &default_timeout);
                                if (r < 0)
                                        log_debug_errno(r, "sd-netlink: Failed to parse $SYSTEMD_NETLINK_DEFAULT_TIMEOUT environment variable, ignoring: %m");
                        }
                }

                usec = default_timeout;
        }

        return usec_add(netlink_now(nl, CLOCK_MONOTONIC), usec);
}

static void netlink_trim_ignored_serials(sd_netlink *nl) {
        NetlinkIgnoredSerial *s;
        usec_t now_usec = 0;

        assert(nl);

        HASHMAP_FOREACH(s, nl->ignored_serials) {
                if (s->timeout_usec == USEC_INFINITY)
                        continue;

                if (now_usec == 0)
                        now_usec = netlink_now(nl, CLOCK_MONOTONIC);

                if (s->timeout_usec < now_usec)
                        free(hashmap_remove(nl->ignored_serials, UINT32_TO_PTR(s->serial)));
        }
}

int sd_netlink_ignore_serial(sd_netlink *nl, uint32_t serial, uint64_t timeout_usec) {
        int r;

        assert_return(nl, -EINVAL);
        assert_return(!netlink_pid_changed(nl), -ECHILD);
        assert_return(serial != 0, -EINVAL);

        timeout_usec = timespan_to_timestamp(nl, timeout_usec);

        NetlinkIgnoredSerial *existing = hashmap_get(nl->ignored_serials, UINT32_TO_PTR(serial));
        if (existing) {
                existing->timeout_usec = timeout_usec;
                return 0;
        }

        netlink_trim_ignored_serials(nl);

        _cleanup_free_ NetlinkIgnoredSerial *s = new(NetlinkIgnoredSerial, 1);
        if (!s)
                return -ENOMEM;

        *s = (NetlinkIgnoredSerial) {
                .serial = serial,
                .timeout_usec = timeout_usec,
        };

        r = hashmap_ensure_put(&nl->ignored_serials, &trivial_hash_ops_value_free, UINT32_TO_PTR(s->serial), s);
        if (r < 0)
                return r;

        TAKE_PTR(s);
        return 0;
}

int sd_netlink_send(
                sd_netlink *nl,
                sd_netlink_message *message,
                uint32_t *ret_serial) {

        int r;

        assert_return(nl, -EINVAL);
        assert_return(!netlink_pid_changed(nl), -ECHILD);
        assert_return(message, -EINVAL);
        assert_return(!message->sealed, -EPERM);

        netlink_seal_message(nl, message);

        r = socket_write_message(nl, message);
        if (r < 0)
                return r;

        if (ret_serial)
                *ret_serial = message_get_serial(message);

        return 1;
}

static int dispatch_rqueue(sd_netlink *nl, sd_netlink_message **ret) {
        sd_netlink_message *m;
        int r;

        assert(nl);
        assert(ret);

        if (ordered_set_isempty(nl->rqueue)) {
                /* Try to read a new message */
                r = socket_read_message(nl);
                if (r == -ENOBUFS) /* FIXME: ignore buffer overruns for now */
                        log_debug_errno(r, "sd-netlink: Got ENOBUFS from netlink socket, ignoring.");
                else if (r < 0)
                        return r;
        }

        /* Dispatch a queued message */
        m = ordered_set_steal_first(nl->rqueue);
        if (m)
                sd_netlink_message_unref(hashmap_remove_value(nl->rqueue_by_serial, UINT32_TO_PTR(message_get_serial(m)), m));
        *ret = m;
        return !!m;
}

static int process_timeout(sd_netlink *nl) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        struct reply_callback *c;
        sd_netlink_slot *slot;
        int r;

        assert(nl);

        c = prioq_peek(nl->reply_callbacks_prioq);
        if (!c)
                return 0;

        if (c->timeout > netlink_now(nl, CLOCK_MONOTONIC))
                return 0;

        r = message_new_synthetic_error(nl, -ETIMEDOUT, c->serial, &m);
        if (r < 0)
                return r;

        assert_se(prioq_pop(nl->reply_callbacks_prioq) == c);
        hashmap_remove(nl->reply_callbacks, UINT32_TO_PTR(c->serial));

        slot = container_of(c, sd_netlink_slot, reply_callback);

        r = c->callback(nl, m, slot->userdata);
        if (r < 0)
                log_debug_errno(r, "sd-netlink: timedout callback %s%s%sfailed: %m",
                                slot->description ? "'" : "",
                                strempty(slot->description),
                                slot->description ? "' " : "");

        if (slot->floating)
                netlink_slot_disconnect(slot, true);

        return 1;
}

static int process_reply(sd_netlink *nl, sd_netlink_message *m) {
        struct reply_callback *c;
        uint32_t serial;
        uint16_t type;
        int r;

        assert(nl);
        assert(m);

        serial = message_get_serial(m);
        c = hashmap_remove(nl->reply_callbacks, UINT32_TO_PTR(serial));
        if (!c)
                return 0;

        if (c->timeout != USEC_INFINITY)
                prioq_remove(nl->reply_callbacks_prioq, c, &c->prioq_idx);

        r = sd_netlink_message_get_type(m, &type);
        if (r < 0)
                return r;

        if (type == NLMSG_DONE)
                m = NULL;

        _cleanup_(sd_netlink_slot_unrefp) sd_netlink_slot *slot =
                sd_netlink_slot_ref(container_of(c, sd_netlink_slot, reply_callback));

        r = c->callback(nl, m, slot->userdata);
        if (r < 0)
                log_debug_errno(r, "sd-netlink: reply callback %s%s%sfailed: %m",
                                slot->description ? "'" : "",
                                strempty(slot->description),
                                slot->description ? "' " : "");

        if (slot->floating)
                netlink_slot_disconnect(slot, true);

        return 1;
}

static int process_match(sd_netlink *nl, sd_netlink_message *m) {
        uint16_t type;
        uint8_t cmd;
        int r;

        assert(nl);
        assert(m);

        r = sd_netlink_message_get_type(m, &type);
        if (r < 0)
                return r;

        if (m->protocol == NETLINK_GENERIC) {
                r = sd_genl_message_get_command(nl, m, &cmd);
                if (r < 0)
                        return r;
        } else
                cmd = 0;

        LIST_FOREACH(match_callbacks, c, nl->match_callbacks) {
                sd_netlink_slot *slot;
                bool found = false;

                if (c->type != type)
                        continue;
                if (c->cmd != 0 && c->cmd != cmd)
                        continue;

                for (size_t i = 0; i < c->n_groups; i++)
                        if (c->groups[i] == m->multicast_group) {
                                found = true;
                                break;
                        }

                if (!found)
                        continue;

                slot = container_of(c, sd_netlink_slot, match_callback);

                r = c->callback(nl, m, slot->userdata);
                if (r < 0)
                        log_debug_errno(r, "sd-netlink: match callback %s%s%sfailed: %m",
                                        slot->description ? "'" : "",
                                        strempty(slot->description),
                                        slot->description ? "' " : "");
                if (r != 0)
                        break;
        }

        return 1;
}

static int process_running(sd_netlink *nl, sd_netlink_message **ret) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(nl);

        netlink_trim_ignored_serials(nl);

        r = process_timeout(nl);
        if (r != 0)
                goto null_message;

        r = dispatch_rqueue(nl, &m);
        if (r < 0)
                return r;
        if (!m)
                goto null_message;

        if (sd_netlink_message_is_broadcast(m))
                r = process_match(nl, m);
        else
                r = process_reply(nl, m);
        if (r != 0)
                goto null_message;

        if (ret) {
                *ret = TAKE_PTR(m);

                return 1;
        }

        return 1;

null_message:
        if (r >= 0 && ret)
                *ret = NULL;

        return r;
}

int sd_netlink_process(sd_netlink *nl, sd_netlink_message **ret) {
        NETLINK_DONT_DESTROY(nl);
        int r;

        assert_return(nl, -EINVAL);
        assert_return(!netlink_pid_changed(nl), -ECHILD);
        assert_return(!nl->processing, -EBUSY);

        nl->processing = true;
        r = process_running(nl, ret);
        nl->processing = false;

        return r;
}

static int netlink_poll(sd_netlink *nl, bool need_more, usec_t timeout_usec) {
        usec_t m = USEC_INFINITY;
        int r, e;

        assert(nl);

        e = sd_netlink_get_events(nl);
        if (e < 0)
                return e;

        if (need_more)
                /* Caller wants more data, and doesn't care about
                 * what's been read or any other timeouts. */
                e |= POLLIN;
        else {
                usec_t until;

                /* Caller wants to process if there is something to
                 * process, but doesn't care otherwise */

                r = sd_netlink_get_timeout(nl, &until);
                if (r < 0)
                        return r;

                m = usec_sub_unsigned(until, netlink_now(nl, CLOCK_MONOTONIC));
        }

        r = fd_wait_for_event(nl->fd, e, MIN(m, timeout_usec));
        if (r <= 0)
                return r;

        return 1;
}

int sd_netlink_wait(sd_netlink *nl, uint64_t timeout_usec) {
        int r;

        assert_return(nl, -EINVAL);
        assert_return(!netlink_pid_changed(nl), -ECHILD);

        if (!ordered_set_isempty(nl->rqueue))
                return 0;

        r = netlink_poll(nl, false, timeout_usec);
        if (ERRNO_IS_NEG_TRANSIENT(r)) /* Convert EINTR to "something happened" and give user a chance to run some code before calling back into us */
                return 1;
        return r;
}

static int timeout_compare(const void *a, const void *b) {
        const struct reply_callback *x = a, *y = b;

        return CMP(x->timeout, y->timeout);
}

size_t netlink_get_reply_callback_count(sd_netlink *nl) {
        if (!nl)
                return 0;

        return hashmap_size(nl->reply_callbacks);
}

int sd_netlink_call_async(
                sd_netlink *nl,
                sd_netlink_slot **ret_slot,
                sd_netlink_message *m,
                sd_netlink_message_handler_t callback,
                sd_netlink_destroy_t destroy_callback,
                void *userdata,
                uint64_t usec,
                const char *description) {

        _cleanup_free_ sd_netlink_slot *slot = NULL;
        int r, k;

        assert_return(nl, -EINVAL);
        assert_return(m, -EINVAL);
        assert_return(callback, -EINVAL);
        assert_return(!netlink_pid_changed(nl), -ECHILD);

        if (hashmap_size(nl->reply_callbacks) >= REPLY_CALLBACKS_MAX)
                return -EXFULL;

        r = hashmap_ensure_allocated(&nl->reply_callbacks, &trivial_hash_ops);
        if (r < 0)
                return r;

        if (usec != UINT64_MAX) {
                r = prioq_ensure_allocated(&nl->reply_callbacks_prioq, timeout_compare);
                if (r < 0)
                        return r;
        }

        r = netlink_slot_allocate(nl, !ret_slot, NETLINK_REPLY_CALLBACK, sizeof(struct reply_callback), userdata, description, &slot);
        if (r < 0)
                return r;

        slot->reply_callback.callback = callback;
        slot->reply_callback.timeout = timespan_to_timestamp(nl, usec);

        k = sd_netlink_send(nl, m, &slot->reply_callback.serial);
        if (k < 0)
                return k;

        r = hashmap_put(nl->reply_callbacks, UINT32_TO_PTR(slot->reply_callback.serial), &slot->reply_callback);
        if (r < 0)
                return r;

        if (slot->reply_callback.timeout != USEC_INFINITY) {
                r = prioq_put(nl->reply_callbacks_prioq, &slot->reply_callback, &slot->reply_callback.prioq_idx);
                if (r < 0) {
                        (void) hashmap_remove(nl->reply_callbacks, UINT32_TO_PTR(slot->reply_callback.serial));
                        return r;
                }
        }

        /* Set this at last. Otherwise, some failures in above would call destroy_callback but some would not. */
        slot->destroy_callback = destroy_callback;

        if (ret_slot)
                *ret_slot = slot;

        TAKE_PTR(slot);

        return k;
}

int sd_netlink_read(
                sd_netlink *nl,
                uint32_t serial,
                uint64_t timeout,
                sd_netlink_message **ret) {

        usec_t usec;
        int r;

        assert_return(nl, -EINVAL);
        assert_return(!netlink_pid_changed(nl), -ECHILD);

        usec = timespan_to_timestamp(nl, timeout);

        for (;;) {
                _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
                usec_t left;

                m = hashmap_remove(nl->rqueue_by_serial, UINT32_TO_PTR(serial));
                if (m) {
                        uint16_t type;

                        /* found a match, remove from rqueue and return it */
                        sd_netlink_message_unref(ordered_set_remove(nl->rqueue, m));

                        r = sd_netlink_message_get_errno(m);
                        if (r < 0)
                                return r;

                        r = sd_netlink_message_get_type(m, &type);
                        if (r < 0)
                                return r;

                        if (type == NLMSG_DONE) {
                                if (ret)
                                        *ret = NULL;
                                return 0;
                        }

                        if (ret)
                                *ret = TAKE_PTR(m);
                        return 1;
                }

                r = socket_read_message(nl);
                if (r < 0)
                        return r;
                if (r > 0)
                        /* received message, so try to process straight away */
                        continue;

                if (usec != USEC_INFINITY) {
                        usec_t n;

                        n = netlink_now(nl, CLOCK_MONOTONIC);
                        if (n >= usec)
                                return -ETIMEDOUT;

                        left = usec_sub_unsigned(usec, n);
                } else
                        left = USEC_INFINITY;

                r = netlink_poll(nl, true, left);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ETIMEDOUT;
        }
}

int sd_netlink_call(
                sd_netlink *nl,
                sd_netlink_message *message,
                uint64_t timeout,
                sd_netlink_message **ret) {

        uint32_t serial;
        int r;

        assert_return(nl, -EINVAL);
        assert_return(!netlink_pid_changed(nl), -ECHILD);
        assert_return(message, -EINVAL);

        r = sd_netlink_send(nl, message, &serial);
        if (r < 0)
                return r;

        return sd_netlink_read(nl, serial, timeout, ret);
}

int sd_netlink_get_events(sd_netlink *nl) {
        assert_return(nl, -EINVAL);
        assert_return(!netlink_pid_changed(nl), -ECHILD);

        return ordered_set_isempty(nl->rqueue) ? POLLIN : 0;
}

int sd_netlink_get_timeout(sd_netlink *nl, uint64_t *ret) {
        struct reply_callback *c;

        assert_return(nl, -EINVAL);
        assert_return(ret, -EINVAL);
        assert_return(!netlink_pid_changed(nl), -ECHILD);

        if (!ordered_set_isempty(nl->rqueue)) {
                *ret = 0;
                return 1;
        }

        c = prioq_peek(nl->reply_callbacks_prioq);
        if (!c) {
                *ret = UINT64_MAX;
                return 0;
        }

        *ret = c->timeout;
        return 1;
}

static int io_callback(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_netlink *nl = ASSERT_PTR(userdata);
        int r;

        r = sd_netlink_process(nl, NULL);
        if (r < 0)
                return r;

        return 1;
}

static int time_callback(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_netlink *nl = ASSERT_PTR(userdata);
        int r;

        r = sd_netlink_process(nl, NULL);
        if (r < 0)
                return r;

        return 1;
}

static int prepare_callback(sd_event_source *s, void *userdata) {
        sd_netlink *nl = ASSERT_PTR(userdata);
        int r, enabled;
        usec_t until;

        assert(s);

        r = sd_netlink_get_events(nl);
        if (r < 0)
                return r;

        r = sd_event_source_set_io_events(nl->io_event_source, r);
        if (r < 0)
                return r;

        enabled = sd_netlink_get_timeout(nl, &until);
        if (enabled < 0)
                return enabled;
        if (enabled > 0) {
                r = sd_event_source_set_time(nl->time_event_source, until);
                if (r < 0)
                        return r;
        }

        r = sd_event_source_set_enabled(nl->time_event_source,
                                        enabled > 0 ? SD_EVENT_ONESHOT : SD_EVENT_OFF);
        if (r < 0)
                return r;

        return 1;
}

int sd_netlink_attach_event(sd_netlink *nl, sd_event *event, int64_t priority) {
        int r;

        assert_return(nl, -EINVAL);
        assert_return(!nl->event, -EBUSY);

        assert(!nl->io_event_source);
        assert(!nl->time_event_source);

        if (event)
                nl->event = sd_event_ref(event);
        else {
                r = sd_event_default(&nl->event);
                if (r < 0)
                        return r;
        }

        r = sd_event_add_io(nl->event, &nl->io_event_source, nl->fd, 0, io_callback, nl);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(nl->io_event_source, priority);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_description(nl->io_event_source, "netlink-receive-message");
        if (r < 0)
                goto fail;

        r = sd_event_source_set_prepare(nl->io_event_source, prepare_callback);
        if (r < 0)
                goto fail;

        r = sd_event_add_time(nl->event, &nl->time_event_source, CLOCK_MONOTONIC, 0, 0, time_callback, nl);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(nl->time_event_source, priority);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_description(nl->time_event_source, "netlink-timer");
        if (r < 0)
                goto fail;

        return 0;

fail:
        sd_netlink_detach_event(nl);
        return r;
}

int sd_netlink_detach_event(sd_netlink *nl) {
        assert_return(nl, -EINVAL);
        assert_return(nl->event, -ENXIO);

        nl->io_event_source = sd_event_source_unref(nl->io_event_source);

        nl->time_event_source = sd_event_source_unref(nl->time_event_source);

        nl->event = sd_event_unref(nl->event);

        return 0;
}

sd_event* sd_netlink_get_event(sd_netlink *nl) {
        assert_return(nl, NULL);

        return nl->event;
}

int netlink_add_match_internal(
                sd_netlink *nl,
                sd_netlink_slot **ret_slot,
                const uint32_t *groups,
                size_t n_groups,
                uint16_t type,
                uint8_t cmd,
                sd_netlink_message_handler_t callback,
                sd_netlink_destroy_t destroy_callback,
                void *userdata,
                const char *description) {

        _cleanup_free_ sd_netlink_slot *slot = NULL;
        int r;

        assert(groups);
        assert(n_groups > 0);

        for (size_t i = 0; i < n_groups; i++) {
                r = socket_broadcast_group_ref(nl, groups[i]);
                if (r < 0)
                        return r;
        }

        r = netlink_slot_allocate(nl, !ret_slot, NETLINK_MATCH_CALLBACK, sizeof(struct match_callback),
                                  userdata, description, &slot);
        if (r < 0)
                return r;

        slot->match_callback.groups = newdup(uint32_t, groups, n_groups);
        if (!slot->match_callback.groups)
                return -ENOMEM;

        slot->match_callback.n_groups = n_groups;
        slot->match_callback.callback = callback;
        slot->match_callback.type = type;
        slot->match_callback.cmd = cmd;

        LIST_PREPEND(match_callbacks, nl->match_callbacks, &slot->match_callback);

        /* Set this at last. Otherwise, some failures in above call the destroy callback but some do not. */
        slot->destroy_callback = destroy_callback;

        if (ret_slot)
                *ret_slot = slot;

        TAKE_PTR(slot);
        return 0;
}

int sd_netlink_add_match(
                sd_netlink *rtnl,
                sd_netlink_slot **ret_slot,
                uint16_t type,
                sd_netlink_message_handler_t callback,
                sd_netlink_destroy_t destroy_callback,
                void *userdata,
                const char *description) {

        static const uint32_t
                address_groups[]  = { RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR, },
                link_groups[]     = { RTNLGRP_LINK, },
                neighbor_groups[] = { RTNLGRP_NEIGH, },
                nexthop_groups[]  = { RTNLGRP_NEXTHOP, },
                route_groups[]    = { RTNLGRP_IPV4_ROUTE, RTNLGRP_IPV6_ROUTE, },
                rule_groups[]     = { RTNLGRP_IPV4_RULE, RTNLGRP_IPV6_RULE, },
                tc_groups[]       = { RTNLGRP_TC };
        const uint32_t *groups;
        size_t n_groups;

        assert_return(rtnl, -EINVAL);
        assert_return(callback, -EINVAL);
        assert_return(!netlink_pid_changed(rtnl), -ECHILD);

        switch (type) {
                case RTM_NEWLINK:
                case RTM_DELLINK:
                        groups = link_groups;
                        n_groups = ELEMENTSOF(link_groups);
                        break;
                case RTM_NEWADDR:
                case RTM_DELADDR:
                        groups = address_groups;
                        n_groups = ELEMENTSOF(address_groups);
                        break;
                case RTM_NEWNEIGH:
                case RTM_DELNEIGH:
                        groups = neighbor_groups;
                        n_groups = ELEMENTSOF(neighbor_groups);
                        break;
                case RTM_NEWROUTE:
                case RTM_DELROUTE:
                        groups = route_groups;
                        n_groups = ELEMENTSOF(route_groups);
                        break;
                case RTM_NEWRULE:
                case RTM_DELRULE:
                        groups = rule_groups;
                        n_groups = ELEMENTSOF(rule_groups);
                        break;
                case RTM_NEWNEXTHOP:
                case RTM_DELNEXTHOP:
                        groups = nexthop_groups;
                        n_groups = ELEMENTSOF(nexthop_groups);
                        break;
                case RTM_NEWQDISC:
                case RTM_DELQDISC:
                case RTM_NEWTCLASS:
                case RTM_DELTCLASS:
                        groups = tc_groups;
                        n_groups = ELEMENTSOF(tc_groups);
                        break;
                default:
                        return -EOPNOTSUPP;
        }

        return netlink_add_match_internal(rtnl, ret_slot, groups, n_groups, type, 0, callback,
                                          destroy_callback, userdata, description);
}

int sd_netlink_attach_filter(sd_netlink *nl, size_t len, const struct sock_filter *filter) {
        assert_return(nl, -EINVAL);
        assert_return(len == 0 || filter, -EINVAL);

        if (setsockopt(nl->fd, SOL_SOCKET,
                       len == 0 ? SO_DETACH_FILTER : SO_ATTACH_FILTER,
                       &(struct sock_fprog) {
                               .len = len,
                               .filter = (struct sock_filter*) filter,
                       }, sizeof(struct sock_fprog)) < 0)
                return -errno;

        return 0;
}
