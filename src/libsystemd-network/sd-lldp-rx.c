/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>

#include "sd-json.h"
#include "sd-lldp-rx.h"

#include "alloc-util.h"
#include "ether-addr-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "lldp-neighbor.h"
#include "lldp-network.h"
#include "lldp-rx-internal.h"
#include "memory-util.h"
#include "network-common.h"
#include "socket-util.h"
#include "sort-util.h"
#include "string-table.h"

#define LLDP_DEFAULT_NEIGHBORS_MAX 128U

static const char * const lldp_rx_event_table[_SD_LLDP_RX_EVENT_MAX] = {
        [SD_LLDP_RX_EVENT_ADDED]     = "added",
        [SD_LLDP_RX_EVENT_REMOVED]   = "removed",
        [SD_LLDP_RX_EVENT_UPDATED]   = "updated",
        [SD_LLDP_RX_EVENT_REFRESHED] = "refreshed",
};

DEFINE_STRING_TABLE_LOOKUP(lldp_rx_event, sd_lldp_rx_event_t);

static void lldp_rx_flush_neighbors(sd_lldp_rx *lldp_rx) {
        assert(lldp_rx);

        hashmap_clear(lldp_rx->neighbor_by_id);
}

static void lldp_rx_callback(sd_lldp_rx *lldp_rx, sd_lldp_rx_event_t event, sd_lldp_neighbor *n) {
        assert(lldp_rx);
        assert(event >= 0 && event < _SD_LLDP_RX_EVENT_MAX);

        if (!lldp_rx->callback)
                return (void) log_lldp_rx(lldp_rx, "Received '%s' event.", lldp_rx_event_to_string(event));

        log_lldp_rx(lldp_rx, "Invoking callback for '%s' event.", lldp_rx_event_to_string(event));
        lldp_rx->callback(lldp_rx, event, n, lldp_rx->userdata);
}

static int lldp_rx_make_space(sd_lldp_rx *lldp_rx, size_t extra) {
        usec_t t = USEC_INFINITY;
        bool changed = false;

        assert(lldp_rx);

        /* Remove all entries that are past their TTL, and more until at least the specified number of extra entries
         * are free. */

        for (;;) {
                _cleanup_(sd_lldp_neighbor_unrefp) sd_lldp_neighbor *n = NULL;

                n = prioq_peek(lldp_rx->neighbor_by_expiry);
                if (!n)
                        break;

                sd_lldp_neighbor_ref(n);

                if (hashmap_size(lldp_rx->neighbor_by_id) > LESS_BY(lldp_rx->neighbors_max, extra))
                        goto remove_one;

                if (t == USEC_INFINITY)
                        t = now(CLOCK_BOOTTIME);

                if (n->until > t)
                        break;

        remove_one:
                lldp_neighbor_unlink(n);
                lldp_rx_callback(lldp_rx, SD_LLDP_RX_EVENT_REMOVED, n);
                changed = true;
        }

        return changed;
}

static bool lldp_rx_keep_neighbor(sd_lldp_rx *lldp_rx, sd_lldp_neighbor *n) {
        assert(lldp_rx);
        assert(n);

        /* Don't keep data with a zero TTL */
        if (n->ttl <= 0)
                return false;

        /* Filter out data from the filter address */
        if (!ether_addr_is_null(&lldp_rx->filter_address) &&
            ether_addr_equal(&lldp_rx->filter_address, &n->source_address))
                return false;

        /* Only add if the neighbor has a capability we are interested in. Note that we also store all neighbors with
         * no caps field set. */
        if (n->has_capabilities &&
            (n->enabled_capabilities & lldp_rx->capability_mask) == 0)
                return false;

        /* Keep everything else */
        return true;
}

static int lldp_rx_start_timer(sd_lldp_rx *lldp_rx, sd_lldp_neighbor *neighbor);

static int lldp_rx_add_neighbor(sd_lldp_rx *lldp_rx, sd_lldp_neighbor *n) {
        _cleanup_(sd_lldp_neighbor_unrefp) sd_lldp_neighbor *old = NULL;
        bool keep;
        int r;

        assert(lldp_rx);
        assert(n);
        assert(!n->lldp_rx);

        keep = lldp_rx_keep_neighbor(lldp_rx, n);

        /* First retrieve the old entry for this MSAP */
        old = hashmap_get(lldp_rx->neighbor_by_id, &n->id);
        if (old) {
                sd_lldp_neighbor_ref(old);

                if (!keep) {
                        lldp_neighbor_unlink(old);
                        lldp_rx_callback(lldp_rx, SD_LLDP_RX_EVENT_REMOVED, old);
                        return 0;
                }

                if (lldp_neighbor_equal(n, old)) {
                        /* Is this equal, then restart the TTL counter, but don't do anything else. */
                        old->timestamp = n->timestamp;
                        lldp_rx_start_timer(lldp_rx, old);
                        lldp_rx_callback(lldp_rx, SD_LLDP_RX_EVENT_REFRESHED, old);
                        return 0;
                }

                /* Data changed, remove the old entry, and add a new one */
                lldp_neighbor_unlink(old);

        } else if (!keep)
                return 0;

        /* Then, make room for at least one new neighbor */
        lldp_rx_make_space(lldp_rx, 1);

        r = hashmap_ensure_put(&lldp_rx->neighbor_by_id, &lldp_neighbor_hash_ops, &n->id, n);
        if (r < 0)
                goto finish;

        r = prioq_ensure_put(&lldp_rx->neighbor_by_expiry, lldp_neighbor_prioq_compare_func, n, &n->prioq_idx);
        if (r < 0) {
                assert_se(hashmap_remove(lldp_rx->neighbor_by_id, &n->id) == n);
                goto finish;
        }

        n->lldp_rx = lldp_rx;

        lldp_rx_start_timer(lldp_rx, n);
        lldp_rx_callback(lldp_rx, old ? SD_LLDP_RX_EVENT_UPDATED : SD_LLDP_RX_EVENT_ADDED, n);

        return 1;

finish:
        if (old)
                lldp_rx_callback(lldp_rx, SD_LLDP_RX_EVENT_REMOVED, old);

        return r;
}

static int lldp_rx_handle_datagram(sd_lldp_rx *lldp_rx, sd_lldp_neighbor *n) {
        int r;

        assert(lldp_rx);
        assert(n);

        r = lldp_neighbor_parse(n);
        if (r < 0)
                return r;

        r = lldp_rx_add_neighbor(lldp_rx, n);
        if (r < 0)
                return log_lldp_rx_errno(lldp_rx, r, "Failed to add datagram. Ignoring.");

        log_lldp_rx(lldp_rx, "Successfully processed LLDP datagram.");
        return 0;
}

static int lldp_rx_receive_datagram(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(sd_lldp_neighbor_unrefp) sd_lldp_neighbor *n = NULL;
        ssize_t space, length;
        sd_lldp_rx *lldp_rx = ASSERT_PTR(userdata);
        struct timespec ts;

        assert(fd >= 0);

        space = next_datagram_size_fd(fd);
        if (ERRNO_IS_NEG_TRANSIENT(space) || ERRNO_IS_NEG_DISCONNECT(space))
                return 0;
        if (space < 0) {
                log_lldp_rx_errno(lldp_rx, space, "Failed to determine datagram size to read, ignoring: %m");
                return 0;
        }

        n = lldp_neighbor_new(space);
        if (!n) {
                log_oom_debug();
                return 0;
        }

        length = recv(fd, LLDP_NEIGHBOR_RAW(n), n->raw_size, MSG_DONTWAIT);
        if (length < 0) {
                if (ERRNO_IS_TRANSIENT(errno) || ERRNO_IS_DISCONNECT(errno))
                        return 0;

                log_lldp_rx_errno(lldp_rx, errno, "Failed to read LLDP datagram, ignoring: %m");
                return 0;
        }

        if ((size_t) length != n->raw_size) {
                log_lldp_rx(lldp_rx, "Packet size mismatch, ignoring");
                return 0;
        }

        /* Try to get the timestamp of this packet if it is known */
        if (ioctl(fd, SIOCGSTAMPNS, &ts) >= 0)
                triple_timestamp_from_realtime(&n->timestamp, timespec_load(&ts));
        else
                triple_timestamp_now(&n->timestamp);

        (void) lldp_rx_handle_datagram(lldp_rx, n);
        return 0;
}

static void lldp_rx_reset(sd_lldp_rx *lldp_rx) {
        assert(lldp_rx);

        (void) event_source_disable(lldp_rx->timer_event_source);
        lldp_rx->io_event_source = sd_event_source_disable_unref(lldp_rx->io_event_source);
        lldp_rx->fd = safe_close(lldp_rx->fd);
}

int sd_lldp_rx_is_running(sd_lldp_rx *lldp_rx) {
        if (!lldp_rx)
                return false;

        return lldp_rx->fd >= 0;
}

int sd_lldp_rx_start(sd_lldp_rx *lldp_rx) {
        int r;

        assert_return(lldp_rx, -EINVAL);
        assert_return(lldp_rx->event, -EINVAL);
        assert_return(lldp_rx->ifindex > 0, -EINVAL);

        if (sd_lldp_rx_is_running(lldp_rx))
                return 0;

        assert(!lldp_rx->io_event_source);

        lldp_rx->fd = lldp_network_bind_raw_socket(lldp_rx->ifindex);
        if (lldp_rx->fd < 0)
                return lldp_rx->fd;

        r = sd_event_add_io(lldp_rx->event, &lldp_rx->io_event_source, lldp_rx->fd, EPOLLIN, lldp_rx_receive_datagram, lldp_rx);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(lldp_rx->io_event_source, lldp_rx->event_priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(lldp_rx->io_event_source, "lldp-rx-io");

        log_lldp_rx(lldp_rx, "Started LLDP client");
        return 1;

fail:
        lldp_rx_reset(lldp_rx);
        return r;
}

int sd_lldp_rx_stop(sd_lldp_rx *lldp_rx) {
        if (!sd_lldp_rx_is_running(lldp_rx))
                return 0;

        log_lldp_rx(lldp_rx, "Stopping LLDP client");

        lldp_rx_reset(lldp_rx);
        lldp_rx_flush_neighbors(lldp_rx);

        return 1;
}

int sd_lldp_rx_attach_event(sd_lldp_rx *lldp_rx, sd_event *event, int64_t priority) {
        int r;

        assert_return(lldp_rx, -EINVAL);
        assert_return(!sd_lldp_rx_is_running(lldp_rx), -EBUSY);
        assert_return(!lldp_rx->event, -EBUSY);

        if (event)
                lldp_rx->event = sd_event_ref(event);
        else {
                r = sd_event_default(&lldp_rx->event);
                if (r < 0)
                        return r;
        }

        lldp_rx->event_priority = priority;

        return 0;
}

int sd_lldp_rx_detach_event(sd_lldp_rx *lldp_rx) {
        assert_return(lldp_rx, -EINVAL);
        assert_return(!sd_lldp_rx_is_running(lldp_rx), -EBUSY);

        lldp_rx->io_event_source = sd_event_source_disable_unref(lldp_rx->io_event_source);
        lldp_rx->timer_event_source = sd_event_source_disable_unref(lldp_rx->timer_event_source);
        lldp_rx->event = sd_event_unref(lldp_rx->event);
        return 0;
}

sd_event* sd_lldp_rx_get_event(sd_lldp_rx *lldp_rx) {
        assert_return(lldp_rx, NULL);

        return lldp_rx->event;
}

int sd_lldp_rx_set_callback(sd_lldp_rx *lldp_rx, sd_lldp_rx_callback_t cb, void *userdata) {
        assert_return(lldp_rx, -EINVAL);

        lldp_rx->callback = cb;
        lldp_rx->userdata = userdata;

        return 0;
}

int sd_lldp_rx_set_ifindex(sd_lldp_rx *lldp_rx, int ifindex) {
        assert_return(lldp_rx, -EINVAL);
        assert_return(ifindex > 0, -EINVAL);
        assert_return(!sd_lldp_rx_is_running(lldp_rx), -EBUSY);

        lldp_rx->ifindex = ifindex;
        return 0;
}

int sd_lldp_rx_set_ifname(sd_lldp_rx *lldp_rx, const char *ifname) {
        assert_return(lldp_rx, -EINVAL);
        assert_return(ifname, -EINVAL);

        if (!ifname_valid_full(ifname, IFNAME_VALID_ALTERNATIVE))
                return -EINVAL;

        return free_and_strdup(&lldp_rx->ifname, ifname);
}

int sd_lldp_rx_get_ifname(sd_lldp_rx *lldp_rx, const char **ret) {
        int r;

        assert_return(lldp_rx, -EINVAL);

        r = get_ifname(lldp_rx->ifindex, &lldp_rx->ifname);
        if (r < 0)
                return r;

        if (ret)
                *ret = lldp_rx->ifname;

        return 0;
}

static sd_lldp_rx *lldp_rx_free(sd_lldp_rx *lldp_rx) {
        if (!lldp_rx)
                return NULL;

        lldp_rx_reset(lldp_rx);

        sd_lldp_rx_detach_event(lldp_rx);

        lldp_rx_flush_neighbors(lldp_rx);

        hashmap_free(lldp_rx->neighbor_by_id);
        prioq_free(lldp_rx->neighbor_by_expiry);
        free(lldp_rx->ifname);
        return mfree(lldp_rx);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_lldp_rx, sd_lldp_rx, lldp_rx_free);

int sd_lldp_rx_new(sd_lldp_rx **ret) {
        _cleanup_(sd_lldp_rx_unrefp) sd_lldp_rx *lldp_rx = NULL;

        assert_return(ret, -EINVAL);

        lldp_rx = new(sd_lldp_rx, 1);
        if (!lldp_rx)
                return -ENOMEM;

        *lldp_rx = (sd_lldp_rx) {
                .n_ref = 1,
                .fd = -EBADF,
                .neighbors_max = LLDP_DEFAULT_NEIGHBORS_MAX,
                .capability_mask = UINT16_MAX,
        };

        *ret = TAKE_PTR(lldp_rx);
        return 0;
}

static int on_timer_event(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_lldp_rx *lldp_rx = userdata;
        int r;

        r = lldp_rx_make_space(lldp_rx, 0);
        if (r < 0) {
                log_lldp_rx_errno(lldp_rx, r, "Failed to make space, ignoring: %m");
                return 0;
        }

        r = lldp_rx_start_timer(lldp_rx, NULL);
        if (r < 0) {
                log_lldp_rx_errno(lldp_rx, r, "Failed to restart timer, ignoring: %m");
                return 0;
        }

        return 0;
}

static int lldp_rx_start_timer(sd_lldp_rx *lldp_rx, sd_lldp_neighbor *neighbor) {
        sd_lldp_neighbor *n;

        assert(lldp_rx);
        assert(lldp_rx->event);

        if (neighbor)
                lldp_neighbor_start_ttl(neighbor);

        n = prioq_peek(lldp_rx->neighbor_by_expiry);
        if (!n)
                return event_source_disable(lldp_rx->timer_event_source);

        return event_reset_time(lldp_rx->event, &lldp_rx->timer_event_source,
                                CLOCK_BOOTTIME,
                                n->until, 0,
                                on_timer_event, lldp_rx,
                                lldp_rx->event_priority, "lldp-rx-timer", true);
}

static int neighbor_compare_func(sd_lldp_neighbor * const *a, sd_lldp_neighbor * const *b) {
        assert(a);
        assert(b);
        assert(*a);
        assert(*b);

        return lldp_neighbor_id_compare_func(&(*a)->id, &(*b)->id);
}

int sd_lldp_rx_get_neighbors(sd_lldp_rx *lldp_rx, sd_lldp_neighbor ***ret) {
        _cleanup_free_ sd_lldp_neighbor **l = NULL;
        sd_lldp_neighbor *n;
        int k = 0;

        assert_return(lldp_rx, -EINVAL);
        assert_return(ret, -EINVAL);

        if (hashmap_isempty(lldp_rx->neighbor_by_id)) { /* Special shortcut */
                *ret = NULL;
                return 0;
        }

        l = new0(sd_lldp_neighbor*, hashmap_size(lldp_rx->neighbor_by_id));
        if (!l)
                return -ENOMEM;

        HASHMAP_FOREACH(n, lldp_rx->neighbor_by_id)
                l[k++] = sd_lldp_neighbor_ref(n);

        assert((size_t) k == hashmap_size(lldp_rx->neighbor_by_id));

        /* Return things in a stable order */
        typesafe_qsort(l, k, neighbor_compare_func);
        *ret = TAKE_PTR(l);

        return k;
}

int lldp_rx_build_neighbors_json(sd_lldp_rx *lldp_rx, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(lldp_rx);
        assert(ret);

        sd_lldp_neighbor *n;
        HASHMAP_FOREACH(n, lldp_rx->neighbor_by_id) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;

                r = lldp_neighbor_build_json(n, &w);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(&v, w);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

int sd_lldp_rx_set_neighbors_max(sd_lldp_rx *lldp_rx, uint64_t m) {
        assert_return(lldp_rx, -EINVAL);
        assert_return(m > 0, -EINVAL);

        lldp_rx->neighbors_max = m;
        lldp_rx_make_space(lldp_rx, 0);

        return 0;
}

int sd_lldp_rx_match_capabilities(sd_lldp_rx *lldp_rx, uint16_t mask) {
        assert_return(lldp_rx, -EINVAL);
        assert_return(mask != 0, -EINVAL);

        lldp_rx->capability_mask = mask;

        return 0;
}

int sd_lldp_rx_set_filter_address(sd_lldp_rx *lldp_rx, const struct ether_addr *addr) {
        assert_return(lldp_rx, -EINVAL);

        /* In order to deal nicely with bridges that send back our own packets, allow one address to be filtered, so
         * that our own can be filtered out here. */

        if (addr)
                lldp_rx->filter_address = *addr;
        else
                zero(lldp_rx->filter_address);

        return 0;
}
