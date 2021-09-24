/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>

#include "sd-lldp.h"

#include "alloc-util.h"
#include "ether-addr-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "lldp-internal.h"
#include "lldp-neighbor.h"
#include "lldp-network.h"
#include "memory-util.h"
#include "network-common.h"
#include "socket-util.h"
#include "sort-util.h"
#include "string-table.h"

#define LLDP_DEFAULT_NEIGHBORS_MAX 128U

static const char * const lldp_event_table[_SD_LLDP_EVENT_MAX] = {
        [SD_LLDP_EVENT_ADDED]     = "added",
        [SD_LLDP_EVENT_REMOVED]   = "removed",
        [SD_LLDP_EVENT_UPDATED]   = "updated",
        [SD_LLDP_EVENT_REFRESHED] = "refreshed",
};

DEFINE_STRING_TABLE_LOOKUP(lldp_event, sd_lldp_event_t);

static void lldp_flush_neighbors(sd_lldp *lldp) {
        assert(lldp);

        hashmap_clear(lldp->neighbor_by_id);
}

static void lldp_callback(sd_lldp *lldp, sd_lldp_event_t event, sd_lldp_neighbor *n) {
        assert(lldp);
        assert(event >= 0 && event < _SD_LLDP_EVENT_MAX);

        if (!lldp->callback)
                return (void) log_lldp(lldp, "Received '%s' event.", lldp_event_to_string(event));

        log_lldp(lldp, "Invoking callback for '%s' event.", lldp_event_to_string(event));
        lldp->callback(lldp, event, n, lldp->userdata);
}

static int lldp_make_space(sd_lldp *lldp, size_t extra) {
        usec_t t = USEC_INFINITY;
        bool changed = false;

        assert(lldp);

        /* Remove all entries that are past their TTL, and more until at least the specified number of extra entries
         * are free. */

        for (;;) {
                _cleanup_(sd_lldp_neighbor_unrefp) sd_lldp_neighbor *n = NULL;

                n = prioq_peek(lldp->neighbor_by_expiry);
                if (!n)
                        break;

                sd_lldp_neighbor_ref(n);

                if (hashmap_size(lldp->neighbor_by_id) > LESS_BY(lldp->neighbors_max, extra))
                        goto remove_one;

                if (t == USEC_INFINITY)
                        t = now(clock_boottime_or_monotonic());

                if (n->until > t)
                        break;

        remove_one:
                lldp_neighbor_unlink(n);
                lldp_callback(lldp, SD_LLDP_EVENT_REMOVED, n);
                changed = true;
        }

        return changed;
}

static bool lldp_keep_neighbor(sd_lldp *lldp, sd_lldp_neighbor *n) {
        assert(lldp);
        assert(n);

        /* Don't keep data with a zero TTL */
        if (n->ttl <= 0)
                return false;

        /* Filter out data from the filter address */
        if (!ether_addr_is_null(&lldp->filter_address) &&
            ether_addr_equal(&lldp->filter_address, &n->source_address))
                return false;

        /* Only add if the neighbor has a capability we are interested in. Note that we also store all neighbors with
         * no caps field set. */
        if (n->has_capabilities &&
            (n->enabled_capabilities & lldp->capability_mask) == 0)
                return false;

        /* Keep everything else */
        return true;
}

static int lldp_start_timer(sd_lldp *lldp, sd_lldp_neighbor *neighbor);

static int lldp_add_neighbor(sd_lldp *lldp, sd_lldp_neighbor *n) {
        _cleanup_(sd_lldp_neighbor_unrefp) sd_lldp_neighbor *old = NULL;
        bool keep;
        int r;

        assert(lldp);
        assert(n);
        assert(!n->lldp);

        keep = lldp_keep_neighbor(lldp, n);

        /* First retrieve the old entry for this MSAP */
        old = hashmap_get(lldp->neighbor_by_id, &n->id);
        if (old) {
                sd_lldp_neighbor_ref(old);

                if (!keep) {
                        lldp_neighbor_unlink(old);
                        lldp_callback(lldp, SD_LLDP_EVENT_REMOVED, old);
                        return 0;
                }

                if (lldp_neighbor_equal(n, old)) {
                        /* Is this equal, then restart the TTL counter, but don't do anything else. */
                        old->timestamp = n->timestamp;
                        lldp_start_timer(lldp, old);
                        lldp_callback(lldp, SD_LLDP_EVENT_REFRESHED, old);
                        return 0;
                }

                /* Data changed, remove the old entry, and add a new one */
                lldp_neighbor_unlink(old);

        } else if (!keep)
                return 0;

        /* Then, make room for at least one new neighbor */
        lldp_make_space(lldp, 1);

        r = hashmap_put(lldp->neighbor_by_id, &n->id, n);
        if (r < 0)
                goto finish;

        r = prioq_put(lldp->neighbor_by_expiry, n, &n->prioq_idx);
        if (r < 0) {
                assert_se(hashmap_remove(lldp->neighbor_by_id, &n->id) == n);
                goto finish;
        }

        n->lldp = lldp;

        lldp_start_timer(lldp, n);
        lldp_callback(lldp, old ? SD_LLDP_EVENT_UPDATED : SD_LLDP_EVENT_ADDED, n);

        return 1;

finish:
        if (old)
                lldp_callback(lldp, SD_LLDP_EVENT_REMOVED, old);

        return r;
}

static int lldp_handle_datagram(sd_lldp *lldp, sd_lldp_neighbor *n) {
        int r;

        assert(lldp);
        assert(n);

        r = lldp_neighbor_parse(n);
        if (r == -EBADMSG) /* Ignore bad messages */
                return 0;
        if (r < 0)
                return r;

        r = lldp_add_neighbor(lldp, n);
        if (r < 0) {
                log_lldp_errno(lldp, r, "Failed to add datagram. Ignoring.");
                return 0;
        }

        log_lldp(lldp, "Successfully processed LLDP datagram.");
        return 0;
}

static int lldp_receive_datagram(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(sd_lldp_neighbor_unrefp) sd_lldp_neighbor *n = NULL;
        ssize_t space, length;
        sd_lldp *lldp = userdata;
        struct timespec ts;

        assert(fd >= 0);
        assert(lldp);

        space = next_datagram_size_fd(fd);
        if (space < 0) {
                log_lldp_errno(lldp, space, "Failed to determine datagram size to read, ignoring: %m");
                return 0;
        }

        n = lldp_neighbor_new(space);
        if (!n)
                return -ENOMEM;

        length = recv(fd, LLDP_NEIGHBOR_RAW(n), n->raw_size, MSG_DONTWAIT);
        if (length < 0) {
                if (IN_SET(errno, EAGAIN, EINTR))
                        return 0;

                log_lldp_errno(lldp, errno, "Failed to read LLDP datagram, ignoring: %m");
                return 0;
        }

        if ((size_t) length != n->raw_size) {
                log_lldp(lldp, "Packet size mismatch, ignoring");
                return 0;
        }

        /* Try to get the timestamp of this packet if it is known */
        if (ioctl(fd, SIOCGSTAMPNS, &ts) >= 0)
                triple_timestamp_from_realtime(&n->timestamp, timespec_load(&ts));
        else
                triple_timestamp_get(&n->timestamp);

        return lldp_handle_datagram(lldp, n);
}

static void lldp_reset(sd_lldp *lldp) {
        assert(lldp);

        (void) event_source_disable(lldp->timer_event_source);
        lldp->io_event_source = sd_event_source_disable_unref(lldp->io_event_source);
        lldp->fd = safe_close(lldp->fd);
}

_public_ int sd_lldp_start(sd_lldp *lldp) {
        int r;

        assert_return(lldp, -EINVAL);
        assert_return(lldp->event, -EINVAL);
        assert_return(lldp->ifindex > 0, -EINVAL);

        if (lldp->fd >= 0)
                return 0;

        assert(!lldp->io_event_source);

        lldp->fd = lldp_network_bind_raw_socket(lldp->ifindex);
        if (lldp->fd < 0)
                return lldp->fd;

        r = sd_event_add_io(lldp->event, &lldp->io_event_source, lldp->fd, EPOLLIN, lldp_receive_datagram, lldp);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(lldp->io_event_source, lldp->event_priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(lldp->io_event_source, "lldp-io");

        log_lldp(lldp, "Started LLDP client");
        return 1;

fail:
        lldp_reset(lldp);
        return r;
}

_public_ int sd_lldp_stop(sd_lldp *lldp) {
        if (!lldp)
                return 0;

        if (lldp->fd < 0)
                return 0;

        log_lldp(lldp, "Stopping LLDP client");

        lldp_reset(lldp);
        lldp_flush_neighbors(lldp);

        return 1;
}

_public_ int sd_lldp_attach_event(sd_lldp *lldp, sd_event *event, int64_t priority) {
        int r;

        assert_return(lldp, -EINVAL);
        assert_return(lldp->fd < 0, -EBUSY);
        assert_return(!lldp->event, -EBUSY);

        if (event)
                lldp->event = sd_event_ref(event);
        else {
                r = sd_event_default(&lldp->event);
                if (r < 0)
                        return r;
        }

        lldp->event_priority = priority;

        return 0;
}

_public_ int sd_lldp_detach_event(sd_lldp *lldp) {

        assert_return(lldp, -EINVAL);
        assert_return(lldp->fd < 0, -EBUSY);

        lldp->event = sd_event_unref(lldp->event);
        return 0;
}

_public_ sd_event* sd_lldp_get_event(sd_lldp *lldp) {
        assert_return(lldp, NULL);

        return lldp->event;
}

_public_ int sd_lldp_set_callback(sd_lldp *lldp, sd_lldp_callback_t cb, void *userdata) {
        assert_return(lldp, -EINVAL);

        lldp->callback = cb;
        lldp->userdata = userdata;

        return 0;
}

_public_ int sd_lldp_set_ifindex(sd_lldp *lldp, int ifindex) {
        assert_return(lldp, -EINVAL);
        assert_return(ifindex > 0, -EINVAL);
        assert_return(lldp->fd < 0, -EBUSY);

        lldp->ifindex = ifindex;
        return 0;
}

int sd_lldp_set_ifname(sd_lldp *lldp, const char *ifname) {
        assert_return(lldp, -EINVAL);
        assert_return(ifname, -EINVAL);

        if (!ifname_valid_full(ifname, IFNAME_VALID_ALTERNATIVE))
                return -EINVAL;

        return free_and_strdup(&lldp->ifname, ifname);
}

const char *sd_lldp_get_ifname(sd_lldp *lldp) {
        if (!lldp)
                return NULL;

        return get_ifname(lldp->ifindex, &lldp->ifname);
}

static sd_lldp* lldp_free(sd_lldp *lldp) {
        assert(lldp);

        lldp_reset(lldp);

        sd_event_source_unref(lldp->timer_event_source);
        sd_lldp_detach_event(lldp);

        lldp_flush_neighbors(lldp);

        hashmap_free(lldp->neighbor_by_id);
        prioq_free(lldp->neighbor_by_expiry);
        free(lldp->ifname);
        return mfree(lldp);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_lldp, sd_lldp, lldp_free);

_public_ int sd_lldp_new(sd_lldp **ret) {
        _cleanup_(sd_lldp_unrefp) sd_lldp *lldp = NULL;
        int r;

        assert_return(ret, -EINVAL);

        lldp = new(sd_lldp, 1);
        if (!lldp)
                return -ENOMEM;

        *lldp = (sd_lldp) {
                .n_ref = 1,
                .fd = -1,
                .neighbors_max = LLDP_DEFAULT_NEIGHBORS_MAX,
                .capability_mask = UINT16_MAX,
        };

        lldp->neighbor_by_id = hashmap_new(&lldp_neighbor_hash_ops);
        if (!lldp->neighbor_by_id)
                return -ENOMEM;

        r = prioq_ensure_allocated(&lldp->neighbor_by_expiry, lldp_neighbor_prioq_compare_func);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(lldp);

        return 0;
}

static int neighbor_compare_func(sd_lldp_neighbor * const *a, sd_lldp_neighbor * const *b) {
        return lldp_neighbor_id_compare_func(&(*a)->id, &(*b)->id);
}

static int on_timer_event(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_lldp *lldp = userdata;
        int r;

        r = lldp_make_space(lldp, 0);
        if (r < 0) {
                log_lldp_errno(lldp, r, "Failed to make space, ignoring: %m");
                return 0;
        }

        r = lldp_start_timer(lldp, NULL);
        if (r < 0) {
                log_lldp_errno(lldp, r, "Failed to restart timer, ignoring: %m");
                return 0;
        }

        return 0;
}

static int lldp_start_timer(sd_lldp *lldp, sd_lldp_neighbor *neighbor) {
        sd_lldp_neighbor *n;

        assert(lldp);

        if (neighbor)
                lldp_neighbor_start_ttl(neighbor);

        n = prioq_peek(lldp->neighbor_by_expiry);
        if (!n)
                return event_source_disable(lldp->timer_event_source);

        if (!lldp->event)
                return 0;

        return event_reset_time(lldp->event, &lldp->timer_event_source,
                                clock_boottime_or_monotonic(),
                                n->until, 0,
                                on_timer_event, lldp,
                                lldp->event_priority, "lldp-timer", true);
}

_public_ int sd_lldp_get_neighbors(sd_lldp *lldp, sd_lldp_neighbor ***ret) {
        sd_lldp_neighbor **l = NULL, *n;
        int k = 0, r;

        assert_return(lldp, -EINVAL);
        assert_return(ret, -EINVAL);

        if (hashmap_isempty(lldp->neighbor_by_id)) { /* Special shortcut */
                *ret = NULL;
                return 0;
        }

        l = new0(sd_lldp_neighbor*, hashmap_size(lldp->neighbor_by_id));
        if (!l)
                return -ENOMEM;

        r = lldp_start_timer(lldp, NULL);
        if (r < 0) {
                free(l);
                return r;
        }

        HASHMAP_FOREACH(n, lldp->neighbor_by_id)
                l[k++] = sd_lldp_neighbor_ref(n);

        assert((size_t) k == hashmap_size(lldp->neighbor_by_id));

        /* Return things in a stable order */
        typesafe_qsort(l, k, neighbor_compare_func);
        *ret = l;

        return k;
}

_public_ int sd_lldp_set_neighbors_max(sd_lldp *lldp, uint64_t m) {
        assert_return(lldp, -EINVAL);
        assert_return(m > 0, -EINVAL);

        lldp->neighbors_max = m;
        lldp_make_space(lldp, 0);

        return 0;
}

_public_ int sd_lldp_match_capabilities(sd_lldp *lldp, uint16_t mask) {
        assert_return(lldp, -EINVAL);
        assert_return(mask != 0, -EINVAL);

        lldp->capability_mask = mask;

        return 0;
}

_public_ int sd_lldp_set_filter_address(sd_lldp *lldp, const struct ether_addr *addr) {
        assert_return(lldp, -EINVAL);

        /* In order to deal nicely with bridges that send back our own packets, allow one address to be filtered, so
         * that our own can be filtered out here. */

        if (addr)
                lldp->filter_address = *addr;
        else
                zero(lldp->filter_address);

        return 0;
}
