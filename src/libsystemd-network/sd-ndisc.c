/***
  This file is part of systemd.

  Copyright (C) 2014 Intel Corporation. All rights reserved.

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ioctl.h>

#include "sd-ndisc.h"

#include "alloc-util.h"
#include "async.h"
#include "icmp6-util.h"
#include "in-addr-util.h"
#include "list.h"
#include "socket-util.h"

#define NDISC_ROUTER_SOLICITATION_INTERVAL      4 * USEC_PER_SEC
#define NDISC_MAX_ROUTER_SOLICITATIONS          3

enum NDiscState {
        NDISC_STATE_IDLE,
        NDISC_STATE_SOLICITATION_SENT,
        NDISC_STATE_ADVERTISMENT_LISTEN,
        _NDISC_STATE_MAX,
        _NDISC_STATE_INVALID = -1,
};

#define IP6_MIN_MTU (unsigned)1280
#define ICMP6_RECV_SIZE (IP6_MIN_MTU - sizeof(struct ip6_hdr))
#define NDISC_OPT_LEN_UNITS 8

#define ND_RA_FLAG_PREF                0x18
#define ND_RA_FLAG_PREF_LOW            0x03
#define ND_RA_FLAG_PREF_MEDIUM         0x0
#define ND_RA_FLAG_PREF_HIGH           0x1
#define ND_RA_FLAG_PREF_INVALID        0x2

typedef struct NDiscPrefix NDiscPrefix;

struct NDiscPrefix {
        unsigned n_ref;

        sd_ndisc *nd;

        LIST_FIELDS(NDiscPrefix, prefixes);

        uint8_t len;
        usec_t valid_until;
        struct in6_addr addr;
};

struct sd_ndisc {
        unsigned n_ref;

        enum NDiscState state;
        sd_event *event;
        int event_priority;
        int index;
        struct ether_addr mac_addr;
        uint32_t mtu;
        LIST_HEAD(NDiscPrefix, prefixes);
        int fd;
        sd_event_source *recv;
        sd_event_source *timeout;
        int nd_sent;
        sd_ndisc_router_callback_t router_callback;
        sd_ndisc_prefix_autonomous_callback_t prefix_autonomous_callback;
        sd_ndisc_prefix_onlink_callback_t prefix_onlink_callback;
        sd_ndisc_callback_t callback;
        void *userdata;
};

#define log_ndisc(p, fmt, ...) log_internal(LOG_DEBUG, 0, __FILE__, __LINE__, __func__, "NDisc CLIENT: " fmt, ##__VA_ARGS__)

static NDiscPrefix *ndisc_prefix_unref(NDiscPrefix *prefix) {

        if (!prefix)
                return NULL;

        assert(prefix->n_ref > 0);
        prefix->n_ref--;

        if (prefix->n_ref > 0)
                return NULL;

        if (prefix->nd)
                LIST_REMOVE(prefixes, prefix->nd->prefixes, prefix);

        free(prefix);

        return NULL;
}

static int ndisc_prefix_new(sd_ndisc *nd, NDiscPrefix **ret) {
        _cleanup_free_ NDiscPrefix *prefix = NULL;

        assert(ret);

        prefix = new0(NDiscPrefix, 1);
        if (!prefix)
                return -ENOMEM;

        prefix->n_ref = 1;
        LIST_INIT(prefixes, prefix);
        prefix->nd = nd;

        *ret = prefix;
        prefix = NULL;

        return 0;
}

int sd_ndisc_set_callback(sd_ndisc *nd,
                          sd_ndisc_router_callback_t router_callback,
                          sd_ndisc_prefix_onlink_callback_t prefix_onlink_callback,
                          sd_ndisc_prefix_autonomous_callback_t prefix_autonomous_callback,
                          sd_ndisc_callback_t callback,
                          void *userdata) {
        assert(nd);

        nd->router_callback = router_callback;
        nd->prefix_onlink_callback = prefix_onlink_callback;
        nd->prefix_autonomous_callback = prefix_autonomous_callback;
        nd->callback = callback;
        nd->userdata = userdata;

        return 0;
}

int sd_ndisc_set_index(sd_ndisc *nd, int interface_index) {
        assert(nd);
        assert(interface_index >= -1);

        nd->index = interface_index;

        return 0;
}

int sd_ndisc_set_mac(sd_ndisc *nd, const struct ether_addr *mac_addr) {
        assert(nd);

        if (mac_addr)
                memcpy(&nd->mac_addr, mac_addr, sizeof(nd->mac_addr));
        else
                zero(nd->mac_addr);

        return 0;

}

int sd_ndisc_attach_event(sd_ndisc *nd, sd_event *event, int priority) {
        int r;

        assert_return(nd, -EINVAL);
        assert_return(!nd->event, -EBUSY);

        if (event)
                nd->event = sd_event_ref(event);
        else {
                r = sd_event_default(&nd->event);
                if (r < 0)
                        return 0;
        }

        nd->event_priority = priority;

        return 0;
}

int sd_ndisc_detach_event(sd_ndisc *nd) {
        assert_return(nd, -EINVAL);

        nd->event = sd_event_unref(nd->event);

        return 0;
}

sd_event *sd_ndisc_get_event(sd_ndisc *nd) {
        assert(nd);

        return nd->event;
}

sd_ndisc *sd_ndisc_ref(sd_ndisc *nd) {

        if (!nd)
                return NULL;

        assert(nd->n_ref > 0);
        nd->n_ref++;

        return nd;
}

static int ndisc_init(sd_ndisc *nd) {
        assert(nd);

        nd->recv = sd_event_source_unref(nd->recv);
        nd->fd = asynchronous_close(nd->fd);
        nd->timeout = sd_event_source_unref(nd->timeout);

        return 0;
}

sd_ndisc *sd_ndisc_unref(sd_ndisc *nd) {
        NDiscPrefix *prefix, *p;

        if (!nd)
                return NULL;

        assert(nd->n_ref > 0);
        nd->n_ref--;

        if (nd->n_ref > 0)
                return NULL;

        ndisc_init(nd);
        sd_ndisc_detach_event(nd);

        LIST_FOREACH_SAFE(prefixes, prefix, p, nd->prefixes)
                prefix = ndisc_prefix_unref(prefix);

        free(nd);

        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_ndisc*, sd_ndisc_unref);
#define _cleanup_sd_ndisc_free_ _cleanup_(sd_ndisc_unrefp)

int sd_ndisc_new(sd_ndisc **ret) {
        _cleanup_sd_ndisc_free_ sd_ndisc *nd = NULL;

        assert(ret);

        nd = new0(sd_ndisc, 1);
        if (!nd)
                return -ENOMEM;

        nd->n_ref = 1;

        nd->index = -1;
        nd->fd = -1;

        LIST_HEAD_INIT(nd->prefixes);

        *ret = nd;
        nd = NULL;

        return 0;
}

int sd_ndisc_get_mtu(sd_ndisc *nd, uint32_t *mtu) {
        assert_return(nd, -EINVAL);
        assert_return(mtu, -EINVAL);

        if (nd->mtu == 0)
                return -ENOMSG;

        *mtu = nd->mtu;

        return 0;
}

static int prefix_match(const struct in6_addr *prefix, uint8_t prefixlen,
                        const struct in6_addr *addr,
                        uint8_t addr_prefixlen) {
        uint8_t bytes, mask, len;

        assert_return(prefix, -EINVAL);
        assert_return(addr, -EINVAL);

        len = MIN(prefixlen, addr_prefixlen);

        bytes = len / 8;
        mask = 0xff << (8 - len % 8);

        if (memcmp(prefix, addr, bytes) != 0 ||
            (prefix->s6_addr[bytes] & mask) != (addr->s6_addr[bytes] & mask))
                return -EADDRNOTAVAIL;

        return 0;
}

static int ndisc_prefix_match(sd_ndisc *nd, const struct in6_addr *addr,
                              uint8_t addr_len, NDiscPrefix **result) {
        NDiscPrefix *prefix, *p;
        usec_t time_now;
        int r;

        assert(nd);

        r = sd_event_now(nd->event, clock_boottime_or_monotonic(), &time_now);
        if (r < 0)
                return r;

        LIST_FOREACH_SAFE(prefixes, prefix, p, nd->prefixes) {
                if (prefix->valid_until < time_now) {
                        prefix = ndisc_prefix_unref(prefix);

                        continue;
                }

                if (prefix_match(&prefix->addr, prefix->len, addr, addr_len) >= 0) {
                        *result = prefix;
                        return 0;
                }
        }

        return -EADDRNOTAVAIL;
}

static int ndisc_prefix_update(sd_ndisc *nd, ssize_t len,
                               const struct nd_opt_prefix_info *prefix_opt) {
        NDiscPrefix *prefix;
        uint32_t lifetime_valid, lifetime_preferred;
        usec_t time_now;
        char time_string[FORMAT_TIMESPAN_MAX];
        int r;

        assert(nd);
        assert(prefix_opt);

        if (len < prefix_opt->nd_opt_pi_len)
                return -ENOMSG;

        if (!(prefix_opt->nd_opt_pi_flags_reserved & (ND_OPT_PI_FLAG_ONLINK | ND_OPT_PI_FLAG_AUTO)))
                return 0;

        if (in_addr_is_link_local(AF_INET6, (const union in_addr_union *) &prefix_opt->nd_opt_pi_prefix) > 0)
                return 0;

        lifetime_valid = be32toh(prefix_opt->nd_opt_pi_valid_time);
        lifetime_preferred = be32toh(prefix_opt->nd_opt_pi_preferred_time);

        if (lifetime_valid < lifetime_preferred)
                return 0;

        r = ndisc_prefix_match(nd, &prefix_opt->nd_opt_pi_prefix,
                               prefix_opt->nd_opt_pi_prefix_len, &prefix);

        if (r < 0 && r != -EADDRNOTAVAIL)
                return r;

        /* if router advertisment prefix valid timeout is zero, the timeout
           callback will be called immediately to clean up the prefix */

        if (r == -EADDRNOTAVAIL) {
                r = ndisc_prefix_new(nd, &prefix);
                if (r < 0)
                        return r;

                prefix->len = prefix_opt->nd_opt_pi_prefix_len;

                memcpy(&prefix->addr, &prefix_opt->nd_opt_pi_prefix,
                        sizeof(prefix->addr));

                log_ndisc(nd, "New prefix "SD_NDISC_ADDRESS_FORMAT_STR"/%d lifetime %d expires in %s",
                             SD_NDISC_ADDRESS_FORMAT_VAL(prefix->addr),
                             prefix->len, lifetime_valid,
                             format_timespan(time_string, FORMAT_TIMESPAN_MAX, lifetime_valid * USEC_PER_SEC, USEC_PER_SEC));

                LIST_PREPEND(prefixes, nd->prefixes, prefix);

        } else {
                if (prefix->len != prefix_opt->nd_opt_pi_prefix_len) {
                        uint8_t prefixlen;

                        prefixlen = MIN(prefix->len, prefix_opt->nd_opt_pi_prefix_len);

                        log_ndisc(nd, "Prefix length mismatch %d/%d using %d",
                                     prefix->len,
                                     prefix_opt->nd_opt_pi_prefix_len,
                                     prefixlen);

                        prefix->len = prefixlen;
                }

                log_ndisc(nd, "Update prefix "SD_NDISC_ADDRESS_FORMAT_STR"/%d lifetime %d expires in %s",
                             SD_NDISC_ADDRESS_FORMAT_VAL(prefix->addr),
                             prefix->len, lifetime_valid,
                             format_timespan(time_string, FORMAT_TIMESPAN_MAX, lifetime_valid * USEC_PER_SEC, USEC_PER_SEC));
        }

        r = sd_event_now(nd->event, clock_boottime_or_monotonic(), &time_now);
        if (r < 0)
                return r;

        prefix->valid_until = time_now + lifetime_valid * USEC_PER_SEC;

        if ((prefix_opt->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_ONLINK) && nd->prefix_onlink_callback)
                nd->prefix_onlink_callback(nd, &prefix->addr, prefix->len, prefix->valid_until, nd->userdata);

        if ((prefix_opt->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_AUTO) && nd->prefix_autonomous_callback)
                nd->prefix_autonomous_callback(nd, &prefix->addr, prefix->len, lifetime_preferred, lifetime_valid,
                                               nd->userdata);

        return 0;
}

static int ndisc_ra_parse(sd_ndisc *nd, struct nd_router_advert *ra,
                          ssize_t len) {
        void *opt;
        struct nd_opt_hdr *opt_hdr;

        assert_return(nd, -EINVAL);
        assert_return(ra, -EINVAL);

        len -= sizeof(*ra);
        if (len < NDISC_OPT_LEN_UNITS) {
                log_ndisc(nd, "Router Advertisement below minimum length");

                return -ENOMSG;
        }

        opt = ra + 1;
        opt_hdr = opt;

        while (len != 0 && len >= opt_hdr->nd_opt_len * NDISC_OPT_LEN_UNITS) {
                struct nd_opt_mtu *opt_mtu;
                uint32_t mtu;
                struct nd_opt_prefix_info *opt_prefix;

                if (opt_hdr->nd_opt_len == 0)
                        return -ENOMSG;

                switch (opt_hdr->nd_opt_type) {
                case ND_OPT_MTU:
                        opt_mtu = opt;

                        mtu = be32toh(opt_mtu->nd_opt_mtu_mtu);

                        if (mtu != nd->mtu) {
                                nd->mtu = MAX(mtu, IP6_MIN_MTU);

                                log_ndisc(nd, "Router Advertisement link MTU %d using %d",
                                             mtu, nd->mtu);
                        }

                        break;

                case ND_OPT_PREFIX_INFORMATION:
                        opt_prefix = opt;

                        ndisc_prefix_update(nd, len, opt_prefix);

                        break;
                }

                len -= opt_hdr->nd_opt_len * NDISC_OPT_LEN_UNITS;
                opt = (void *)((char *)opt +
                        opt_hdr->nd_opt_len * NDISC_OPT_LEN_UNITS);
                opt_hdr = opt;
        }

        if (len > 0)
                log_ndisc(nd, "Router Advertisement contains %zd bytes of trailing garbage", len);

        return 0;
}

static int ndisc_router_advertisment_recv(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_free_ struct nd_router_advert *ra = NULL;
        sd_ndisc *nd = userdata;
        int r, buflen = 0, pref, stateful;
        union sockaddr_union router = {};
        socklen_t router_len = sizeof(router);
        unsigned lifetime;
        ssize_t len;

        assert(s);
        assert(nd);
        assert(nd->event);

        r = ioctl(fd, FIONREAD, &buflen);
        if (r < 0 || buflen <= 0)
                buflen = ICMP6_RECV_SIZE;

        ra = malloc(buflen);
        if (!ra)
                return -ENOMEM;

        len = recvfrom(fd, ra, buflen, 0, &router.sa, &router_len);
        if (len < 0) {
                log_ndisc(nd, "Could not receive message from ICMPv6 socket: %m");
                return 0;
        } else if (router_len != sizeof(router.in6) && router_len != 0) {
                log_ndisc(nd, "Received invalid source address size from ICMPv6 socket: %zu bytes", (size_t)router_len);
                return 0;
        }

        if (ra->nd_ra_type != ND_ROUTER_ADVERT)
                return 0;

        if (ra->nd_ra_code != 0)
                return 0;

        nd->timeout = sd_event_source_unref(nd->timeout);

        nd->state = NDISC_STATE_ADVERTISMENT_LISTEN;

        stateful = ra->nd_ra_flags_reserved & (ND_RA_FLAG_MANAGED | ND_RA_FLAG_OTHER);
        pref = (ra->nd_ra_flags_reserved & ND_RA_FLAG_PREF) >> 3;

        switch (pref) {
        case ND_RA_FLAG_PREF_LOW:
        case ND_RA_FLAG_PREF_HIGH:
                break;
        default:
                pref = ND_RA_FLAG_PREF_MEDIUM;
                break;
        }

        lifetime = be16toh(ra->nd_ra_router_lifetime);

        log_ndisc(nd, "Received Router Advertisement: flags %s preference %s lifetime %u sec",
                  stateful & ND_RA_FLAG_MANAGED ? "MANAGED" : stateful & ND_RA_FLAG_OTHER ? "OTHER" : "none",
                  pref == ND_RA_FLAG_PREF_HIGH ? "high" : pref == ND_RA_FLAG_PREF_LOW ? "low" : "medium",
                  lifetime);

        r = ndisc_ra_parse(nd, ra, len);
        if (r < 0) {
                log_ndisc(nd, "Could not parse Router Advertisement: %s", strerror(-r));
                return 0;
        }

        if (nd->router_callback)
                nd->router_callback(nd, stateful, router_len != 0 ? &router.in6.sin6_addr : NULL, lifetime, pref, nd->userdata);

        return 0;
}

static int ndisc_router_solicitation_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_ndisc *nd = userdata;
        uint64_t time_now, next_timeout;
        struct ether_addr unset = { };
        struct ether_addr *addr = NULL;
        int r;

        assert(s);
        assert(nd);
        assert(nd->event);

        nd->timeout = sd_event_source_unref(nd->timeout);

        if (nd->nd_sent >= NDISC_MAX_ROUTER_SOLICITATIONS) {
                if (nd->callback)
                        nd->callback(nd, SD_NDISC_EVENT_TIMEOUT, nd->userdata);
                nd->state = NDISC_STATE_ADVERTISMENT_LISTEN;
        } else {
                if (memcmp(&nd->mac_addr, &unset, sizeof(struct ether_addr)))
                        addr = &nd->mac_addr;

                r = icmp6_send_router_solicitation(nd->fd, addr);
                if (r < 0)
                        log_ndisc(nd, "Error sending Router Solicitation");
                else {
                        nd->state = NDISC_STATE_SOLICITATION_SENT;
                        log_ndisc(nd, "Sent Router Solicitation");
                }

                nd->nd_sent++;

                assert_se(sd_event_now(nd->event, clock_boottime_or_monotonic(), &time_now) >= 0);

                next_timeout = time_now + NDISC_ROUTER_SOLICITATION_INTERVAL;

                r = sd_event_add_time(nd->event, &nd->timeout, clock_boottime_or_monotonic(),
                                      next_timeout, 0,
                                      ndisc_router_solicitation_timeout, nd);
                if (r < 0) {
                        /* we cannot continue if we are unable to rearm the timer */
                        sd_ndisc_stop(nd);
                        return 0;
                }

                r = sd_event_source_set_priority(nd->timeout, nd->event_priority);
                if (r < 0)
                        return 0;

                r = sd_event_source_set_description(nd->timeout, "ndisc-timeout");
                if (r < 0)
                        return 0;
        }

        return 0;
}

int sd_ndisc_stop(sd_ndisc *nd) {
        assert_return(nd, -EINVAL);
        assert_return(nd->event, -EINVAL);

        log_ndisc(client, "Stop NDisc");

        ndisc_init(nd);

        nd->state = NDISC_STATE_IDLE;

        if (nd->callback)
                nd->callback(nd, SD_NDISC_EVENT_STOP, nd->userdata);

        return 0;
}

int sd_ndisc_router_discovery_start(sd_ndisc *nd) {
        int r;

        assert(nd);
        assert(nd->event);

        if (nd->state != NDISC_STATE_IDLE)
                return -EBUSY;

        if (nd->index < 1)
                return -EINVAL;

        r = icmp6_bind_router_solicitation(nd->index);
        if (r < 0)
                return r;

        nd->fd = r;

        r = sd_event_add_io(nd->event, &nd->recv, nd->fd, EPOLLIN,
                            ndisc_router_advertisment_recv, nd);
        if (r < 0)
                goto error;

        r = sd_event_source_set_priority(nd->recv, nd->event_priority);
        if (r < 0)
                goto error;

        r = sd_event_source_set_description(nd->recv, "ndisc-receive-message");
        if (r < 0)
                goto error;

        r = sd_event_add_time(nd->event, &nd->timeout, clock_boottime_or_monotonic(),
                              0, 0, ndisc_router_solicitation_timeout, nd);
        if (r < 0)
                goto error;

        r = sd_event_source_set_priority(nd->timeout, nd->event_priority);
        if (r < 0)
                goto error;

        r = sd_event_source_set_description(nd->timeout, "ndisc-timeout");
error:
        if (r < 0)
                ndisc_init(nd);
        else
                log_ndisc(client, "Start Router Solicitation");

        return r;
}
