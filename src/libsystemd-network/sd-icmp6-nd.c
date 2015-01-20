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
#include <netinet/ip6.h>
#include <string.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

#include "socket-util.h"
#include "refcnt.h"
#include "async.h"

#include "dhcp6-internal.h"
#include "sd-icmp6-nd.h"

#define ICMP6_ROUTER_SOLICITATION_INTERVAL      4 * USEC_PER_SEC
#define ICMP6_MAX_ROUTER_SOLICITATIONS          3

enum icmp6_nd_state {
        ICMP6_NEIGHBOR_DISCOVERY_IDLE           = 0,
        ICMP6_ROUTER_SOLICITATION_SENT          = 10,
        ICMP6_ROUTER_ADVERTISMENT_LISTEN        = 11,
};

#define IP6_MIN_MTU (unsigned)1280
#define ICMP6_ND_RECV_SIZE (IP6_MIN_MTU - sizeof(struct ip6_hdr))
#define ICMP6_OPT_LEN_UNITS 8

typedef struct ICMP6Prefix ICMP6Prefix;

struct ICMP6Prefix {
        RefCount n_ref;

        LIST_FIELDS(ICMP6Prefix, prefixes);

        uint8_t len;
        sd_event_source *timeout_valid;
        struct in6_addr addr;
};

struct sd_icmp6_nd {
        RefCount n_ref;

        enum icmp6_nd_state state;
        sd_event *event;
        int event_priority;
        int index;
        struct ether_addr mac_addr;
        uint32_t mtu;
        ICMP6Prefix *expired_prefix;
        LIST_HEAD(ICMP6Prefix, prefixes);
        int fd;
        sd_event_source *recv;
        sd_event_source *timeout;
        int nd_sent;
        sd_icmp6_nd_callback_t callback;
        void *userdata;
};

#define log_icmp6_nd(p, fmt, ...) log_internal(LOG_DEBUG, 0, __FILE__, __LINE__, __func__, "ICMPv6 CLIENT: " fmt, ##__VA_ARGS__)

static ICMP6Prefix *icmp6_prefix_unref(ICMP6Prefix *prefix) {
        if (prefix && REFCNT_DEC(prefix->n_ref) <= 0) {
                prefix->timeout_valid =
                        sd_event_source_unref(prefix->timeout_valid);

                free(prefix);
        }

        return NULL;
}

static int icmp6_prefix_new(ICMP6Prefix **ret) {
        _cleanup_free_ ICMP6Prefix *prefix = NULL;

        assert(ret);

        prefix = new0(ICMP6Prefix, 1);
        if (!prefix)
                return -ENOMEM;

        prefix->n_ref = REFCNT_INIT;
        LIST_INIT(prefixes, prefix);

        *ret = prefix;
        prefix = NULL;

        return 0;
}

static void icmp6_nd_notify(sd_icmp6_nd *nd, int event)
{
        if (nd->callback)
                nd->callback(nd, event, nd->userdata);
}

int sd_icmp6_nd_set_callback(sd_icmp6_nd *nd, sd_icmp6_nd_callback_t callback,
                             void *userdata) {
        assert(nd);

        nd->callback = callback;
        nd->userdata = userdata;

        return 0;
}

int sd_icmp6_nd_set_index(sd_icmp6_nd *nd, int interface_index) {
        assert(nd);
        assert(interface_index >= -1);

        nd->index = interface_index;

        return 0;
}

int sd_icmp6_nd_set_mac(sd_icmp6_nd *nd, const struct ether_addr *mac_addr) {
        assert(nd);

        if (mac_addr)
                memcpy(&nd->mac_addr, mac_addr, sizeof(nd->mac_addr));
        else
                zero(nd->mac_addr);

        return 0;

}

int sd_icmp6_nd_attach_event(sd_icmp6_nd *nd, sd_event *event, int priority) {
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

int sd_icmp6_nd_detach_event(sd_icmp6_nd *nd) {
        assert_return(nd, -EINVAL);

        nd->event = sd_event_unref(nd->event);

        return 0;
}

sd_event *sd_icmp6_nd_get_event(sd_icmp6_nd *nd) {
        assert(nd);

        return nd->event;
}

sd_icmp6_nd *sd_icmp6_nd_ref(sd_icmp6_nd *nd) {
        assert (nd);

        assert_se(REFCNT_INC(nd->n_ref) >= 2);

        return nd;
}

static int icmp6_nd_init(sd_icmp6_nd *nd) {
        assert(nd);

        nd->recv = sd_event_source_unref(nd->recv);
        nd->fd = asynchronous_close(nd->fd);
        nd->timeout = sd_event_source_unref(nd->timeout);

        return 0;
}

sd_icmp6_nd *sd_icmp6_nd_unref(sd_icmp6_nd *nd) {
        if (nd && REFCNT_DEC(nd->n_ref) == 0) {
                ICMP6Prefix *prefix, *p;

                icmp6_nd_init(nd);
                sd_icmp6_nd_detach_event(nd);

                LIST_FOREACH_SAFE(prefixes, prefix, p, nd->prefixes) {
                        LIST_REMOVE(prefixes, nd->prefixes, prefix);

                        prefix = icmp6_prefix_unref(prefix);
                }

                free(nd);
        }

        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_icmp6_nd*, sd_icmp6_nd_unref);
#define _cleanup_sd_icmp6_nd_free_ _cleanup_(sd_icmp6_nd_unrefp)

int sd_icmp6_nd_new(sd_icmp6_nd **ret) {
        _cleanup_sd_icmp6_nd_free_ sd_icmp6_nd *nd = NULL;

        assert(ret);

        nd = new0(sd_icmp6_nd, 1);
        if (!nd)
                return -ENOMEM;

        nd->n_ref = REFCNT_INIT;

        nd->index = -1;
        nd->fd = -1;

        LIST_HEAD_INIT(nd->prefixes);

        *ret = nd;
        nd = NULL;

        return 0;
}

int sd_icmp6_ra_get_mtu(sd_icmp6_nd *nd, uint32_t *mtu) {
        assert_return(nd, -EINVAL);
        assert_return(mtu, -EINVAL);

        if (nd->mtu == 0)
                return -ENOMSG;

        *mtu = nd->mtu;

        return 0;
}

static int icmp6_ra_prefix_timeout(sd_event_source *s, uint64_t usec,
                                   void *userdata) {
        sd_icmp6_nd *nd = userdata;
        ICMP6Prefix *prefix, *p;

        assert(nd);

        LIST_FOREACH_SAFE(prefixes, prefix, p, nd->prefixes) {
                if (prefix->timeout_valid != s)
                        continue;

                log_icmp6_nd(nd, "Prefix expired "SD_ICMP6_ADDRESS_FORMAT_STR"/%d",
                             SD_ICMP6_ADDRESS_FORMAT_VAL(prefix->addr),
                             prefix->len);

                LIST_REMOVE(prefixes, nd->prefixes, prefix);

                nd->expired_prefix = prefix;
                icmp6_nd_notify(nd,
                                ICMP6_EVENT_ROUTER_ADVERTISMENT_PREFIX_EXPIRED);
                nd->expired_prefix = NULL;

                prefix = icmp6_prefix_unref(prefix);

                break;
        }

        return 0;
}

static int icmp6_ra_prefix_set_timeout(sd_icmp6_nd *nd,
                                       ICMP6Prefix *prefix,
                                       usec_t valid) {
        usec_t time_now;
        int r;

        assert_return(prefix, -EINVAL);

        r = sd_event_now(nd->event, clock_boottime_or_monotonic(), &time_now);
        if (r < 0)
                return r;

        prefix->timeout_valid = sd_event_source_unref(prefix->timeout_valid);

        r = sd_event_add_time(nd->event, &prefix->timeout_valid,
                        clock_boottime_or_monotonic(), time_now + valid,
                        USEC_PER_SEC, icmp6_ra_prefix_timeout, nd);
        if (r < 0)
                goto error;

        r = sd_event_source_set_priority(prefix->timeout_valid,
                                        nd->event_priority);
        if (r < 0)
                goto error;

        r = sd_event_source_set_description(prefix->timeout_valid,
                                        "icmp6-prefix-timeout");

error:
        if (r < 0)
                prefix->timeout_valid =
                        sd_event_source_unref(prefix->timeout_valid);

        return r;
}

static int icmp6_prefix_match(const struct in6_addr *prefix, uint8_t prefixlen,
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

static int icmp6_ra_prefix_match(ICMP6Prefix *head, const struct in6_addr *addr,
                                 uint8_t addr_len, ICMP6Prefix **result) {
        ICMP6Prefix *prefix;

        LIST_FOREACH(prefixes, prefix, head) {
                if (icmp6_prefix_match(&prefix->addr, prefix->len, addr,
                                       addr_len) >= 0) {
                        *result = prefix;
                        return 0;
                }
        }

        return -EADDRNOTAVAIL;
}

int sd_icmp6_prefix_match(struct in6_addr *prefix, uint8_t prefixlen,
                          struct in6_addr *addr) {
        return icmp6_prefix_match(prefix, prefixlen, addr,
                                  sizeof(addr->s6_addr) * 8);
}

int sd_icmp6_ra_get_prefixlen(sd_icmp6_nd *nd, const struct in6_addr *addr,
                              uint8_t *prefixlen) {
        int r;
        ICMP6Prefix *prefix;

        assert_return(nd, -EINVAL);
        assert_return(addr, -EINVAL);
        assert_return(prefixlen, -EINVAL);

        r = icmp6_ra_prefix_match(nd->prefixes, addr,
                                  sizeof(addr->s6_addr) * 8, &prefix);
        if (r < 0)
                return r;

        *prefixlen = prefix->len;

        return 0;
}

int sd_icmp6_ra_get_expired_prefix(sd_icmp6_nd *nd, struct in6_addr **addr,
                                uint8_t *prefixlen)
{
        assert_return(nd, -EINVAL);
        assert_return(addr, -EINVAL);
        assert_return(prefixlen, -EINVAL);

        if (!nd->expired_prefix)
                return -EADDRNOTAVAIL;

        *addr = &nd->expired_prefix->addr;
        *prefixlen = nd->expired_prefix->len;

        return 0;
}

static int icmp6_ra_prefix_update(sd_icmp6_nd *nd, ssize_t len,
                                  const struct nd_opt_prefix_info *prefix_opt) {
        int r;
        ICMP6Prefix *prefix;
        uint32_t lifetime;
        char time_string[FORMAT_TIMESPAN_MAX];

        assert_return(nd, -EINVAL);
        assert_return(prefix_opt, -EINVAL);

        if (len < prefix_opt->nd_opt_pi_len)
                return -ENOMSG;

        if (!(prefix_opt->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_ONLINK))
                return 0;

        lifetime = be32toh(prefix_opt->nd_opt_pi_valid_time);

        r = icmp6_ra_prefix_match(nd->prefixes,
                                  &prefix_opt->nd_opt_pi_prefix,
                                  prefix_opt->nd_opt_pi_prefix_len, &prefix);

        if (r < 0 && r != -EADDRNOTAVAIL)
                return r;

        /* if router advertisment prefix valid timeout is zero, the timeout
           callback will be called immediately to clean up the prefix */

        if (r == -EADDRNOTAVAIL) {
                r = icmp6_prefix_new(&prefix);
                if (r < 0)
                        return r;

                prefix->len = prefix_opt->nd_opt_pi_prefix_len;

                memcpy(&prefix->addr, &prefix_opt->nd_opt_pi_prefix,
                        sizeof(prefix->addr));

                log_icmp6_nd(nd, "New prefix "SD_ICMP6_ADDRESS_FORMAT_STR"/%d lifetime %d expires in %s",
                             SD_ICMP6_ADDRESS_FORMAT_VAL(prefix->addr),
                             prefix->len, lifetime,
                             format_timespan(time_string, FORMAT_TIMESPAN_MAX,
                                             lifetime * USEC_PER_SEC, 0));

                LIST_PREPEND(prefixes, nd->prefixes, prefix);

        } else {
                if (prefix->len != prefix_opt->nd_opt_pi_prefix_len) {
                        uint8_t prefixlen;

                        prefixlen = MIN(prefix->len, prefix_opt->nd_opt_pi_prefix_len);

                        log_icmp6_nd(nd, "Prefix length mismatch %d/%d using %d",
                                     prefix->len,
                                     prefix_opt->nd_opt_pi_prefix_len,
                                     prefixlen);

                        prefix->len = prefixlen;
                }

                log_icmp6_nd(nd, "Update prefix "SD_ICMP6_ADDRESS_FORMAT_STR"/%d lifetime %d expires in %s",
                             SD_ICMP6_ADDRESS_FORMAT_VAL(prefix->addr),
                             prefix->len, lifetime,
                             format_timespan(time_string, FORMAT_TIMESPAN_MAX,
                                             lifetime * USEC_PER_SEC, 0));
        }

        r = icmp6_ra_prefix_set_timeout(nd, prefix, lifetime * USEC_PER_SEC);

        return r;
}

static int icmp6_ra_parse(sd_icmp6_nd *nd, struct nd_router_advert *ra,
                          ssize_t len) {
        void *opt;
        struct nd_opt_hdr *opt_hdr;

        assert_return(nd, -EINVAL);
        assert_return(ra, -EINVAL);

        len -= sizeof(*ra);
        if (len < ICMP6_OPT_LEN_UNITS) {
                log_icmp6_nd(nd, "Router Advertisement below minimum length");

                return -ENOMSG;
        }

        opt = ra + 1;
        opt_hdr = opt;

        while (len != 0 && len >= opt_hdr->nd_opt_len * ICMP6_OPT_LEN_UNITS) {
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

                                log_icmp6_nd(nd, "Router Advertisement link MTU %d using %d",
                                             mtu, nd->mtu);
                        }

                        break;

                case ND_OPT_PREFIX_INFORMATION:
                        opt_prefix = opt;

                        icmp6_ra_prefix_update(nd, len, opt_prefix);

                        break;
                }

                len -= opt_hdr->nd_opt_len * ICMP6_OPT_LEN_UNITS;
                opt = (void *)((char *)opt +
                        opt_hdr->nd_opt_len * ICMP6_OPT_LEN_UNITS);
                opt_hdr = opt;
        }

        if (len > 0)
                log_icmp6_nd(nd, "Router Advertisement contains %zd bytes of trailing garbage", len);

        return 0;
}

static int icmp6_router_advertisment_recv(sd_event_source *s, int fd,
                                          uint32_t revents, void *userdata)
{
        sd_icmp6_nd *nd = userdata;
        int r, buflen = 0;
        ssize_t len;
        _cleanup_free_ struct nd_router_advert *ra = NULL;
        int event = ICMP6_EVENT_ROUTER_ADVERTISMENT_NONE;

        assert(s);
        assert(nd);
        assert(nd->event);

        r = ioctl(fd, FIONREAD, &buflen);
        if (r < 0 || buflen <= 0)
                buflen = ICMP6_ND_RECV_SIZE;

        ra = malloc(buflen);
        if (!ra)
                return -ENOMEM;

        len = read(fd, ra, buflen);
        if (len < 0) {
                log_icmp6_nd(nd, "Could not receive message from UDP socket: %m");
                return 0;
        }

        if (ra->nd_ra_type != ND_ROUTER_ADVERT)
                return 0;

        if (ra->nd_ra_code != 0)
                return 0;

        nd->timeout = sd_event_source_unref(nd->timeout);

        nd->state = ICMP6_ROUTER_ADVERTISMENT_LISTEN;

        if (ra->nd_ra_flags_reserved & ND_RA_FLAG_OTHER )
                event = ICMP6_EVENT_ROUTER_ADVERTISMENT_OTHER;

        if (ra->nd_ra_flags_reserved & ND_RA_FLAG_MANAGED)
                event = ICMP6_EVENT_ROUTER_ADVERTISMENT_MANAGED;

        log_icmp6_nd(nd, "Received Router Advertisement flags %s/%s",
                     ra->nd_ra_flags_reserved & ND_RA_FLAG_MANAGED? "MANAGED": "none",
                     ra->nd_ra_flags_reserved & ND_RA_FLAG_OTHER? "OTHER": "none");

        if (event != ICMP6_EVENT_ROUTER_ADVERTISMENT_NONE) {
                r = icmp6_ra_parse(nd, ra, len);
                if (r < 0) {
                        log_icmp6_nd(nd, "Could not parse Router Advertisement: %s",
                                     strerror(-r));
                        return 0;
                }
        }

        icmp6_nd_notify(nd, event);

        return 0;
}

static int icmp6_router_solicitation_timeout(sd_event_source *s, uint64_t usec,
                                             void *userdata)
{
        sd_icmp6_nd *nd = userdata;
        uint64_t time_now, next_timeout;
        struct ether_addr unset = { };
        struct ether_addr *addr = NULL;
        int r;

        assert(s);
        assert(nd);
        assert(nd->event);

        nd->timeout = sd_event_source_unref(nd->timeout);

        if (nd->nd_sent >= ICMP6_MAX_ROUTER_SOLICITATIONS) {
                icmp6_nd_notify(nd, ICMP6_EVENT_ROUTER_ADVERTISMENT_TIMEOUT);
                nd->state = ICMP6_ROUTER_ADVERTISMENT_LISTEN;
        } else {
                if (memcmp(&nd->mac_addr, &unset, sizeof(struct ether_addr)))
                        addr = &nd->mac_addr;

                r = dhcp_network_icmp6_send_router_solicitation(nd->fd, addr);
                if (r < 0)
                        log_icmp6_nd(nd, "Error sending Router Solicitation");
                else {
                        nd->state = ICMP6_ROUTER_SOLICITATION_SENT;
                        log_icmp6_nd(nd, "Sent Router Solicitation");
                }

                nd->nd_sent++;

                r = sd_event_now(nd->event, clock_boottime_or_monotonic(), &time_now);
                if (r < 0) {
                        icmp6_nd_notify(nd, r);
                        return 0;
                }

                next_timeout = time_now + ICMP6_ROUTER_SOLICITATION_INTERVAL;

                r = sd_event_add_time(nd->event, &nd->timeout, clock_boottime_or_monotonic(),
                                      next_timeout, 0,
                                      icmp6_router_solicitation_timeout, nd);
                if (r < 0) {
                        icmp6_nd_notify(nd, r);
                        return 0;
                }

                r = sd_event_source_set_priority(nd->timeout,
                                                 nd->event_priority);
                if (r < 0) {
                        icmp6_nd_notify(nd, r);
                        return 0;
                }

                r = sd_event_source_set_description(nd->timeout, "icmp6-timeout");
                if (r < 0) {
                        icmp6_nd_notify(nd, r);
                        return 0;
                }
        }

        return 0;
}

int sd_icmp6_nd_stop(sd_icmp6_nd *nd) {
        assert_return(nd, -EINVAL);
        assert_return(nd->event, -EINVAL);

        log_icmp6_nd(client, "Stop ICMPv6");

        icmp6_nd_init(nd);

        nd->state = ICMP6_NEIGHBOR_DISCOVERY_IDLE;

        return 0;
}

int sd_icmp6_router_solicitation_start(sd_icmp6_nd *nd) {
        int r;

        assert(nd);
        assert(nd->event);

        if (nd->state != ICMP6_NEIGHBOR_DISCOVERY_IDLE)
                return -EINVAL;

        if (nd->index < 1)
                return -EINVAL;

        r = dhcp_network_icmp6_bind_router_solicitation(nd->index);
        if (r < 0)
                return r;

        nd->fd = r;

        r = sd_event_add_io(nd->event, &nd->recv, nd->fd, EPOLLIN,
                            icmp6_router_advertisment_recv, nd);
        if (r < 0)
                goto error;

        r = sd_event_source_set_priority(nd->recv, nd->event_priority);
        if (r < 0)
                goto error;

        r = sd_event_source_set_description(nd->recv, "icmp6-receive-message");
        if (r < 0)
                goto error;

        r = sd_event_add_time(nd->event, &nd->timeout, clock_boottime_or_monotonic(),
                              0, 0, icmp6_router_solicitation_timeout, nd);
        if (r < 0)
                goto error;

        r = sd_event_source_set_priority(nd->timeout, nd->event_priority);
        if (r < 0)
                goto error;

        r = sd_event_source_set_description(nd->timeout, "icmp6-timeout");
error:
        if (r < 0)
                icmp6_nd_init(nd);
        else
                log_icmp6_nd(client, "Start Router Solicitation");

        return r;
}
