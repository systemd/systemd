/***
  This file is part of systemd.

  Copyright (C) 2017 Intel Corporation. All rights reserved.

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
#include <arpa/inet.h>
#include <linux/in6.h>

#include "sd-radv.h"

#include "macro.h"
#include "alloc-util.h"
#include "fd-util.h"
#include "icmp6-util.h"
#include "in-addr-util.h"
#include "radv-internal.h"
#include "socket-util.h"
#include "string-util.h"
#include "util.h"
#include "random-util.h"

_public_ int sd_radv_new(sd_radv **ret) {
        _cleanup_(sd_radv_unrefp) sd_radv *ra = NULL;

        assert_return(ret, -EINVAL);

        ra = new0(sd_radv, 1);
        if (!ra)
                return -ENOMEM;

        ra->n_ref = 1;
        ra->fd = -1;

        LIST_HEAD_INIT(ra->prefixes);

        *ret = ra;
        ra = NULL;

        return 0;
}

_public_ int sd_radv_attach_event(sd_radv *ra, sd_event *event, int64_t priority) {
        int r;

        assert_return(ra, -EINVAL);
        assert_return(!ra->event, -EBUSY);

        if (event)
                ra->event = sd_event_ref(event);
        else {
                r = sd_event_default(&ra->event);
                if (r < 0)
                        return 0;
        }

        ra->event_priority = priority;

        return 0;
}

_public_ int sd_radv_detach_event(sd_radv *ra) {

        assert_return(ra, -EINVAL);

        ra->event = sd_event_unref(ra->event);
        return 0;
}

_public_ sd_event *sd_radv_get_event(sd_radv *ra) {
        assert_return(ra, NULL);

        return ra->event;
}

static void radv_reset(sd_radv *ra) {

        ra->timeout_event_source =
                sd_event_source_unref(ra->timeout_event_source);

        ra->recv_event_source =
                sd_event_source_unref(ra->recv_event_source);

        ra->ra_sent = 0;
}

_public_ sd_radv *sd_radv_ref(sd_radv *ra) {
        if (!ra)
                return NULL;

        assert(ra->n_ref > 0);
        ra->n_ref++;

        return ra;
}

_public_ sd_radv *sd_radv_unref(sd_radv *ra) {
        if (!ra)
                return NULL;

        assert(ra->n_ref > 0);
        ra->n_ref--;

        if (ra->n_ref > 0)
                return NULL;

        while (ra->prefixes) {
                sd_radv_prefix *p = ra->prefixes;

                LIST_REMOVE(prefix, ra->prefixes, p);
                sd_radv_prefix_unref(p);
        }

        radv_reset(ra);

        sd_radv_detach_event(ra);
        return mfree(ra);
}

static int radv_send(sd_radv *ra, const struct in6_addr *dst,
                     const uint32_t router_lifetime) {
        static const struct ether_addr mac_zero = {};
        sd_radv_prefix *p;
        struct sockaddr_in6 dst_addr = {
                .sin6_family = AF_INET6,
                .sin6_addr = IN6ADDR_ALL_NODES_MULTICAST_INIT,
        };
        struct nd_router_advert adv = {};
        struct {
                struct nd_opt_hdr opthdr;
                struct ether_addr slladdr;
        } _packed_ opt_mac = {
                .opthdr = {
                        .nd_opt_type = ND_OPT_SOURCE_LINKADDR,
                        .nd_opt_len = (sizeof(struct nd_opt_hdr) +
                                       sizeof(struct ether_addr) - 1) /8 + 1,
                },
        };
        struct nd_opt_mtu opt_mtu =  {
                .nd_opt_mtu_type = ND_OPT_MTU,
                .nd_opt_mtu_len = 1,
        };
        /* Reserve iov space for RA header, linkaddr, MTU + N prefixes */
        struct iovec iov[3 + ra->n_prefixes];
        struct msghdr msg = {
                .msg_name = &dst_addr,
                .msg_namelen = sizeof(dst_addr),
                .msg_iov = iov,
        };

        if (dst && !in_addr_is_null(AF_INET6, (union in_addr_union*) dst))
                dst_addr.sin6_addr = *dst;

        adv.nd_ra_type = ND_ROUTER_ADVERT;
        adv.nd_ra_curhoplimit = ra->hop_limit;
        adv.nd_ra_flags_reserved = ra->flags;
        adv.nd_ra_router_lifetime = htobe16(router_lifetime);
        iov[msg.msg_iovlen].iov_base = &adv;
        iov[msg.msg_iovlen].iov_len = sizeof(adv);
        msg.msg_iovlen++;

        /* MAC address is optional, either because the link does not use L2
           addresses or load sharing is desired. See RFC 4861, Section 4.2 */
        if (memcmp(&mac_zero, &ra->mac_addr, sizeof(mac_zero))) {
                opt_mac.slladdr = ra->mac_addr;
                iov[msg.msg_iovlen].iov_base = &opt_mac;
                iov[msg.msg_iovlen].iov_len = sizeof(opt_mac);
                msg.msg_iovlen++;
        }

        if (ra->mtu) {
                opt_mtu.nd_opt_mtu_mtu = htobe32(ra->mtu);
                iov[msg.msg_iovlen].iov_base = &opt_mtu;
                iov[msg.msg_iovlen].iov_len = sizeof(opt_mtu);
                msg.msg_iovlen++;
        }

        LIST_FOREACH(prefix, p, ra->prefixes) {
                iov[msg.msg_iovlen].iov_base = &p->opt;
                iov[msg.msg_iovlen].iov_len = sizeof(p->opt);
                msg.msg_iovlen++;
        }

        if (sendmsg(ra->fd, &msg, 0) < 0)
                return -errno;

        return 0;
}

static int radv_recv(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_radv *ra = userdata;
        _cleanup_free_ char *addr = NULL;
        struct in6_addr src;
        triple_timestamp timestamp;
        int r;
        ssize_t buflen;
        _cleanup_free_ char *buf = NULL;

        assert(s);
        assert(ra);
        assert(ra->event);

        buflen = next_datagram_size_fd(fd);

        if ((unsigned) buflen < sizeof(struct nd_router_solicit))
                return log_radv("Too short packet received");

        buf = new0(char, buflen);
        if (!buf)
                return 0;

        r = icmp6_receive(fd, buf, buflen, &src, &timestamp);
        if (r < 0) {
                switch (r) {
                case -EADDRNOTAVAIL:
                        (void) in_addr_to_string(AF_INET6, (union in_addr_union*) &src, &addr);
                        log_radv("Received RS from non-link-local address %s. Ignoring", addr);
                        break;

                case -EMULTIHOP:
                        log_radv("Received RS with invalid hop limit. Ignoring.");
                        break;

                case -EPFNOSUPPORT:
                        log_radv("Received invalid source address from ICMPv6 socket. Ignoring.");
                        break;

                default:
                        log_radv_warning_errno(r, "Error receiving from ICMPv6 socket: %m");
                        break;
                }

                return 0;
        }

        (void) in_addr_to_string(AF_INET6, (union in_addr_union*) &src, &addr);

        r = radv_send(ra, &src, ra->lifetime);
        if (r < 0)
                log_radv_warning_errno(r, "Unable to send solicited Router Advertisment to %s: %m", addr);
        else
                log_radv("Sent solicited Router Advertisement to %s", addr);

        return 0;
}

static usec_t radv_compute_timeout(usec_t min, usec_t max) {
        assert_return(min <= max, SD_RADV_DEFAULT_MIN_TIMEOUT_USEC);

        return min + (random_u32() % (max - min));
}

static int radv_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        int r;
        sd_radv *ra = userdata;
        usec_t min_timeout = SD_RADV_DEFAULT_MIN_TIMEOUT_USEC;
        usec_t max_timeout = SD_RADV_DEFAULT_MAX_TIMEOUT_USEC;
        usec_t time_now, timeout;
        char time_string[FORMAT_TIMESPAN_MAX];

        assert(s);
        assert(ra);
        assert(ra->event);

        ra->timeout_event_source = sd_event_source_unref(ra->timeout_event_source);

        r = sd_event_now(ra->event, clock_boottime_or_monotonic(), &time_now);
        if (r < 0)
                goto fail;

        r = radv_send(ra, NULL, ra->lifetime);
        if (r < 0)
                log_radv_warning_errno(r, "Unable to send Router Advertisement: %m");

        /* RFC 4861, Section 6.2.4, sending initial Router Advertisements */
        if (ra->ra_sent < SD_RADV_MAX_INITIAL_RTR_ADVERTISEMENTS) {
                max_timeout = SD_RADV_MAX_INITIAL_RTR_ADVERT_INTERVAL_USEC;
                min_timeout = SD_RADV_MAX_INITIAL_RTR_ADVERT_INTERVAL_USEC / 3;
        }

        timeout = radv_compute_timeout(min_timeout, max_timeout);

        log_radv("Next Router Advertisement in %s",
                 format_timespan(time_string, FORMAT_TIMESPAN_MAX,
                                 timeout, USEC_PER_SEC));

        r = sd_event_add_time(ra->event, &ra->timeout_event_source,
                              clock_boottime_or_monotonic(),
                              time_now + timeout, MSEC_PER_SEC,
                              radv_timeout, ra);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(ra->timeout_event_source,
                                         ra->event_priority);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_description(ra->timeout_event_source,
                                            "radv-timeout");
        if (r < 0)
                goto fail;

        ra->ra_sent++;

fail:
        if (r < 0)
                sd_radv_stop(ra);

        return 0;
}

_public_ int sd_radv_stop(sd_radv *ra) {
        int r;

        assert_return(ra, -EINVAL);

        log_radv("Stopping IPv6 Router Advertisement daemon");

        /* RFC 4861, Section 6.2.5, send at least one Router Advertisement
           with zero lifetime  */
        r = radv_send(ra, NULL, 0);
        if (r < 0)
                log_radv_warning_errno(r, "Unable to send last Router Advertisement with router lifetime set to zero: %m");

        radv_reset(ra);
        ra->fd = safe_close(ra->fd);
        ra->state = SD_RADV_STATE_IDLE;

        return 0;
}

_public_ int sd_radv_start(sd_radv *ra) {
        int r = 0;

        assert_return(ra, -EINVAL);
        assert_return(ra->event, -EINVAL);
        assert_return(ra->ifindex > 0, -EINVAL);

        if (ra->state != SD_RADV_STATE_IDLE)
                return 0;

        r = sd_event_add_time(ra->event, &ra->timeout_event_source,
                              clock_boottime_or_monotonic(), 0, 0,
                              radv_timeout, ra);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(ra->timeout_event_source,
                                         ra->event_priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(ra->timeout_event_source,
                                               "radv-timeout");

        r = icmp6_bind_router_advertisement(ra->ifindex);
        if (r < 0)
                goto fail;

        ra->fd = r;

        r = sd_event_add_io(ra->event, &ra->recv_event_source, ra->fd, EPOLLIN, radv_recv, ra);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(ra->recv_event_source, ra->event_priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(ra->recv_event_source, "radv-receive-message");

        ra->state = SD_RADV_STATE_ADVERTISING;

        log_radv("Started IPv6 Router Advertisement daemon");

        return 0;

 fail:
        radv_reset(ra);

        return r;
}

_public_ int sd_radv_set_ifindex(sd_radv *ra, int ifindex) {
        assert_return(ra, -EINVAL);
        assert_return(ifindex >= -1, -EINVAL);

        if (ra->state != SD_RADV_STATE_IDLE)
                return -EBUSY;

        ra->ifindex = ifindex;

        return 0;
}

_public_ int sd_radv_set_mac(sd_radv *ra, const struct ether_addr *mac_addr) {
        assert_return(ra, -EINVAL);

        if (ra->state != SD_RADV_STATE_IDLE)
                return -EBUSY;

        if (mac_addr)
                ra->mac_addr = *mac_addr;
        else
                zero(ra->mac_addr);

        return 0;
}

_public_ int sd_radv_set_mtu(sd_radv *ra, uint32_t mtu) {
        assert_return(ra, -EINVAL);
        assert_return(mtu >= 1280, -EINVAL);

        if (ra->state != SD_RADV_STATE_IDLE)
                return -EBUSY;

        ra->mtu = mtu;

        return 0;
}

_public_ int sd_radv_set_hop_limit(sd_radv *ra, uint8_t hop_limit) {
        assert_return(ra, -EINVAL);

        if (ra->state != SD_RADV_STATE_IDLE)
                return -EBUSY;

        ra->hop_limit = hop_limit;

        return 0;
}

_public_ int sd_radv_set_router_lifetime(sd_radv *ra, uint32_t router_lifetime) {
        assert_return(ra, -EINVAL);

        if (ra->state != SD_RADV_STATE_IDLE)
                return -EBUSY;

        /* RFC 4191, Section 2.2, "...If the Router Lifetime is zero, the
           preference value MUST be set to (00) by the sender..." */
        if (router_lifetime == 0 &&
            (ra->flags & (0x3 << 3)) != (SD_NDISC_PREFERENCE_MEDIUM << 3))
                return -ETIME;

        ra->lifetime = router_lifetime;

        return 0;
}

_public_ int sd_radv_set_managed_information(sd_radv *ra, int managed) {
        assert_return(ra, -EINVAL);

        if (ra->state != SD_RADV_STATE_IDLE)
                return -EBUSY;

        SET_FLAG(ra->flags, ND_RA_FLAG_MANAGED, managed);

        return 0;
}

_public_ int sd_radv_set_other_information(sd_radv *ra, int other) {
        assert_return(ra, -EINVAL);

        if (ra->state != SD_RADV_STATE_IDLE)
                return -EBUSY;

        SET_FLAG(ra->flags, ND_RA_FLAG_OTHER, other);

        return 0;
}

_public_ int sd_radv_set_preference(sd_radv *ra, unsigned preference) {
        int r = 0;

        assert_return(ra, -EINVAL);
        assert_return(IN_SET(preference,
                             SD_NDISC_PREFERENCE_LOW,
                             SD_NDISC_PREFERENCE_MEDIUM,
                             SD_NDISC_PREFERENCE_HIGH), -EINVAL);

        ra->flags = (ra->flags & ~(0x3 << 3)) | (preference << 3);

        return r;
}

_public_ int sd_radv_add_prefix(sd_radv *ra, sd_radv_prefix *p) {
        sd_radv_prefix *cur;
        _cleanup_free_ char *addr_p = NULL;

        assert_return(ra, -EINVAL);

        if (!p)
                return -EINVAL;

        LIST_FOREACH(prefix, cur, ra->prefixes) {
                int r;

                r = in_addr_prefix_intersect(AF_INET6,
                                             (union in_addr_union*) &cur->opt.in6_addr,
                                             cur->opt.prefixlen,
                                             (union in_addr_union*) &p->opt.in6_addr,
                                             p->opt.prefixlen);
                if (r > 0) {
                        _cleanup_free_ char *addr_cur = NULL;

                        (void) in_addr_to_string(AF_INET6,
                                                 (union in_addr_union*) &cur->opt.in6_addr,
                                                 &addr_cur);
                        (void) in_addr_to_string(AF_INET6,
                                                 (union in_addr_union*) &p->opt.in6_addr,
                                                 &addr_p);

                        log_radv("IPv6 prefix %s/%u already configured, ignoring %s/%u",
                                 addr_cur, cur->opt.prefixlen,
                                 addr_p, p->opt.prefixlen);

                        return -EEXIST;
                }
        }

        p = sd_radv_prefix_ref(p);

        LIST_APPEND(prefix, ra->prefixes, p);

        ra->n_prefixes++;

        (void) in_addr_to_string(AF_INET6, (union in_addr_union*) &p->opt.in6_addr, &addr_p);
        log_radv("Added prefix %s/%d", addr_p, p->opt.prefixlen);

        return 0;
}

_public_ int sd_radv_prefix_new(sd_radv_prefix **ret) {
        _cleanup_(sd_radv_prefix_unrefp) sd_radv_prefix *p = NULL;

        assert_return(ret, -EINVAL);

        p = new0(sd_radv_prefix, 1);
        if (!p)
                return -ENOMEM;

        p->n_ref = 1;

        p->opt.type = ND_OPT_PREFIX_INFORMATION;
        p->opt.length = (sizeof(p->opt) - 1) /8 + 1;

        p->opt.prefixlen = 64;

        /* RFC 4861, Section 6.2.1 */
        SET_FLAG(p->opt.flags, ND_OPT_PI_FLAG_ONLINK, true);
        SET_FLAG(p->opt.flags, ND_OPT_PI_FLAG_AUTO, true);
        p->opt.preferred_lifetime = htobe32(604800);
        p->opt.valid_lifetime = htobe32(2592000);

        LIST_INIT(prefix, p);

        *ret = p;
        p = NULL;

        return 0;
}

_public_ sd_radv_prefix *sd_radv_prefix_ref(sd_radv_prefix *p) {
        if (!p)
                return NULL;

        assert(p->n_ref > 0);
        p->n_ref++;

        return p;
}

_public_ sd_radv_prefix *sd_radv_prefix_unref(sd_radv_prefix *p) {
        if (!p)
                return NULL;

        assert(p->n_ref > 0);
        p->n_ref--;

        if (p->n_ref > 0)
                return NULL;

        return mfree(p);
}

_public_ int sd_radv_prefix_set_prefix(sd_radv_prefix *p, struct in6_addr *in6_addr,
                                       unsigned char prefixlen) {
        assert_return(p, -EINVAL);
        assert_return(in6_addr, -EINVAL);

        if (prefixlen < 3 || prefixlen > 128)
                return -EINVAL;

        if (prefixlen > 64)
                /* unusual but allowed, log it */
                log_radv("Unusual prefix length %d greater than 64", prefixlen);

        p->opt.in6_addr = *in6_addr;
        p->opt.prefixlen = prefixlen;

        return 0;
}

_public_ int sd_radv_prefix_set_onlink(sd_radv_prefix *p, int onlink) {
        assert_return(p, -EINVAL);

        SET_FLAG(p->opt.flags, ND_OPT_PI_FLAG_ONLINK, onlink);

        return 0;
}

_public_ int sd_radv_prefix_set_address_autoconfiguration(sd_radv_prefix *p,
                                                          int address_autoconfiguration) {
        assert_return(p, -EINVAL);

        SET_FLAG(p->opt.flags, ND_OPT_PI_FLAG_AUTO, address_autoconfiguration);

        return 0;
}

_public_ int sd_radv_prefix_set_valid_lifetime(sd_radv_prefix *p,
                                               uint32_t valid_lifetime) {
        assert_return(p, -EINVAL);

        p->opt.valid_lifetime = htobe32(valid_lifetime);

        return 0;
}

_public_ int sd_radv_prefix_set_preferred_lifetime(sd_radv_prefix *p,
                                                   uint32_t preferred_lifetime) {
        assert_return(p, -EINVAL);

        p->opt.preferred_lifetime = htobe32(preferred_lifetime);

        return 0;
}
