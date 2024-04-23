/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2017 Intel Corporation. All rights reserved.
***/

#include <linux/ipv6.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sd-radv.h"

#include "alloc-util.h"
#include "dns-domain.h"
#include "ether-addr-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "icmp6-util.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "macro.h"
#include "memory-util.h"
#include "ndisc-router-solicit-internal.h"
#include "network-common.h"
#include "radv-internal.h"
#include "random-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "unaligned.h"

int sd_radv_new(sd_radv **ret) {
        _cleanup_(sd_radv_unrefp) sd_radv *ra = NULL;

        assert_return(ret, -EINVAL);

        ra = new(sd_radv, 1);
        if (!ra)
                return -ENOMEM;

        *ra = (sd_radv) {
                .n_ref = 1,
                .fd = -EBADF,
                .lifetime_usec = RADV_DEFAULT_ROUTER_LIFETIME_USEC,
        };

        *ret = TAKE_PTR(ra);

        return 0;
}

int sd_radv_attach_event(sd_radv *ra, sd_event *event, int64_t priority) {
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

int sd_radv_detach_event(sd_radv *ra) {
        assert_return(ra, -EINVAL);

        ra->event = sd_event_unref(ra->event);
        return 0;
}

sd_event *sd_radv_get_event(sd_radv *ra) {
        assert_return(ra, NULL);

        return ra->event;
}

int sd_radv_is_running(sd_radv *ra) {
        if (!ra)
                return false;

        return ra->state != RADV_STATE_IDLE;
}

static void radv_reset(sd_radv *ra) {
        assert(ra);

        (void) event_source_disable(ra->timeout_event_source);

        ra->recv_event_source = sd_event_source_disable_unref(ra->recv_event_source);

        ra->ra_sent = 0;
}

static sd_radv *radv_free(sd_radv *ra) {
        if (!ra)
                return NULL;

        radv_reset(ra);

        sd_event_source_unref(ra->timeout_event_source);
        sd_radv_detach_event(ra);

        ra->fd = safe_close(ra->fd);
        free(ra->ifname);

        set_free(ra->options);

        return mfree(ra);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_radv, sd_radv, radv_free);

static bool router_lifetime_is_valid(usec_t lifetime_usec) {
        assert_cc(RADV_MAX_ROUTER_LIFETIME_USEC <= UINT16_MAX * USEC_PER_SEC);
        return lifetime_usec == 0 ||
                (lifetime_usec >= RADV_MIN_ROUTER_LIFETIME_USEC &&
                 lifetime_usec <= RADV_MAX_ROUTER_LIFETIME_USEC);
}

static int radv_send_router_on_stop(sd_radv *ra) {
        static const struct nd_router_advert adv = {
                .nd_ra_type = ND_ROUTER_ADVERT,
        };

        _cleanup_set_free_ Set *options = NULL;
        struct ether_addr mac_addr;
        usec_t time_now;
        int r;

        assert(ra);

        r = sd_event_now(ra->event, CLOCK_BOOTTIME, &time_now);
        if (r < 0)
                return r;

        /* On stop, we only send source link-layer address option. */
        if (ndisc_option_get_mac(ra->options, SD_NDISC_OPTION_SOURCE_LL_ADDRESS, &mac_addr) >= 0) {
                r = ndisc_option_set_link_layer_address(&options, SD_NDISC_OPTION_SOURCE_LL_ADDRESS, &mac_addr);
                if (r < 0)
                        return r;
        }

        return ndisc_send(ra->fd, &IN6_ADDR_ALL_NODES_MULTICAST, &adv.nd_ra_hdr, options, time_now);
}

static int radv_send_router(sd_radv *ra, const struct in6_addr *dst) {
        assert(ra);

        struct nd_router_advert adv = {
                .nd_ra_type = ND_ROUTER_ADVERT,
                .nd_ra_router_lifetime = usec_to_be16_sec(ra->lifetime_usec),
                .nd_ra_reachable = usec_to_be32_msec(ra->reachable_usec),
                .nd_ra_retransmit = usec_to_be32_msec(ra->retransmit_usec),
        };
        usec_t time_now;
        int r;

        r = sd_event_now(ra->event, CLOCK_BOOTTIME, &time_now);
        if (r < 0)
                return r;

        /* The nd_ra_curhoplimit and nd_ra_flags_reserved fields cannot specified with nd_ra_router_lifetime
         * simultaneously in the structured initializer in the above. */
        adv.nd_ra_curhoplimit = ra->hop_limit;
        /* RFC 4191, Section 2.2,
         * "...If the Router Lifetime is zero, the preference value MUST be set to (00) by the sender..." */
        adv.nd_ra_flags_reserved = ra->flags | (ra->lifetime_usec > 0 ? (ra->preference << 3) : 0);

        return ndisc_send(ra->fd,
                          (dst && in6_addr_is_set(dst)) ? dst : &IN6_ADDR_ALL_NODES_MULTICAST,
                          &adv.nd_ra_hdr, ra->options, time_now);
}

static int radv_process_packet(sd_radv *ra, ICMP6Packet *packet) {
        int r;

        assert(ra);
        assert(packet);

        if (icmp6_packet_get_type(packet) != ND_ROUTER_SOLICIT)
                return log_radv_errno(ra, SYNTHETIC_ERRNO(EBADMSG), "Received ICMP6 packet with unexpected type, ignoring.");

        _cleanup_(sd_ndisc_router_solicit_unrefp) sd_ndisc_router_solicit *rs = NULL;
        rs = ndisc_router_solicit_new(packet);
        if (!rs)
                return log_oom_debug();

        r = ndisc_router_solicit_parse(ra, rs);
        if (r < 0)
                return r;

        struct in6_addr src;
        r = sd_ndisc_router_solicit_get_sender_address(rs, &src);
        if (r == -ENODATA) /* null address is allowed */
                return sd_radv_send(ra); /* When an unsolicited RA, we need to also update timer. */
        if (r < 0)
                return log_radv_errno(ra, r, "Failed to get sender address of RS, ignoring: %m");
        if (in6_addr_equal(&src, &ra->ipv6ll))
                /* This should be definitely caused by a misconfiguration. If we send RA to ourself, the
                 * kernel complains about that. Let's ignore the packet. */
                return log_radv_errno(ra, SYNTHETIC_ERRNO(EADDRINUSE), "Received RS from the same interface, ignoring.");

        r = radv_send_router(ra, &src);
        if (r < 0)
                return log_radv_errno(ra, r, "Unable to send solicited Router Advertisement to %s, ignoring: %m", IN6_ADDR_TO_STRING(&src));

        log_radv(ra, "Sent solicited Router Advertisement to %s.", IN6_ADDR_TO_STRING(&src));
        return 0;
}

static int radv_recv(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(icmp6_packet_unrefp) ICMP6Packet *packet = NULL;
        sd_radv *ra = ASSERT_PTR(userdata);
        int r;

        assert(fd >= 0);

        r = icmp6_packet_receive(fd, &packet);
        if (r < 0) {
                log_radv_errno(ra, r, "Failed to receive ICMPv6 packet, ignoring: %m");
                return 0;
        }

        (void) radv_process_packet(ra, packet);
        return 0;
}

static int radv_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_radv *ra = ASSERT_PTR(userdata);

        if (sd_radv_send(ra) < 0)
                (void) sd_radv_stop(ra);

        return 0;
}

int sd_radv_send(sd_radv *ra) {
        usec_t min_timeout, max_timeout, time_now, timeout;
        int r;

        assert_return(ra, -EINVAL);
        assert_return(ra->event, -EINVAL);
        assert_return(sd_radv_is_running(ra), -EINVAL);
        assert(router_lifetime_is_valid(ra->lifetime_usec));

        r = sd_event_now(ra->event, CLOCK_BOOTTIME, &time_now);
        if (r < 0)
                return r;

        r = radv_send_router(ra, NULL);
        if (r < 0)
                return log_radv_errno(ra, r, "Unable to send Router Advertisement: %m");

        ra->ra_sent++;

        /* RFC 4861, Section 6.2.4, sending initial Router Advertisements */
        if (ra->ra_sent <= RADV_MAX_INITIAL_RTR_ADVERTISEMENTS)
                max_timeout = RADV_MAX_INITIAL_RTR_ADVERT_INTERVAL_USEC;
        else
                max_timeout = RADV_DEFAULT_MAX_TIMEOUT_USEC;

        /* RFC 4861, Section 6.2.1, lifetime must be at least MaxRtrAdvInterval,
         * so lower the interval here */
        if (ra->lifetime_usec > 0)
                max_timeout = MIN(max_timeout, ra->lifetime_usec);

        if (max_timeout >= 9 * USEC_PER_SEC)
                min_timeout = max_timeout / 3;
        else
                min_timeout = max_timeout * 3 / 4;

        /* RFC 4861, Section 6.2.1.
         * MaxRtrAdvInterval MUST be no less than 4 seconds and no greater than 1800 seconds.
         * MinRtrAdvInterval MUST be no less than 3 seconds and no greater than .75 * MaxRtrAdvInterval. */
        assert(max_timeout >= RADV_MIN_MAX_TIMEOUT_USEC);
        assert(max_timeout <= RADV_MAX_MAX_TIMEOUT_USEC);
        assert(min_timeout >= RADV_MIN_MIN_TIMEOUT_USEC);
        assert(min_timeout <= max_timeout * 3 / 4);

        timeout = min_timeout + random_u64_range(max_timeout - min_timeout);
        log_radv(ra, "Sent unsolicited Router Advertisement. Next advertisement will be in %s.",
                 FORMAT_TIMESPAN(timeout, USEC_PER_SEC));

        return event_reset_time(
                        ra->event, &ra->timeout_event_source,
                        CLOCK_BOOTTIME,
                        usec_add(time_now, timeout), MSEC_PER_SEC,
                        radv_timeout, ra,
                        ra->event_priority, "radv-timeout", true);
}

int sd_radv_stop(sd_radv *ra) {
        int r;

        if (!sd_radv_is_running(ra))
                return 0; /* Already stopped. */

        log_radv(ra, "Stopping IPv6 Router Advertisement daemon");

        /* RFC 4861, Section 6.2.5:
         * the router SHOULD transmit one or more (but not more than MAX_FINAL_RTR_ADVERTISEMENTS) final
         * multicast Router Advertisements on the interface with a Router Lifetime field of zero. */
        r = radv_send_router_on_stop(ra);
        if (r < 0)
                log_radv_errno(ra, r, "Unable to send last Router Advertisement with router lifetime set to zero, ignoring: %m");

        radv_reset(ra);
        ra->fd = safe_close(ra->fd);
        ra->state = RADV_STATE_IDLE;

        return 0;
}

static int radv_setup_recv_event(sd_radv *ra) {
        int r;

        assert(ra);
        assert(ra->event);
        assert(ra->ifindex > 0);

        _cleanup_close_ int fd = -EBADF;
        fd = icmp6_bind(ra->ifindex, /* is_router = */ true);
        if (fd < 0)
                return fd;

        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        r = sd_event_add_io(ra->event, &s, fd, EPOLLIN, radv_recv, ra);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(s, ra->event_priority);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(s, "radv-receive-message");

        ra->fd = TAKE_FD(fd);
        ra->recv_event_source = TAKE_PTR(s);
        return 0;
}

int sd_radv_start(sd_radv *ra) {
        int r;

        assert_return(ra, -EINVAL);
        assert_return(ra->event, -EINVAL);
        assert_return(ra->ifindex > 0, -EINVAL);

        if (sd_radv_is_running(ra))
                return 0; /* Already started. */

        r = radv_setup_recv_event(ra);
        if (r < 0)
                goto fail;

        r = event_reset_time(ra->event, &ra->timeout_event_source,
                             CLOCK_BOOTTIME,
                             0, 0,
                             radv_timeout, ra,
                             ra->event_priority, "radv-timeout", true);
        if (r < 0)
                goto fail;

        ra->state = RADV_STATE_ADVERTISING;

        log_radv(ra, "Started IPv6 Router Advertisement daemon");

        return 0;

 fail:
        radv_reset(ra);

        return r;
}

int sd_radv_set_ifindex(sd_radv *ra, int ifindex) {
        assert_return(ra, -EINVAL);
        assert_return(!sd_radv_is_running(ra), -EBUSY);
        assert_return(ifindex > 0, -EINVAL);

        ra->ifindex = ifindex;
        return 0;
}

int sd_radv_set_ifname(sd_radv *ra, const char *ifname) {
        assert_return(ra, -EINVAL);
        assert_return(ifname, -EINVAL);

        if (!ifname_valid_full(ifname, IFNAME_VALID_ALTERNATIVE))
                return -EINVAL;

        return free_and_strdup(&ra->ifname, ifname);
}

int sd_radv_get_ifname(sd_radv *ra, const char **ret) {
        int r;

        assert_return(ra, -EINVAL);

        r = get_ifname(ra->ifindex, &ra->ifname);
        if (r < 0)
                return r;

        if (ret)
                *ret = ra->ifname;

        return 0;
}

int sd_radv_set_link_local_address(sd_radv *ra, const struct in6_addr *addr) {
        assert_return(ra, -EINVAL);
        assert_return(!addr || in6_addr_is_link_local(addr), -EINVAL);

        if (addr)
                ra->ipv6ll = *addr;
        else
                zero(ra->ipv6ll);

        return 0;
}

/* Managing RA header. */

int sd_radv_set_hop_limit(sd_radv *ra, uint8_t hop_limit) {
        assert_return(ra, -EINVAL);

        ra->hop_limit = hop_limit;
        return 0;
}

int sd_radv_set_reachable_time(sd_radv *ra, uint64_t usec) {
        assert_return(ra, -EINVAL);

        ra->reachable_usec = usec;
        return 0;
}

int sd_radv_set_retransmit(sd_radv *ra, uint64_t usec) {
        assert_return(ra, -EINVAL);

        ra->retransmit_usec = usec;
        return 0;
}

int sd_radv_set_router_lifetime(sd_radv *ra, uint64_t usec) {
        assert_return(ra, -EINVAL);

        if (!router_lifetime_is_valid(usec))
                return -EINVAL;

        ra->lifetime_usec = usec;
        return 0;
}

int sd_radv_set_managed_information(sd_radv *ra, int b) {
        assert_return(ra, -EINVAL);

        SET_FLAG(ra->flags, ND_RA_FLAG_MANAGED, b);
        return 0;
}

int sd_radv_set_other_information(sd_radv *ra, int b) {
        assert_return(ra, -EINVAL);

        SET_FLAG(ra->flags, ND_RA_FLAG_OTHER, b);
        return 0;
}

int sd_radv_set_preference(sd_radv *ra, uint8_t preference) {
        assert_return(ra, -EINVAL);
        assert_return(IN_SET(preference,
                             SD_NDISC_PREFERENCE_LOW,
                             SD_NDISC_PREFERENCE_MEDIUM,
                             SD_NDISC_PREFERENCE_HIGH), -EINVAL);

        ra->preference = preference;
        return 0;
}

/* Managing options. */

int sd_radv_set_mac(sd_radv *ra, const struct ether_addr *mac_addr) {
        assert_return(ra, -EINVAL);

        return ndisc_option_set_link_layer_address(&ra->options, SD_NDISC_OPTION_SOURCE_LL_ADDRESS, mac_addr);
}

void sd_radv_unset_mac(sd_radv *ra) {
        if (!ra)
                return;

        ndisc_option_remove_by_type(ra->options, SD_NDISC_OPTION_SOURCE_LL_ADDRESS);
}

int sd_radv_add_prefix(
                sd_radv *ra,
                const struct in6_addr *prefix,
                uint8_t prefixlen,
                uint8_t flags,
                uint64_t valid_lifetime_usec,
                uint64_t preferred_lifetime_usec,
                uint64_t valid_until,
                uint64_t preferred_until) {

        assert_return(ra, -EINVAL);
        assert_return(prefix, -EINVAL);

        sd_ndisc_option *opt;
        SET_FOREACH(opt, ra->options) {
                if (opt->type != SD_NDISC_OPTION_PREFIX_INFORMATION)
                        continue;

                if (!in6_addr_prefix_intersect(&opt->prefix.address, opt->prefix.prefixlen, prefix, prefixlen))
                        continue; /* no intersection */

                if (opt->prefix.prefixlen == prefixlen)
                        break; /* same prefix */

                return log_radv_errno(ra, SYNTHETIC_ERRNO(EEXIST),
                                      "IPv6 prefix %s conflicts with %s, ignoring.",
                                      IN6_ADDR_PREFIX_TO_STRING(prefix, prefixlen),
                                      IN6_ADDR_PREFIX_TO_STRING(&opt->prefix.address, opt->prefix.prefixlen));
        }

        return ndisc_option_set_prefix(
                        &ra->options,
                        flags,
                        prefixlen,
                        prefix,
                        valid_lifetime_usec,
                        preferred_lifetime_usec,
                        valid_until,
                        preferred_until);
}

void sd_radv_remove_prefix(
                sd_radv *ra,
                const struct in6_addr *prefix,
                uint8_t prefixlen) {

        if (!ra || !prefix)
                return;

        ndisc_option_remove(ra->options,
                            &(sd_ndisc_option) {
                                    .type = SD_NDISC_OPTION_PREFIX_INFORMATION,
                                    .prefix.prefixlen = prefixlen,
                                    .prefix.address = *prefix,
                            });
}

int sd_radv_set_mtu(sd_radv *ra, uint32_t mtu) {
        assert_return(ra, -EINVAL);
        assert_return(mtu >= IPV6_MIN_MTU, -EINVAL);

        return ndisc_option_set_mtu(&ra->options, mtu);
}

void sd_radv_unset_mtu(sd_radv *ra) {
        if (!ra)
                return;

        ndisc_option_remove_by_type(ra->options, SD_NDISC_OPTION_MTU);
}

int sd_radv_set_home_agent(sd_radv *ra, uint16_t preference, uint64_t lifetime_usec, uint64_t valid_until) {
        assert_return(ra, -EINVAL);

        ra->flags |= ND_RA_FLAG_HOME_AGENT;
        return ndisc_option_set_home_agent(&ra->options, preference, lifetime_usec, valid_until);
}

void sd_radv_unset_home_agent(sd_radv *ra) {
        if (!ra)
                return;

        ra->flags &= ~ND_RA_FLAG_HOME_AGENT;
        ndisc_option_remove_by_type(ra->options, SD_NDISC_OPTION_HOME_AGENT);
}

int sd_radv_add_route(
                sd_radv *ra,
                const struct in6_addr *prefix,
                uint8_t prefixlen,
                uint8_t preference,
                uint64_t lifetime_usec,
                uint64_t valid_until) {

        assert_return(ra, -EINVAL);
        assert_return(prefix, -EINVAL);

        return ndisc_option_set_route(
                        &ra->options,
                        preference,
                        prefixlen,
                        prefix,
                        lifetime_usec,
                        valid_until);
}

void sd_radv_remove_route(
                sd_radv *ra,
                const struct in6_addr *prefix,
                uint8_t prefixlen) {

        if (!ra || !prefix)
                return;

        ndisc_option_remove(ra->options,
                            &(sd_ndisc_option) {
                                    .type = SD_NDISC_OPTION_ROUTE_INFORMATION,
                                    .route.prefixlen = prefixlen,
                                    .route.address = *prefix,
                            });
}

int sd_radv_add_rdnss(
                sd_radv *ra,
                size_t n_dns,
                const struct in6_addr *dns,
                uint64_t lifetime_usec,
                uint64_t valid_until) {

        assert_return(ra, -EINVAL);
        assert_return(dns, -EINVAL);

        return ndisc_option_set_rdnss(
                        &ra->options,
                        n_dns,
                        dns,
                        lifetime_usec,
                        valid_until);
}

void sd_radv_clear_rdnss(sd_radv *ra) {
        if (!ra)
                return;

        sd_ndisc_option *opt;
        SET_FOREACH(opt, ra->options)
                if (opt->type == SD_NDISC_OPTION_RDNSS)
                        ndisc_option_remove(ra->options, opt);
}

int sd_radv_add_dnssl(
                sd_radv *ra,
                char * const *domains,
                uint64_t lifetime_usec,
                uint64_t valid_until) {

        assert_return(ra, -EINVAL);

        return ndisc_option_set_dnssl(
                        &ra->options,
                        domains,
                        lifetime_usec,
                        valid_until);
}

void sd_radv_clear_dnssl(sd_radv *ra) {
        if (!ra)
                return;

        sd_ndisc_option *opt;
        SET_FOREACH(opt, ra->options)
                if (opt->type == SD_NDISC_OPTION_DNSSL)
                        ndisc_option_remove(ra->options, opt);
}

int sd_radv_set_captive_portal(sd_radv *ra, const char *portal) {
        assert_return(ra, -EINVAL);
        assert_return(portal, -EINVAL);

        return ndisc_option_set_captive_portal(&ra->options, portal);
}

void sd_radv_unset_captive_portal(sd_radv *ra) {
        if (!ra)
                return;

        ndisc_option_remove_by_type(ra->options, SD_NDISC_OPTION_CAPTIVE_PORTAL);
}

int sd_radv_add_prefix64(
                sd_radv *ra,
                const struct in6_addr *prefix,
                uint8_t prefixlen,
                uint64_t lifetime_usec,
                uint64_t valid_until) {

        assert_return(ra, -EINVAL);
        assert_return(prefix, -EINVAL);

        return ndisc_option_set_prefix64(
                        &ra->options,
                        prefixlen,
                        prefix,
                        lifetime_usec,
                        valid_until);
}

void sd_radv_remove_prefix64(
                sd_radv *ra,
                const struct in6_addr *prefix,
                uint8_t prefixlen) {

        if (!ra || !prefix)
                return;

        ndisc_option_remove(ra->options,
                            &(sd_ndisc_option) {
                                    .type = SD_NDISC_OPTION_PREF64,
                                    .prefix64.prefixlen = prefixlen,
                                    .prefix64.prefix = *prefix,
                            });
}
