/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2017 Intel Corporation. All rights reserved.
***/

#include "sd-radv.h"

#include "list.h"
#include "network-common.h"
#include "sparse-endian.h"
#include "time-util.h"

/* RFC 4861 section 6.2.1.
 * MaxRtrAdvInterval
 * The maximum time allowed between sending unsolicited multicast Router Advertisements from the
 * interface, in seconds. MUST be no less than 4 seconds and no greater than 1800 seconds.
 * Default: 600 seconds */
#define RADV_MIN_MAX_TIMEOUT_USEC                 (4 * USEC_PER_SEC)
#define RADV_MAX_MAX_TIMEOUT_USEC                 (1800 * USEC_PER_SEC)
#define RADV_DEFAULT_MAX_TIMEOUT_USEC             (600 * USEC_PER_SEC)
/* RFC 4861 section 6.2.1.
 * MinRtrAdvInterval
 * The minimum time allowed between sending unsolicited multicast Router Advertisements from the
 * interface, in seconds. MUST be no less than 3 seconds and no greater than .75 * MaxRtrAdvInterval.
 * Default: 0.33 * MaxRtrAdvInterval If MaxRtrAdvInterval >= 9 seconds; otherwise, the Default is
 * MaxRtrAdvInterval (Note, this should be a typo. We use 0.75 * MaxRtrAdvInterval). */
#define RADV_MIN_MIN_TIMEOUT_USEC                 (3 * USEC_PER_SEC)
/* RFC 4861 section 6.2.4.
 * AdvDefaultLifetime
 * The value to be placed in the Router Lifetime field of Router Advertisements sent from the interface,
 * in seconds. MUST be either zero or between MaxRtrAdvInterval and 9000 seconds. A value of zero
 * indicates that the router is not to be used as a default router. These limits may be overridden by
 * specific documents that describe how IPv6 operates over different link layers. For instance, in a
 * point-to-point link the peers may have enough information about the number and status of devices at
 * the other end so that advertisements are needed less frequently.
 * Default: 3 * MaxRtrAdvInterval */
#define RADV_MIN_ROUTER_LIFETIME_USEC             RADV_MIN_MAX_TIMEOUT_USEC
#define RADV_MAX_ROUTER_LIFETIME_USEC             (9000 * USEC_PER_SEC)
#define RADV_DEFAULT_ROUTER_LIFETIME_USEC         (3 * RADV_DEFAULT_MAX_TIMEOUT_USEC)
/* draft-ietf-6man-slaac-renum-02 section 4.1.1.
 * AdvPreferredLifetime: max(AdvDefaultLifetime, 3 * MaxRtrAdvInterval)
 * AdvValidLifetime: 2 * AdvPreferredLifetime */
#define RADV_DEFAULT_PREFERRED_LIFETIME_USEC      CONST_MAX(RADV_DEFAULT_ROUTER_LIFETIME_USEC, 3 * RADV_DEFAULT_MAX_TIMEOUT_USEC)
#define RADV_DEFAULT_VALID_LIFETIME_USEC          (2 * RADV_DEFAULT_PREFERRED_LIFETIME_USEC)
/* RFC 4861 section 10.
 * MAX_INITIAL_RTR_ADVERT_INTERVAL  16 seconds
 * MAX_INITIAL_RTR_ADVERTISEMENTS    3 transmissions
 * MAX_FINAL_RTR_ADVERTISEMENTS      3 transmissions
 * MIN_DELAY_BETWEEN_RAS             3 seconds
 * MAX_RA_DELAY_TIME                .5 seconds */
#define RADV_MAX_INITIAL_RTR_ADVERT_INTERVAL_USEC (16 * USEC_PER_SEC)
#define RADV_MAX_INITIAL_RTR_ADVERTISEMENTS       3
#define RADV_MAX_FINAL_RTR_ADVERTISEMENTS         3
#define RADV_MIN_DELAY_BETWEEN_RAS                3
#define RADV_MAX_RA_DELAY_TIME_USEC               (500 * USEC_PER_MSEC)

#define RADV_OPT_ROUTE_INFORMATION                24
#define RADV_OPT_RDNSS                            25
#define RADV_OPT_DNSSL                            31

enum RAdvState {
        RADV_STATE_IDLE                      = 0,
        RADV_STATE_ADVERTISING               = 1,
};
typedef enum RAdvState RAdvState;

struct sd_radv_opt_dns {
        uint8_t type;
        uint8_t length;
        uint16_t reserved;
        be32_t lifetime;
} _packed_;

struct sd_radv {
        unsigned n_ref;
        RAdvState state;

        int ifindex;
        char *ifname;

        sd_event *event;
        int event_priority;

        struct ether_addr mac_addr;
        uint8_t hop_limit;
        uint8_t flags;
        uint32_t mtu;
        usec_t lifetime_usec; /* timespan */

        int fd;
        unsigned ra_sent;
        sd_event_source *recv_event_source;
        sd_event_source *timeout_event_source;

        unsigned n_prefixes;
        LIST_HEAD(sd_radv_prefix, prefixes);

        unsigned n_route_prefixes;
        LIST_HEAD(sd_radv_route_prefix, route_prefixes);

        size_t n_rdnss;
        struct sd_radv_opt_dns *rdnss;
        struct sd_radv_opt_dns *dnssl;
};

#define radv_prefix_opt__contents {             \
        uint8_t type;                           \
        uint8_t length;                         \
        uint8_t prefixlen;                      \
        uint8_t flags;                          \
        be32_t lifetime_valid;                  \
        be32_t lifetime_preferred;              \
        uint32_t reserved;                      \
        struct in6_addr in6_addr;               \
}

struct radv_prefix_opt radv_prefix_opt__contents;

/* We need the opt substructure to be packed, because we use it in send(). But
 * if we use _packed_, this means that the structure cannot be used directly in
 * normal code in general, because the fields might not be properly aligned.
 * But in this particular case, the structure is defined in a way that gives
 * proper alignment, even without the explicit _packed_ attribute. To appease
 * the compiler we use the "unpacked" structure, but we also verify that
 * structure contains no holes, so offsets are the same when _packed_ is used.
 */
struct radv_prefix_opt__packed radv_prefix_opt__contents _packed_;
assert_cc(sizeof(struct radv_prefix_opt) == sizeof(struct radv_prefix_opt__packed));

struct sd_radv_prefix {
        unsigned n_ref;

        struct radv_prefix_opt opt;

        LIST_FIELDS(struct sd_radv_prefix, prefix);

        /* These are timespans, NOT points in time. */
        usec_t lifetime_valid_usec;
        usec_t lifetime_preferred_usec;
        /* These are points in time specified with clock_boottime_or_monotonic(), NOT timespans. */
        usec_t valid_until;
        usec_t preferred_until;
};

#define radv_route_prefix_opt__contents {       \
        uint8_t type;                           \
        uint8_t length;                         \
        uint8_t prefixlen;                      \
        uint8_t flags_reserved;                 \
        be32_t  lifetime;                       \
        struct in6_addr in6_addr;               \
}

struct radv_route_prefix_opt radv_route_prefix_opt__contents;

struct radv_route_prefix_opt__packed radv_route_prefix_opt__contents _packed_;
assert_cc(sizeof(struct radv_route_prefix_opt) == sizeof(struct radv_route_prefix_opt__packed));

struct sd_radv_route_prefix {
        unsigned n_ref;

        struct radv_route_prefix_opt opt;

        LIST_FIELDS(struct sd_radv_route_prefix, prefix);

        /* This is a timespan, NOT a point in time. */
        usec_t lifetime_usec;
        /* This is a point in time specified with clock_boottime_or_monotonic(), NOT a timespan. */
        usec_t valid_until;
};

#define log_radv_errno(radv, error, fmt, ...)           \
        log_interface_prefix_full_errno(                \
                "RADV: ",                               \
                sd_radv, radv,                          \
                error, fmt, ##__VA_ARGS__)
#define log_radv(radv, fmt, ...)                        \
        log_interface_prefix_full_errno_zerook(         \
                "RADV: ",                               \
                sd_radv, radv,                          \
                0, fmt, ##__VA_ARGS__)
