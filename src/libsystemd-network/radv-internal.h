/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2017 Intel Corporation. All rights reserved.
***/

#include <netinet/icmp6.h>

#include "sd-radv.h"

#include "list.h"
#include "ndisc-option.h"
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
/* RFC 4861 section 4.2.
 * Reachable Time and Retrans Timer
 * 32-bit unsigned integer. The time, in milliseconds. */
#define RADV_MAX_UINT32_MSEC_USEC                 (UINT32_MAX * USEC_PER_MSEC)
#define RADV_MAX_REACHABLE_TIME_USEC              RADV_MAX_UINT32_MSEC_USEC
#define RADV_MAX_RETRANSMIT_USEC                  RADV_MAX_UINT32_MSEC_USEC
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
/* From RFC 8781 section 4.1
 * By default, the value of the Scaled Lifetime field SHOULD be set to the lesser of 3 x MaxRtrAdvInterval */
#define RADV_PREF64_DEFAULT_LIFETIME_USEC         (3 * RADV_DEFAULT_MAX_TIMEOUT_USEC)

#define RADV_RDNSS_MAX_LIFETIME_USEC              (UINT32_MAX * USEC_PER_SEC)
#define RADV_DNSSL_MAX_LIFETIME_USEC              (UINT32_MAX * USEC_PER_SEC)
/* rfc6275 7.4 Neighbor Discovery Home Agent Lifetime.
 * The default value is the same as the Router Lifetime.
 * The maximum value corresponds to 18.2 hours. 0 MUST NOT be used. */
#define RADV_HOME_AGENT_MAX_LIFETIME_USEC         (UINT16_MAX * USEC_PER_SEC)

typedef enum RAdvState {
        RADV_STATE_IDLE                      = 0,
        RADV_STATE_ADVERTISING               = 1,
} RAdvState;

struct sd_radv {
        unsigned n_ref;
        RAdvState state;

        int ifindex;
        char *ifname;
        struct in6_addr ipv6ll;

        sd_event *event;
        int event_priority;

        uint8_t hop_limit;
        uint8_t flags;
        uint8_t preference;
        usec_t reachable_usec;
        usec_t retransmit_usec;
        usec_t lifetime_usec; /* timespan */

        Set *options;

        int fd;
        unsigned ra_sent;
        sd_event_source *recv_event_source;
        sd_event_source *timeout_event_source;
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
