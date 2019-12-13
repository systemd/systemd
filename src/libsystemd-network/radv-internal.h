/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright © 2017 Intel Corporation. All rights reserved.
***/

#include "sd-radv.h"

#include "log.h"
#include "list.h"
#include "sparse-endian.h"

assert_cc(SD_RADV_DEFAULT_MIN_TIMEOUT_USEC <= SD_RADV_DEFAULT_MAX_TIMEOUT_USEC);

#define SD_RADV_MAX_INITIAL_RTR_ADVERT_INTERVAL_USEC (16*USEC_PER_SEC)
#define SD_RADV_MAX_INITIAL_RTR_ADVERTISEMENTS  3
#define SD_RADV_MAX_FINAL_RTR_ADVERTISEMENTS    3
#define SD_RADV_MIN_DELAY_BETWEEN_RAS           3
#define SD_RADV_MAX_RA_DELAY_TIME_USEC          (500*USEC_PER_MSEC)

#define SD_RADV_OPT_ROUTE_INFORMATION           24
#define SD_RADV_OPT_RDNSS                       25
#define SD_RADV_OPT_DNSSL                       31

enum RAdvState {
        SD_RADV_STATE_IDLE                      = 0,
        SD_RADV_STATE_ADVERTISING               = 1,
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

        sd_event *event;
        int event_priority;

        struct ether_addr mac_addr;
        uint8_t hop_limit;
        uint8_t flags;
        uint32_t mtu;
        uint16_t lifetime;

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
        be32_t valid_lifetime;                  \
        be32_t preferred_lifetime;              \
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
};

#define log_radv_full(level, error, fmt, ...) log_internal(level, error, PROJECT_FILE, __LINE__, __func__, "RADV: " fmt, ##__VA_ARGS__)
#define log_radv_errno(error, fmt, ...) log_radv_full(LOG_DEBUG, error, fmt, ##__VA_ARGS__)
#define log_radv(fmt, ...) log_radv_errno(0, fmt, ##__VA_ARGS__)
