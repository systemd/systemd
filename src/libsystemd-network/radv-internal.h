/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright © 2017 Intel Corporation. All rights reserved.
***/

#include "sd-radv.h"

#include "log.h"
#include "list.h"
#include "sparse-endian.h"

assert_cc(SD_RADV_DEFAULT_MIN_TIMEOUT_USEC <= SD_RADV_DEFAULT_MAX_TIMEOUT_USEC)

#define SD_RADV_MAX_INITIAL_RTR_ADVERT_INTERVAL_USEC (16 * USEC_PER_SEC)
#define SD_RADV_MAX_INITIAL_RTR_ADVERTISEMENTS 3
#define SD_RADV_MAX_FINAL_RTR_ADVERTISEMENTS 3
#define SD_RADV_MIN_DELAY_BETWEEN_RAS 3
#define SD_RADV_MAX_RA_DELAY_TIME_USEC (500 * USEC_PER_MSEC)

#define SD_RADV_OPT_RDNSS 25
#define SD_RADV_OPT_DNSSL 31

        enum RAdvState {
                SD_RADV_STATE_IDLE = 0,
                SD_RADV_STATE_ADVERTISING = 1,
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

        size_t n_rdnss;
        struct sd_radv_opt_dns *rdnss;
        struct sd_radv_opt_dns *dnssl;
};

struct sd_radv_prefix {
        unsigned n_ref;

        struct {
                uint8_t type;
                uint8_t length;
                uint8_t prefixlen;
                uint8_t flags;
                be32_t valid_lifetime;
                be32_t preferred_lifetime;
                uint32_t reserved;
                struct in6_addr in6_addr;
        } _packed_ opt;

        LIST_FIELDS(struct sd_radv_prefix, prefix);

        usec_t valid_until;
        usec_t preferred_until;
};

#define log_radv_full(level, error, fmt, ...) log_internal(level, error, __FILE__, __LINE__, __func__, "RADV: " fmt, ##__VA_ARGS__)
#define log_radv_errno(error, fmt, ...) log_radv_full(LOG_DEBUG, error, fmt, ##__VA_ARGS__)
#define log_radv(fmt, ...) log_radv_errno(0, fmt, ##__VA_ARGS__)
