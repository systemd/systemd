/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include "in-addr-util.h"

typedef struct DnsServer DnsServer;
typedef enum DnsServerSource DnsServerSource;

typedef enum DnsServerType {
        DNS_SERVER_SYSTEM,
        DNS_SERVER_FALLBACK,
        DNS_SERVER_LINK,
} DnsServerType;

typedef enum DnsServerFeatureLevel {
        DNS_SERVER_FEATURE_LEVEL_TCP,
        DNS_SERVER_FEATURE_LEVEL_UDP,
        DNS_SERVER_FEATURE_LEVEL_EDNS0,
        _DNS_SERVER_FEATURE_LEVEL_MAX,
        _DNS_SERVER_FEATURE_LEVEL_INVALID = -1
} DnsServerFeatureLevel;

#define DNS_SERVER_FEATURE_LEVEL_WORST 0
#define DNS_SERVER_FEATURE_LEVEL_BEST (_DNS_SERVER_FEATURE_LEVEL_MAX - 1)

const char* dns_server_feature_level_to_string(int i) _const_;
int dns_server_feature_level_from_string(const char *s) _pure_;

#include "resolved-link.h"

struct DnsServer {
        Manager *manager;

        unsigned n_ref;

        DnsServerType type;

        Link *link;

        int family;
        union in_addr_union address;

        bool marked:1;
        DnsServerFeatureLevel verified_features;
        DnsServerFeatureLevel possible_features;
        unsigned n_failed_attempts;
        usec_t last_failed_attempt;

        LIST_FIELDS(DnsServer, servers);
};

int dns_server_new(
                Manager *m,
                DnsServer **s,
                DnsServerType type,
                Link *l,
                int family,
                const union in_addr_union *address);

DnsServer* dns_server_ref(DnsServer *s);
DnsServer* dns_server_unref(DnsServer *s);

DnsServerFeatureLevel dns_server_possible_features(DnsServer *s);

extern const struct hash_ops dns_server_hash_ops;

/* The amount of time to wait before retrying with a full feature set */
#define DNS_SERVER_FEATURE_RETRY_USEC (6 * USEC_PER_HOUR)

/* The number of times we will attempt a certain feature set before degrading */
#define DNS_SERVER_FEATURE_RETRY_ATTEMPTS 2
