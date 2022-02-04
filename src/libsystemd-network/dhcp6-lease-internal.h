/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2014-2015 Intel Corporation. All rights reserved.
***/

#include <stdint.h>

#include "sd-dhcp6-lease.h"

#include "dhcp6-internal.h"

struct sd_dhcp6_lease {
        unsigned n_ref;

        uint8_t *clientid;
        size_t clientid_len;
        uint8_t *serverid;
        size_t serverid_len;
        uint8_t preference;
        bool rapid_commit;
        triple_timestamp timestamp;
        struct in6_addr server_address;

        DHCP6IA ia_na;
        DHCP6IA ia_pd;

        DHCP6Address *addr_iter;
        DHCP6Address *prefix_iter;

        struct in6_addr *dns;
        size_t dns_count;
        char **domains;
        struct in6_addr *ntp;
        size_t ntp_count;
        char **ntp_fqdn;
        struct in6_addr *sntp;
        size_t sntp_count;
        char *fqdn;
};

int dhcp6_lease_ia_rebind_expire(const DHCP6IA *ia, uint32_t *expire);
DHCP6IA *dhcp6_lease_free_ia(DHCP6IA *ia);

int dhcp6_lease_set_clientid(sd_dhcp6_lease *lease, const uint8_t *id, size_t len);
int dhcp6_lease_get_clientid(sd_dhcp6_lease *lease, uint8_t **ret_id, size_t *ret_len);
int dhcp6_lease_set_serverid(sd_dhcp6_lease *lease, const uint8_t *id, size_t len);
int dhcp6_lease_get_serverid(sd_dhcp6_lease *lease, uint8_t **ret_id, size_t *ret_len);
int dhcp6_lease_set_preference(sd_dhcp6_lease *lease, uint8_t preference);
int dhcp6_lease_get_preference(sd_dhcp6_lease *lease, uint8_t *ret);
int dhcp6_lease_set_rapid_commit(sd_dhcp6_lease *lease);
int dhcp6_lease_get_rapid_commit(sd_dhcp6_lease *lease, bool *ret);

int dhcp6_lease_add_dns(sd_dhcp6_lease *lease, const uint8_t *optval, size_t optlen);
int dhcp6_lease_add_domains(sd_dhcp6_lease *lease, const uint8_t *optval, size_t optlen);
int dhcp6_lease_add_ntp(sd_dhcp6_lease *lease, const uint8_t *optval, size_t optlen);
int dhcp6_lease_add_sntp(sd_dhcp6_lease *lease, const uint8_t *optval, size_t optlen);
int dhcp6_lease_set_fqdn(sd_dhcp6_lease *lease, const uint8_t *optval, size_t optlen);

int dhcp6_lease_new(sd_dhcp6_lease **ret);
