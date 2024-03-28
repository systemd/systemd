/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2014-2015 Intel Corporation. All rights reserved.
***/

#include <inttypes.h>

#include "sd-dhcp6-lease.h"
#include "dns-resolver-internal.h"

#include "dhcp6-option.h"
#include "dhcp6-protocol.h"
#include "macro.h"
#include "set.h"
#include "time-util.h"

struct sd_dhcp6_lease {
        unsigned n_ref;

        uint8_t *clientid;
        size_t clientid_len;
        uint8_t *serverid;
        size_t serverid_len;
        uint8_t preference;
        bool rapid_commit;
        triple_timestamp timestamp;
        usec_t lifetime_t1;
        usec_t lifetime_t2;
        usec_t lifetime_valid;
        struct in6_addr server_address;

        DHCP6IA *ia_na; /* Identity association non-temporary addresses */
        DHCP6IA *ia_pd; /* Identity association prefix delegation */

        DHCP6Address *addr_iter;
        DHCP6Address *prefix_iter;

        struct in6_addr *dns;
        size_t dns_count;
        sd_dns_resolver *dnr;
        size_t n_dnr;
        char **domains;
        struct in6_addr *ntp;
        size_t ntp_count;
        char **ntp_fqdn;
        struct in6_addr *sntp;
        size_t sntp_count;
        char *fqdn;
        char *captive_portal;
        struct sd_dhcp6_option **sorted_vendor_options;
        Set *vendor_options;
};

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
int dhcp6_lease_set_captive_portal(sd_dhcp6_lease *lease, const uint8_t *optval, size_t optlen);

int dhcp6_lease_new(sd_dhcp6_lease **ret);
int dhcp6_lease_new_from_message(
                sd_dhcp6_client *client,
                const DHCP6Message *message,
                size_t len,
                const triple_timestamp *timestamp,
                const struct in6_addr *server_address,
                sd_dhcp6_lease **ret);

#define _FOREACH_DHCP6_ADDRESS(lease, it)                               \
        for (int it = sd_dhcp6_lease_address_iterator_reset(lease);     \
             it > 0;                                                    \
             it = sd_dhcp6_lease_address_iterator_next(lease))
#define FOREACH_DHCP6_ADDRESS(lease)                                    \
        _FOREACH_DHCP6_ADDRESS(lease, UNIQ_T(i, UNIQ))

#define _FOREACH_DHCP6_PD_PREFIX(lease, it)                             \
        for (int it = sd_dhcp6_lease_pd_iterator_reset(lease);          \
             it > 0;                                                    \
             it = sd_dhcp6_lease_pd_iterator_next(lease))
#define FOREACH_DHCP6_PD_PREFIX(lease)                                  \
        _FOREACH_DHCP6_PD_PREFIX(lease, UNIQ_T(i, UNIQ))
