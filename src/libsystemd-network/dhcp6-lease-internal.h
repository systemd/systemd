/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright (C) 2014 Tom Gundersen
  Copyright (C) 2014-2015 Intel Corporation. All rights reserved.

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

#include <stdint.h>

#include "refcnt.h"

#include "sd-dhcp6-lease.h"
#include "dhcp6-internal.h"

struct sd_dhcp6_lease {
        RefCount n_ref;

        uint8_t *serverid;
        size_t serverid_len;
        uint8_t preference;
        bool rapid_commit;

        DHCP6IA ia;

        DHCP6Address *addr_iter;

        struct in6_addr *dns;
        size_t dns_count;
        size_t dns_allocated;
        char **domains;
        size_t domains_count;
        struct in6_addr *ntp;
        size_t ntp_count;
        size_t ntp_allocated;
        char **ntp_fqdn;
        size_t ntp_fqdn_count;
};

int dhcp6_lease_clear_timers(DHCP6IA *ia);
int dhcp6_lease_ia_rebind_expire(const DHCP6IA *ia, uint32_t *expire);
DHCP6IA *dhcp6_lease_free_ia(DHCP6IA *ia);

int dhcp6_lease_set_serverid(sd_dhcp6_lease *lease, const uint8_t *id,
                             size_t len);
int dhcp6_lease_get_serverid(sd_dhcp6_lease *lease, uint8_t **id, size_t *len);
int dhcp6_lease_set_preference(sd_dhcp6_lease *lease, uint8_t preference);
int dhcp6_lease_get_preference(sd_dhcp6_lease *lease, uint8_t *preference);
int dhcp6_lease_set_rapid_commit(sd_dhcp6_lease *lease);
int dhcp6_lease_get_rapid_commit(sd_dhcp6_lease *lease, bool *rapid_commit);

int dhcp6_lease_get_iaid(sd_dhcp6_lease *lease, be32_t *iaid);

int dhcp6_lease_set_dns(sd_dhcp6_lease *lease, uint8_t *optval, size_t optlen);
int dhcp6_lease_set_domains(sd_dhcp6_lease *lease, uint8_t *optval,
                            size_t optlen);
int dhcp6_lease_set_ntp(sd_dhcp6_lease *lease, uint8_t *optval, size_t optlen);
int dhcp6_lease_set_sntp(sd_dhcp6_lease *lease, uint8_t *optval,
                         size_t optlen) ;

int dhcp6_lease_new(sd_dhcp6_lease **ret);

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_dhcp6_lease*, sd_dhcp6_lease_unref);
#define _cleanup_dhcp6_lease_free_ _cleanup_(sd_dhcp6_lease_unrefp)
