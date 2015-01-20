/***
  This file is part of systemd.

  Copyright (C) 2014 Tom Gundersen
  Copyright (C) 2014 Intel Corporation. All rights reserved.

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

#include <errno.h>

#include "util.h"

#include "dhcp6-lease-internal.h"

int dhcp6_lease_clear_timers(DHCP6IA *ia) {
        assert_return(ia, -EINVAL);

        ia->timeout_t1 = sd_event_source_unref(ia->timeout_t1);
        ia->timeout_t2 = sd_event_source_unref(ia->timeout_t2);

        return 0;
}

int dhcp6_lease_ia_rebind_expire(const DHCP6IA *ia, uint32_t *expire) {
        DHCP6Address *addr;
        uint32_t valid = 0, t;

        assert_return(ia, -EINVAL);
        assert_return(expire, -EINVAL);

        LIST_FOREACH(addresses, addr, ia->addresses) {
                t = be32toh(addr->iaaddr.lifetime_valid);
                if (valid < t)
                        valid = t;
        }

        t = be32toh(ia->lifetime_t2);
        if (t > valid)
                return -EINVAL;

        *expire = valid - t;

        return 0;
}

DHCP6IA *dhcp6_lease_free_ia(DHCP6IA *ia) {
        DHCP6Address *address;

        if (!ia)
                return NULL;

        dhcp6_lease_clear_timers(ia);

        while (ia->addresses) {
                address = ia->addresses;

                LIST_REMOVE(addresses, ia->addresses, address);

                free(address);
        }

        return NULL;
}

int dhcp6_lease_set_serverid(sd_dhcp6_lease *lease, const uint8_t *id,
                             size_t len) {
        assert_return(lease, -EINVAL);
        assert_return(id, -EINVAL);

        free(lease->serverid);

        lease->serverid = memdup(id, len);
        if (!lease->serverid)
                return -EINVAL;

        lease->serverid_len = len;

        return 0;
}

int dhcp6_lease_get_serverid(sd_dhcp6_lease *lease, uint8_t **id, size_t *len) {
        assert_return(lease, -EINVAL);
        assert_return(id, -EINVAL);
        assert_return(len, -EINVAL);

        *id = lease->serverid;
        *len = lease->serverid_len;

        return 0;
}

int dhcp6_lease_set_preference(sd_dhcp6_lease *lease, uint8_t preference) {
        assert_return(lease, -EINVAL);

        lease->preference = preference;

        return 0;
}

int dhcp6_lease_get_preference(sd_dhcp6_lease *lease, uint8_t *preference) {
        assert_return(preference, -EINVAL);

        if (!lease)
                return -EINVAL;

        *preference = lease->preference;

        return 0;
}

int dhcp6_lease_set_rapid_commit(sd_dhcp6_lease *lease) {
        assert_return(lease, -EINVAL);

        lease->rapid_commit = true;

        return 0;
}

int dhcp6_lease_get_rapid_commit(sd_dhcp6_lease *lease, bool *rapid_commit) {
        assert_return(lease, -EINVAL);
        assert_return(rapid_commit, -EINVAL);

        *rapid_commit = lease->rapid_commit;

        return 0;
}

int dhcp6_lease_get_iaid(sd_dhcp6_lease *lease, be32_t *iaid) {
        assert_return(lease, -EINVAL);
        assert_return(iaid, -EINVAL);

        *iaid = lease->ia.id;

        return 0;
}

int sd_dhcp6_lease_get_address(sd_dhcp6_lease *lease, struct in6_addr *addr,
                               uint32_t *lifetime_preferred,
                               uint32_t *lifetime_valid) {
        assert_return(lease, -EINVAL);
        assert_return(addr, -EINVAL);
        assert_return(lifetime_preferred, -EINVAL);
        assert_return(lifetime_valid, -EINVAL);

        if (!lease->addr_iter)
                return -ENOMSG;

        memcpy(addr, &lease->addr_iter->iaaddr.address,
                sizeof(struct in6_addr));
        *lifetime_preferred =
                be32toh(lease->addr_iter->iaaddr.lifetime_preferred);
        *lifetime_valid = be32toh(lease->addr_iter->iaaddr.lifetime_valid);

        lease->addr_iter = lease->addr_iter->addresses_next;

        return 0;
}

void sd_dhcp6_lease_reset_address_iter(sd_dhcp6_lease *lease) {
        if (lease)
                lease->addr_iter = lease->ia.addresses;
}

sd_dhcp6_lease *sd_dhcp6_lease_ref(sd_dhcp6_lease *lease) {
        if (lease)
                assert_se(REFCNT_INC(lease->n_ref) >= 2);

        return lease;
}

sd_dhcp6_lease *sd_dhcp6_lease_unref(sd_dhcp6_lease *lease) {
        if (lease && REFCNT_DEC(lease->n_ref) == 0) {
                free(lease->serverid);
                dhcp6_lease_free_ia(&lease->ia);

                free(lease);
        }

        return NULL;
}

int dhcp6_lease_new(sd_dhcp6_lease **ret) {
        sd_dhcp6_lease *lease;

        lease = new0(sd_dhcp6_lease, 1);
        if (!lease)
                return -ENOMEM;

        lease->n_ref = REFCNT_INIT;

        LIST_HEAD_INIT(lease->ia.addresses);

        *ret = lease;
        return 0;
}
