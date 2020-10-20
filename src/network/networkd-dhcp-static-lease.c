/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include "alloc-util.h"
#include "ether-addr-util.h"
#include "hashmap.h"
#include "memory-util.h"
#include "networkd-dhcp-static-lease.h"
#include "networkd-network.h"
#include "networkd-util.h"
#include "strv.h"
#include "utf8.h"

DEFINE_NETWORK_SECTION_FUNCTIONS(DHCPStaticLease, dhcp_static_lease_free);

DHCPStaticLease *dhcp_static_lease_free(DHCPStaticLease *static_lease) {
        if (!static_lease)
                return NULL;

        if (static_lease->network && static_lease->section)
                ordered_hashmap_remove(static_lease->network->dhcp_static_leases_by_section, static_lease->section);

        network_config_section_free(static_lease->section);
        static_lease->mac_addr = mfree(static_lease->mac_addr);
        return mfree(static_lease);
}

static int dhcp_static_lease_new(DHCPStaticLease **ret) {
        DHCPStaticLease *p = NULL;

        assert(ret);

        p = new0(DHCPStaticLease, 1);
        if (!p)
                return -ENOMEM;

        *ret = TAKE_PTR(p);
        return 0;
}

static int dhcp_static_lease_set_client_id(
                DHCPStaticLease *lease,
                const struct ether_addr *mac_addr,
                size_t mac_addr_size) {
        uint8_t *data;

        assert(lease);
        assert(mac_addr);
        assert_return(mac_addr_size == ETH_ALEN, -EINVAL);

        data = new(uint8_t, mac_addr_size + 1);
        if (!data)
                return -ENOMEM;

        /* set client id type to 1: Ethernet Link-Layer (RFC 2132) */
        data[0] = 0x01;
        memcpy(data + 1, mac_addr, mac_addr_size);

        free_and_replace(lease->mac_addr, data);

        lease->mac_addr_size = mac_addr_size + 1;

        return 0;
}

static int dhcp_static_lease_set_address(DHCPStaticLease *lease, const struct in_addr *address) {
        assert(address);
        assert(lease);
        assert_return(address->s_addr != 0, -EINVAL);

        lease->address = (struct in_addr)
        {
                .s_addr = address->s_addr,
        };

        return 0;
}

static int lease_new_static(Network *network, const char *filename, unsigned section_line, DHCPStaticLease **ret) {
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(dhcp_static_lease_freep) DHCPStaticLease *static_lease = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);
        
        r = network_config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        static_lease = ordered_hashmap_get(network->dhcp_static_leases_by_section, n);
        if (static_lease) {
                *ret = TAKE_PTR(static_lease);
                return 0;
        }

        r = dhcp_static_lease_new(&static_lease);
        if (r < 0)
                return r;

        static_lease->network = network;

        static_lease->section = TAKE_PTR(n);
        r = ordered_hashmap_ensure_put(&network->dhcp_static_leases_by_section, &network_config_hash_ops, static_lease->section, static_lease);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(static_lease);

        return 0;
}
