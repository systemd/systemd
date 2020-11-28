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

void network_drop_invalid_static_leases(Network *network) {
        DHCPStaticLease *static_lease;

        assert(network);

        ORDERED_HASHMAP_FOREACH(static_lease, network->dhcp_static_leases_by_section) {
                assert(static_lease);

                if (section_is_invalid(static_lease->section))
                        dhcp_static_lease_free(static_lease);
        }
}

int config_parse_dhcp_static_lease_address(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network;
        _cleanup_(dhcp_static_lease_free_or_set_invalidp) DHCPStaticLease *current_lease = NULL;
        union in_addr_union addr;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(userdata);

        network = userdata;

        r = lease_new_static(network, filename, section_line, &current_lease);
        if (r < 0)
                return log_oom();

        if (isempty(rvalue)) {
                current_lease->address.s_addr = 0;
                TAKE_PTR(current_lease);
                return 0;
        }

        r = in_addr_from_string(AF_INET, rvalue, &addr);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse IPv4 address for DHCPv4 static lease, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = dhcp_static_lease_set_address(current_lease, &addr.in);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to set IPv4 address for DHCPv4 static lease, ignoring assignment: %s", rvalue);
                return 0;
        }

        TAKE_PTR(current_lease);

        return 0;
}

int config_parse_dhcp_static_lease_hwaddr(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network;
        _cleanup_(dhcp_static_lease_free_or_set_invalidp) DHCPStaticLease *current_lease = NULL;
        struct ether_addr hwaddr;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(userdata);

        network = userdata;

        r = lease_new_static(network, filename, section_line, &current_lease);
        if (r < 0)
                return log_oom();

        if (isempty(rvalue)) {
                current_lease->mac_addr = mfree(current_lease->mac_addr);
                current_lease->mac_addr_size = 0;
                return 0;
        }

        r = ether_addr_from_string(rvalue, &hwaddr);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse MAC address for DHCPv4 static lease, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = dhcp_static_lease_set_client_id(current_lease, &hwaddr, ETH_ALEN);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to set MAC address for DHCPv4 static lease, ignoring assignment: %s", rvalue);
                return 0;
        }

        current_lease->section->invalid = false;
        TAKE_PTR(current_lease);

        return 0;
}
