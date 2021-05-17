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
                hashmap_remove(static_lease->network->dhcp_static_leases_by_section, static_lease->section);

        network_config_section_free(static_lease->section);
        static_lease->client_id = mfree(static_lease->client_id);
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

        static_lease = hashmap_get(network->dhcp_static_leases_by_section, n);
        if (static_lease) {
                *ret = TAKE_PTR(static_lease);
                return 0;
        }

        r = dhcp_static_lease_new(&static_lease);
        if (r < 0)
                return r;

        static_lease->network = network;
        static_lease->section = TAKE_PTR(n);
        r = hashmap_ensure_put(&network->dhcp_static_leases_by_section, &network_config_hash_ops, static_lease->section, static_lease);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(static_lease);

        return 0;
}

void network_drop_invalid_static_leases(Network *network) {
        DHCPStaticLease *static_lease;

        assert(network);

        HASHMAP_FOREACH(static_lease, network->dhcp_static_leases_by_section)
                if (section_is_invalid(static_lease->section))
                        dhcp_static_lease_free(static_lease);
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

        Network *network = userdata;
        _cleanup_(dhcp_static_lease_free_or_set_invalidp) DHCPStaticLease *lease = NULL;
        union in_addr_union addr;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(userdata);

        r = lease_new_static(network, filename, section_line, &lease);
        if (r < 0)
                return log_oom();

        if (isempty(rvalue)) {
                lease->address.s_addr = 0;
                TAKE_PTR(lease);
                return 0;
        }

        r = in_addr_from_string(AF_INET, rvalue, &addr);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse IPv4 address for DHCPv4 static lease, ignoring assignment: %s", rvalue);
                return 0;
        }

        lease->address = addr.in;

        TAKE_PTR(lease);

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

        uint8_t *c;
        Network *network = userdata;
        _cleanup_(dhcp_static_lease_free_or_set_invalidp) DHCPStaticLease *lease = NULL;
        struct ether_addr hwaddr;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(userdata);

        r = lease_new_static(network, filename, section_line, &lease);
        if (r < 0)
                return log_oom();

        if (isempty(rvalue)) {
                lease->client_id = mfree(lease->client_id);
                lease->client_id_size = 0;
                return 0;
        }

        r = ether_addr_from_string(rvalue, &hwaddr);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse MAC address for DHCPv4 static lease, ignoring assignment: %s", rvalue);
                return 0;
        }

        c = new(uint8_t, ETH_ALEN + 1);
        if (!c)
                return log_oom();

        /* set client id type to 1: Ethernet Link-Layer (RFC 2132) */
        c[0] = 0x01;
        memcpy(c + 1, &hwaddr, ETH_ALEN);

        free_and_replace(lease->client_id, c);
        lease->client_id_size = ETH_ALEN + 1;

        TAKE_PTR(lease);

        return 0;
}
