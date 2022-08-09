/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "ether-addr-util.h"
#include "hashmap.h"
#include "networkd-dhcp-server-static-lease.h"
#include "networkd-network.h"
#include "networkd-util.h"

DEFINE_SECTION_CLEANUP_FUNCTIONS(DHCPStaticLease, dhcp_static_lease_free);

DHCPStaticLease *dhcp_static_lease_free(DHCPStaticLease *static_lease) {
        if (!static_lease)
                return NULL;

        if (static_lease->network && static_lease->section)
                hashmap_remove(static_lease->network->dhcp_static_leases_by_section, static_lease->section);

        config_section_free(static_lease->section);
        free(static_lease->client_id);
        return mfree(static_lease);
}

static int dhcp_static_lease_new(DHCPStaticLease **ret) {
        DHCPStaticLease *p;

        assert(ret);

        p = new0(DHCPStaticLease, 1);
        if (!p)
                return -ENOMEM;

        *ret = TAKE_PTR(p);
        return 0;
}

static int lease_new_static(Network *network, const char *filename, unsigned section_line, DHCPStaticLease **ret) {
        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(dhcp_static_lease_freep) DHCPStaticLease *static_lease = NULL;
        int r;

        assert(network);
        assert(filename);
        assert(section_line > 0);
        assert(ret);

        r = config_section_new(filename, section_line, &n);
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
        r = hashmap_ensure_put(&network->dhcp_static_leases_by_section, &config_section_hash_ops, static_lease->section, static_lease);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(static_lease);
        return 0;
}

static int static_lease_verify(DHCPStaticLease *static_lease) {
        if (section_is_invalid(static_lease->section))
                return -EINVAL;

        if (in4_addr_is_null(&static_lease->address))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: DHCP static lease without Address= field configured. "
                                         "Ignoring [DHCPServerStaticLease] section from line %u.",
                                         static_lease->section->filename, static_lease->section->line);

        /* TODO: check that the address is in the pool. */

        if (static_lease->client_id_size == 0 || !static_lease->client_id)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: DHCP static lease without MACAddress= field configured. "
                                         "Ignoring [DHCPServerStaticLease] section from line %u.",
                                         static_lease->section->filename, static_lease->section->line);

        assert(static_lease->client_id_size == ETH_ALEN + 1);

        return 0;
}

void network_drop_invalid_static_leases(Network *network) {
        DHCPStaticLease *static_lease;

        assert(network);

        HASHMAP_FOREACH(static_lease, network->dhcp_static_leases_by_section)
                if (static_lease_verify(static_lease) < 0)
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

        _cleanup_(dhcp_static_lease_free_or_set_invalidp) DHCPStaticLease *lease = NULL;
        Network *network = ASSERT_PTR(userdata);
        union in_addr_union addr;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

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
        if (in4_addr_is_null(&addr.in)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "IPv4 address for DHCPv4 static lease cannot be the ANY address, ignoring assignment: %s", rvalue);
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

        _cleanup_(dhcp_static_lease_free_or_set_invalidp) DHCPStaticLease *lease = NULL;
        Network *network = ASSERT_PTR(userdata);
        struct ether_addr hwaddr;
        uint8_t *c;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = lease_new_static(network, filename, section_line, &lease);
        if (r < 0)
                return log_oom();

        if (isempty(rvalue)) {
                lease->client_id = mfree(lease->client_id);
                lease->client_id_size = 0;
                return 0;
        }

        r = parse_ether_addr(rvalue, &hwaddr);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse MAC address for DHCPv4 static lease, ignoring assignment: %s", rvalue);
                return 0;
        }
        if (ether_addr_is_null(&hwaddr) || (hwaddr.ether_addr_octet[0] & 0x01)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "MAC address for DHCPv4 static lease cannot be null or multicast, ignoring assignment: %s", rvalue);
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
