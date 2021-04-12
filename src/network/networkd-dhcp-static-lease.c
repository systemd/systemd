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
        static_lease->static_lease = sd_dhcp_static_lease_unref(static_lease->static_lease);
        return mfree(static_lease);
}

static int dhcp_static_lease_new(DHCPStaticLease **ret) {
        DHCPStaticLease *p = NULL;
        int r;

        assert(ret);

        p = new0(DHCPStaticLease, 1);
        if (!p)
                return -ENOMEM;

        r = sd_dhcp_static_lease_new(&p->static_lease);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(p);
        return 0;
}

static int dhcp_static_lease_set_client_id(DHCPStaticLease *lease, const struct ether_addr *mac_addr) {
        assert(lease);
        assert(mac_addr);

        return sd_dhcp_static_lease_set_client_id_by_mac(lease->static_lease, mac_addr->ether_addr_octet, ETH_ALEN);
}

static int dhcp_static_lease_set_address(DHCPStaticLease *lease, const struct in_addr *address) {
        assert(address);
        assert(lease);

        return sd_dhcp_static_lease_set_address(lease->static_lease, address);
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
                sd_dhcp_static_lease_unset_address(current_lease->static_lease);
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
                sd_dhcp_static_lease_unset_client_id(current_lease->static_lease);
                return 0;
        }

        r = ether_addr_from_string(rvalue, &hwaddr);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse MAC address for DHCPv4 static lease, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = dhcp_static_lease_set_client_id(current_lease, &hwaddr);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to set MAC address for DHCPv4 static lease, ignoring assignment: %s", rvalue);
                return 0;
        }

        current_lease->section->invalid = false;
        TAKE_PTR(current_lease);

        return 0;
}
