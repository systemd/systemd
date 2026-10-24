/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "conf-parser.h"
#include "dns-domain.h"
#include "ether-addr-util.h"
#include "hashmap.h"
#include "networkd-dhcp-server-static-lease.h"
#include "networkd-network.h"
#include "parse-util.h"
#include "string-util.h"

static DHCPStaticLease* dhcp_static_lease_free(DHCPStaticLease *static_lease) {
        if (!static_lease)
                return NULL;

        if (static_lease->network && static_lease->section)
                hashmap_remove(static_lease->network->dhcp_static_leases_by_section, static_lease->section);

        config_section_free(static_lease->section);
        free(static_lease->hostname);
        return mfree(static_lease);
}

DEFINE_SECTION_CLEANUP_FUNCTIONS(DHCPStaticLease, dhcp_static_lease_free);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                static_lease_hash_ops_by_section,
                ConfigSection, config_section_hash_func, config_section_compare_func,
                DHCPStaticLease, dhcp_static_lease_free);

static int dhcp_static_lease_new(DHCPStaticLease **ret) {
        DHCPStaticLease *p;

        assert(ret);

        p = new(DHCPStaticLease, 1);
        if (!p)
                return -ENOMEM;

        *p = (DHCPStaticLease) {
                .client_identifier = DHCP_CLIENT_ID_MAC,
                .duid.type = _DUID_TYPE_INVALID,
        };

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

        r = hashmap_ensure_put(&network->dhcp_static_leases_by_section, &static_lease_hash_ops_by_section, static_lease->section, static_lease);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(static_lease);
        return 0;
}

static int static_lease_verify(DHCPStaticLease *static_lease) {
        int r;

        if (section_is_invalid(static_lease->section))
                return -EINVAL;

        if (in4_addr_is_null(&static_lease->address))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: DHCP static lease without Address= field configured. "
                                         "Ignoring [DHCPServerStaticLease] section from line %u.",
                                         static_lease->section->filename, static_lease->section->line);

        /* TODO: check that the address is in the pool. */

        switch (static_lease->client_identifier) {
        case DHCP_CLIENT_ID_MAC:
                if (ether_addr_is_null(&static_lease->hw_addr))
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                 "%s: DHCP static lease without MACAddress= field configured. "
                                                 "Ignoring [DHCPServerStaticLease] section from line %u.",
                                                 static_lease->section->filename, static_lease->section->line);

                /* set client id type to 1: Ethernet Link-Layer (RFC 2132) */
                r = sd_dhcp_client_id_set(&static_lease->client_id, 1, &static_lease->hw_addr, ETH_ALEN);
                break;

        case DHCP_CLIENT_ID_DUID: {
                sd_dhcp_duid duid = {};

                /* MACAddress= is ignored here, as the client identifier does not contain it. */

                if (!static_lease->iaid_set ||
                    static_lease->duid.type < 0 ||
                    static_lease->duid.raw_data_len == 0)
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                 "%s: DHCP static lease with ClientIdentifier=duid requires IAID=, "
                                                 "DUIDType=, and DUIDRawData= fields configured. "
                                                 "Ignoring [DHCPServerStaticLease] section from line %u.",
                                                 static_lease->section->filename, static_lease->section->line);

                r = sd_dhcp_duid_set(&duid, static_lease->duid.type,
                                     static_lease->duid.raw_data, static_lease->duid.raw_data_len);
                if (r >= 0)
                        r = sd_dhcp_client_id_set_iaid_duid(&static_lease->client_id, static_lease->iaid, &duid);
                break;
        }

        default:
                assert_not_reached();
        }
        if (r < 0)
                return log_warning_errno(r,
                                         "%s: Failed to set client ID of DHCP static lease. "
                                         "Ignoring [DHCPServerStaticLease] section from line %u: %m",
                                         static_lease->section->filename, static_lease->section->line);

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
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = lease_new_static(network, filename, section_line, &lease);
        if (r < 0)
                return log_oom();

        if (isempty(rvalue)) {
                lease->hw_addr = ETHER_ADDR_NULL;
                TAKE_PTR(lease);
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

        lease->hw_addr = hwaddr;

        TAKE_PTR(lease);
        return 0;
}

static int config_parse_dhcp_static_lease_iaid(
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

        DHCPStaticLease *lease = ASSERT_PTR(userdata);
        int r;

        assert(rvalue);

        if (isempty(rvalue)) {
                lease->iaid = 0;
                lease->iaid_set = false;
                return 1;
        }

        r = safe_atou32(rvalue, &lease->iaid);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        lease->iaid_set = true;
        return 1;
}

int config_parse_dhcp_static_lease_section(
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

        static const ConfigSectionParser table[_DHCP_STATIC_LEASE_CONF_PARSER_MAX] = {
                [DHCP_STATIC_LEASE_CLIENT_IDENTIFIER] = { .parser = config_parse_dhcp_client_identifier, .ltype = 0,    .offset = offsetof(DHCPStaticLease, client_identifier), },
                [DHCP_STATIC_LEASE_IAID]              = { .parser = config_parse_dhcp_static_lease_iaid, .ltype = 0,    .offset = 0,                                            },
                [DHCP_STATIC_LEASE_DUID_TYPE]         = { .parser = config_parse_duid_type,              .ltype = true, .offset = offsetof(DHCPStaticLease, duid),              },
                [DHCP_STATIC_LEASE_DUID_RAW_DATA]     = { .parser = config_parse_duid_rawdata,           .ltype = true, .offset = offsetof(DHCPStaticLease, duid),              },
        };

        _cleanup_(dhcp_static_lease_free_or_set_invalidp) DHCPStaticLease *lease = NULL;
        Network *network = ASSERT_PTR(userdata);
        int r;

        assert(filename);

        r = lease_new_static(network, filename, section_line, &lease);
        if (r < 0)
                return log_oom();

        r = config_section_parse(table, ELEMENTSOF(table),
                                 unit, filename, line, section, section_line, lvalue, ltype, rvalue, lease);
        if (r <= 0)
                return r;

        TAKE_PTR(lease);
        return 0;
}

int config_parse_dhcp_static_lease_hostname(
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
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = lease_new_static(network, filename, section_line, &lease);
        if (r < 0)
                return log_oom();

        if (isempty(rvalue)) {
                lease->hostname = mfree(lease->hostname);
                TAKE_PTR(lease);
                return 0;
        }

        r = dns_name_is_valid_ldh(rvalue);
        if (r <= 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        r = free_and_strdup(&lease->hostname, rvalue);
        if (r < 0)
                return log_oom();

        TAKE_PTR(lease);
        return 0;
}
