/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "conf-parser.h"
#include "dns-domain.h"
#include "ether-addr-util.h"
#include "extract-word.h"
#include "hashmap.h"
#include "hexdecoct.h"
#include "networkd-dhcp-server-static-lease.h"
#include "networkd-network.h"
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

        if (ether_addr_is_null(&static_lease->hw_addr) ==
            !sd_dhcp_client_id_is_set(&static_lease->client_id))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: DHCP static lease must have exactly one of MACAddress= and "
                                         "ClientIdentifier= fields configured. "
                                         "Ignoring [DHCPServerStaticLease] section from line %u.",
                                         static_lease->section->filename, static_lease->section->line);

        if (sd_dhcp_client_id_is_set(&static_lease->client_id))
                return 0;

        /* set client id type to 1: Ethernet Link-Layer (RFC 2132) */
        r = sd_dhcp_client_id_set(&static_lease->client_id, 1, &static_lease->hw_addr, ETH_ALEN);
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

int config_parse_dhcp_static_lease_client_id(
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
        uint8_t raw[MAX_CLIENT_ID_LEN];
        size_t size = 0;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = lease_new_static(network, filename, section_line, &lease);
        if (r < 0)
                return log_oom();

        if (isempty(rvalue)) {
                sd_dhcp_client_id_clear(&lease->client_id);
                TAKE_PTR(lease);
                return 0;
        }

        /* The client ID including its type in format "NN:NN:NN..." */
        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL;
                int hi, lo;

                r = extract_first_word(&p, &word, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);
                if (r == 0)
                        break;

                if (size >= sizeof(raw)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Client ID for DHCPv4 static lease is too long, ignoring assignment: %s",
                                   rvalue);
                        return 0;
                }

                if (strlen(word) != 2 ||
                    (hi = unhexchar(word[0])) < 0 ||
                    (lo = unhexchar(word[1])) < 0)
                        return log_syntax_parse_error(unit, filename, line, 0, lvalue, rvalue);

                raw[size++] = (uint8_t) (hi << 4 | lo);
        }

        r = sd_dhcp_client_id_set_raw(&lease->client_id, raw, size);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Client ID for DHCPv4 static lease is too short, ignoring assignment: %s",
                           rvalue);
                return 0;
        }

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
