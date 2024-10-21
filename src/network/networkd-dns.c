/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-domain.h"
#include "hostname-util.h"
#include "networkd-dns.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "parse-util.h"
#include "string-table.h"

UseDomains link_get_use_domains(Link *link, NetworkConfigSource proto) {
        UseDomains n, c, m;

        assert(link);
        assert(link->manager);

        if (!link->network)
                return USE_DOMAINS_NO;

        switch (proto) {
        case NETWORK_CONFIG_SOURCE_DHCP4:
                n = link->network->dhcp_use_domains;
                c = link->network->compat_dhcp_use_domains;
                m = link->manager->dhcp_use_domains;
                break;
        case NETWORK_CONFIG_SOURCE_DHCP6:
                n = link->network->dhcp6_use_domains;
                c = link->network->compat_dhcp_use_domains;
                m = link->manager->dhcp6_use_domains;
                break;
        case NETWORK_CONFIG_SOURCE_NDISC:
                n = link->network->ndisc_use_domains;
                c = _USE_DOMAINS_INVALID;
                m = link->manager->ndisc_use_domains;
                break;
        default:
                assert_not_reached();
        }

        /* If per-network and per-protocol setting is specified, use it. */
        if (n >= 0)
                return n;

        /* If compat setting is specified, use it. */
        if (c >= 0)
                return c;

        /* If per-network but protocol-independent setting is specified, use it. */
        if (link->network->use_domains >= 0)
                return link->network->use_domains;

        /* If global per-protocol setting is specified, use it. */
        if (m >= 0)
                return m;

        /* If none of them are specified, use the global protocol-independent value. */
        return link->manager->use_domains;
}

bool link_get_use_dns(Link *link, NetworkConfigSource proto) {
        int n, c;

        assert(link);

        if (!link->network)
                return false;

        switch (proto) {
        case NETWORK_CONFIG_SOURCE_DHCP4:
                n = link->network->dhcp_use_dns;
                c = link->network->compat_dhcp_use_dns;
                break;
        case NETWORK_CONFIG_SOURCE_DHCP6:
                n = link->network->dhcp6_use_dns;
                c = link->network->compat_dhcp_use_dns;
                break;
        case NETWORK_CONFIG_SOURCE_NDISC:
                n = link->network->ndisc_use_dns;
                c = -1;
                break;
        default:
                assert_not_reached();
        }

        /* If per-network and per-protocol setting is specified, use it. */
        if (n >= 0)
                return n;

        /* If compat setting is specified, use it. */
        if (c >= 0)
                return c;

        /* Otherwise, defaults to yes. */
        return true;
}

bool link_get_use_dnr(Link *link, NetworkConfigSource proto) {
        int n;

        assert(link);

        if (!link->network)
                return false;

        switch (proto) {
        case NETWORK_CONFIG_SOURCE_DHCP4:
                n = link->network->dhcp_use_dnr;
                break;
        case NETWORK_CONFIG_SOURCE_DHCP6:
                n = link->network->dhcp6_use_dnr;
                break;
        case NETWORK_CONFIG_SOURCE_NDISC:
                n = link->network->ndisc_use_dnr;
                break;
        default:
                assert_not_reached();
        }

        /* If set explicitly, use that */
        if (n >= 0)
                return n;

        /* Otherwise, default to the same as the UseDNS setting. After all,
         * this is just another way for the server to tell us about DNS configuration. */
        return link_get_use_dns(link, proto);
}

int config_parse_domains(
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

        Network *n = ASSERT_PTR(userdata);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                n->search_domains = ordered_set_free(n->search_domains);
                n->route_domains = ordered_set_free(n->route_domains);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *w = NULL, *normalized = NULL;
                const char *domain;
                bool is_route;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to extract search or route domain, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                is_route = w[0] == '~';
                domain = is_route ? w + 1 : w;

                if (dns_name_is_root(domain) || streq(domain, "*")) {
                        /* If the root domain appears as is, or the special token "*" is found, we'll
                         * consider this as routing domain, unconditionally. */
                        is_route = true;
                        domain = "."; /* make sure we don't allow empty strings, thus write the root
                                       * domain as "." */
                } else {
                        r = dns_name_normalize(domain, 0, &normalized);
                        if (r < 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, r,
                                           "'%s' is not a valid domain name, ignoring.", domain);
                                continue;
                        }

                        domain = normalized;

                        if (is_localhost(domain)) {
                                log_syntax(unit, LOG_WARNING, filename, line, 0,
                                           "'localhost' domain may not be configured as search or route domain, ignoring assignment: %s",
                                           domain);
                                continue;
                        }
                }

                OrderedSet **set = is_route ? &n->route_domains : &n->search_domains;
                r = ordered_set_put_strdup(set, domain);
                if (r == -EEXIST)
                        continue;
                if (r < 0)
                        return log_oom();
        }
}

int config_parse_dns(
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

        Network *n = ASSERT_PTR(userdata);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                for (unsigned i = 0; i < n->n_dns; i++)
                        in_addr_full_free(n->dns[i]);
                n->dns = mfree(n->dns);
                n->n_dns = 0;
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_(in_addr_full_freep) struct in_addr_full *dns = NULL;
                _cleanup_free_ char *w = NULL;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = in_addr_full_new_from_string(w, &dns);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse dns server address, ignoring: %s", w);
                        continue;
                }

                if (IN_SET(dns->port, 53, 853))
                        dns->port = 0;

                if (!GREEDY_REALLOC(n->dns, n->n_dns + 1))
                        return log_oom();

                n->dns[n->n_dns++] = TAKE_PTR(dns);
        }
}

int config_parse_dnssec_negative_trust_anchors(
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

        Set **nta = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *nta = set_free_free(*nta);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *w = NULL;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to extract negative trust anchor domain, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = dns_name_is_valid(w);
                if (r <= 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "%s is not a valid domain name, ignoring.", w);
                        continue;
                }

                r = set_ensure_consume(nta, &dns_name_hash_ops, TAKE_PTR(w));
                if (r < 0)
                        return log_oom();
        }
}

static const char* const use_domains_table[_USE_DOMAINS_MAX] = {
        [USE_DOMAINS_NO]    = "no",
        [USE_DOMAINS_ROUTE] = "route",
        [USE_DOMAINS_YES]   = "yes",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(use_domains, UseDomains, USE_DOMAINS_YES);
DEFINE_CONFIG_PARSE_ENUM(config_parse_use_domains, use_domains, UseDomains);
