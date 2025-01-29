/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "conf-parser.h"
#include "constants.h"
#include "creds-util.h"
#include "dns-domain.h"
#include "extract-word.h"
#include "hexdecoct.h"
#include "parse-util.h"
#include "proc-cmdline.h"
#include "resolved-conf.h"
#include "resolved-dns-search-domain.h"
#include "resolved-dns-stub.h"
#include "resolved-dnssd.h"
#include "resolved-manager.h"
#include "socket-netlink.h"
#include "specifier.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

DEFINE_CONFIG_PARSE_ENUM(config_parse_dns_stub_listener_mode, dns_stub_listener_mode, DnsStubListenerMode);

static int manager_add_dns_server_by_string(Manager *m, DnsServerType type, const char *word) {
        _cleanup_free_ char *server_name = NULL;
        union in_addr_union address;
        int family, r, ifindex = 0;
        uint16_t port;
        DnsServer *s;

        assert(m);
        assert(word);

        r = in_addr_port_ifindex_name_from_string_auto(word, &family, &address, &port, &ifindex, &server_name);
        if (r < 0)
                return r;

        /* Silently filter out 0.0.0.0, 127.0.0.53, 127.0.0.54 (our own stub DNS listener) */
        if (!dns_server_address_valid(family, &address))
                return 0;

        /* By default, the port number is determined with the transaction feature level.
         * See dns_transaction_port() and dns_server_port(). */
        if (IN_SET(port, 53, 853))
                port = 0;

        /* Filter out duplicates */
        s = dns_server_find(manager_get_first_dns_server(m, type), family, &address, port, ifindex, server_name);
        if (s) {
                /* Drop the marker. This is used to find the servers that ceased to exist, see
                 * manager_mark_dns_servers() and manager_flush_marked_dns_servers(). */
                dns_server_move_back_and_unmark(s);
                return 0;
        }

        return dns_server_new(m, NULL, type, NULL, family, &address, port, ifindex, server_name, RESOLVE_CONFIG_SOURCE_FILE);
}

int manager_parse_dns_server_string_and_warn(Manager *m, DnsServerType type, const char *string) {
        int r;

        assert(m);
        assert(string);

        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&string, &word, NULL, 0);
                if (r <= 0)
                        return r;

                r = manager_add_dns_server_by_string(m, type, word);
                if (r < 0)
                        log_warning_errno(r, "Failed to add DNS server address '%s', ignoring: %m", word);
        }
}

static int manager_add_search_domain_by_string(Manager *m, const char *domain) {
        DnsSearchDomain *d;
        bool route_only;
        int r;

        assert(m);
        assert(domain);

        route_only = *domain == '~';
        if (route_only)
                domain++;

        if (dns_name_is_root(domain) || streq(domain, "*")) {
                route_only = true;
                domain = ".";
        }

        r = dns_search_domain_find(m->search_domains, domain, &d);
        if (r < 0)
                return r;
        if (r > 0)
                dns_search_domain_move_back_and_unmark(d);
        else {
                r = dns_search_domain_new(m, &d, DNS_SEARCH_DOMAIN_SYSTEM, NULL, domain);
                if (r < 0)
                        return r;
        }

        d->route_only = route_only;
        return 0;
}

int manager_parse_search_domains_and_warn(Manager *m, const char *string) {
        int r;

        assert(m);
        assert(string);

        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&string, &word, NULL, EXTRACT_UNQUOTE);
                if (r <= 0)
                        return r;

                r = manager_add_search_domain_by_string(m, word);
                if (r < 0)
                        log_warning_errno(r, "Failed to add search domain '%s', ignoring: %m", word);
        }
}

int config_parse_dns_servers(
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

        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue))
                /* Empty assignment means clear the list */
                dns_server_unlink_all(manager_get_first_dns_server(m, ltype));
        else {
                /* Otherwise, add to the list */
                r = manager_parse_dns_server_string_and_warn(m, ltype, rvalue);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse DNS server string '%s', ignoring.", rvalue);
                        return 0;
                }
        }

        /* If we have a manual setting, then we stop reading
         * /etc/resolv.conf */
        if (ltype == DNS_SERVER_SYSTEM)
                m->read_resolv_conf = false;
        if (ltype == DNS_SERVER_FALLBACK)
                m->need_builtin_fallbacks = false;

        return 0;
}

int config_parse_search_domains(
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

        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue))
                /* Empty assignment means clear the list */
                dns_search_domain_unlink_all(m->search_domains);
        else {
                /* Otherwise, add to the list */
                r = manager_parse_search_domains_and_warn(m, rvalue);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse search domains string '%s', ignoring.", rvalue);
                        return 0;
                }
        }

        /* If we have a manual setting, then we stop reading
         * /etc/resolv.conf */
        m->read_resolv_conf = false;

        return 0;
}

int config_parse_dns_stub_listener_extra(
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

        _cleanup_free_ DnsStubListenerExtra *stub = NULL;
        Manager *m = userdata;
        const char *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                m->dns_extra_stub_listeners = ordered_set_free(m->dns_extra_stub_listeners);
                return 0;
        }

        r = dns_stub_listener_extra_new(m, &stub);
        if (r < 0)
                return log_oom();

        p = startswith(rvalue, "udp:");
        if (p)
                stub->mode = DNS_STUB_LISTENER_UDP;
        else {
                p = startswith(rvalue, "tcp:");
                if (p)
                        stub->mode = DNS_STUB_LISTENER_TCP;
                else {
                        stub->mode = DNS_STUB_LISTENER_YES;
                        p = rvalue;
                }
        }

        r = in_addr_port_ifindex_name_from_string_auto(p, &stub->family, &stub->address, &stub->port, NULL, NULL);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse address in %s=%s, ignoring assignment: %m",
                           lvalue, rvalue);
                return 0;
        }

        r = ordered_set_ensure_put(&m->dns_extra_stub_listeners, &dns_stub_listener_extra_hash_ops, stub);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to store %s=%s, ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(stub);

        return 0;
}

static void read_credentials(Manager *m) {
        _cleanup_free_ char *dns = NULL, *domains = NULL;
        int r;

        assert(m);

        /* Hmm, if we aren't supposed to read /etc/resolv.conf because the DNS settings were already
         * configured explicitly in our config file, we don't want to honour credentials either */
        if (!m->read_resolv_conf)
                return;

        r = read_credential_strings_many("network.dns", &dns,
                                         "network.search_domains", &domains);
        if (r < 0)
                log_warning_errno(r, "Failed to read credentials, ignoring: %m");

        if (dns) {
                r = manager_parse_dns_server_string_and_warn(m, DNS_SERVER_SYSTEM, dns);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse credential network.dns '%s', ignoring.", dns);

                m->read_resolv_conf = false;
        }

        if (domains) {
                r = manager_parse_search_domains_and_warn(m, domains);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse credential network.search_domains '%s', ignoring.", domains);

                m->read_resolv_conf = false;
        }
}

struct ProcCmdlineInfo {
        Manager *manager;

        /* If there's a setting configured via /proc/cmdline we want to reset the configured lists, but only
         * once, so that multiple nameserver= or domain= settings can be specified on the kernel command line
         * and will be combined. These booleans will be set once we erase the list once. */
        bool dns_server_unlinked;
        bool search_domain_unlinked;
};

static int proc_cmdline_callback(const char *key, const char *value, void *data) {
        struct ProcCmdlineInfo *info = ASSERT_PTR(data);
        int r;

        assert(key);
        assert(info->manager);

        /* The kernel command line option names are chosen to be compatible with what various tools already
         * interpret, for example dracut and SUSE Linux. */

        if (streq(key, "nameserver")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                if (!info->dns_server_unlinked) {
                        /* The kernel command line overrides any prior configuration */
                        dns_server_unlink_all(manager_get_first_dns_server(info->manager, DNS_SERVER_SYSTEM));
                        info->dns_server_unlinked = true;
                }

                r = manager_parse_dns_server_string_and_warn(info->manager, DNS_SERVER_SYSTEM, value);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse DNS server string '%s', ignoring.", value);

                info->manager->read_resolv_conf = false;

        } else if (streq(key, "domain")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                if (!info->search_domain_unlinked) {
                        dns_search_domain_unlink_all(info->manager->search_domains);
                        info->search_domain_unlinked = true;
                }

                r = manager_parse_search_domains_and_warn(info->manager, value);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse credential provided search domain string '%s', ignoring.", value);

                info->manager->read_resolv_conf = false;
        }

        return 0;
}

static void read_proc_cmdline(Manager *m) {
        int r;

        assert(m);

        r = proc_cmdline_parse(proc_cmdline_callback, &(struct ProcCmdlineInfo) { .manager = m }, 0);
        if (r < 0)
                log_warning_errno(r, "Failed to read kernel command line, ignoring: %m");
}

int manager_parse_config_file(Manager *m) {
        int r;

        assert(m);

        r = config_parse_standard_file_with_dropins(
                        "systemd/resolved.conf",
                        "Resolve\0",
                        config_item_perf_lookup, resolved_gperf_lookup,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ m);
        if (r < 0)
                return r;

        read_credentials(m);   /* credentials are only used when nothing is explicitly configured … */
        read_proc_cmdline(m);  /* … but kernel command line overrides local configuration. */

        if (m->need_builtin_fallbacks) {
                r = manager_parse_dns_server_string_and_warn(m, DNS_SERVER_FALLBACK, DNS_SERVERS);
                if (r < 0)
                        return r;
        }

#if !HAVE_OPENSSL_OR_GCRYPT
        if (m->dnssec_mode != DNSSEC_NO) {
                log_warning("DNSSEC option cannot be enabled or set to allow-downgrade when systemd-resolved is built without a cryptographic library. Turning off DNSSEC support.");
                m->dnssec_mode = DNSSEC_NO;
        }
#endif

#if !ENABLE_DNS_OVER_TLS
        if (m->dns_over_tls_mode != DNS_OVER_TLS_NO) {
                log_warning("DNS-over-TLS option cannot be enabled or set to opportunistic when systemd-resolved is built without DNS-over-TLS support. Turning off DNS-over-TLS support.");
                m->dns_over_tls_mode = DNS_OVER_TLS_NO;
        }
#endif
        return 0;
}
