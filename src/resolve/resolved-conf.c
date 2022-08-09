/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "conf-parser.h"
#include "def.h"
#include "extract-word.h"
#include "hexdecoct.h"
#include "parse-util.h"
#include "resolved-conf.h"
#include "resolved-dnssd.h"
#include "resolved-manager.h"
#include "resolved-dns-search-domain.h"
#include "resolved-dns-stub.h"
#include "dns-domain.h"
#include "socket-netlink.h"
#include "specifier.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

DEFINE_CONFIG_PARSE_ENUM(config_parse_dns_stub_listener_mode, dns_stub_listener_mode, DnsStubListenerMode, "Failed to parse DNS stub listener mode setting");

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

        return dns_server_new(m, NULL, type, NULL, family, &address, port, ifindex, server_name);
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

int config_parse_dnssd_service_name(
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

        static const Specifier specifier_table[] = {
                { 'a', specifier_architecture,    NULL },
                { 'b', specifier_boot_id,         NULL },
                { 'B', specifier_os_build_id,     NULL },
                { 'H', specifier_hostname,        NULL }, /* We will use specifier_dnssd_hostname(). */
                { 'm', specifier_machine_id,      NULL },
                { 'o', specifier_os_id,           NULL },
                { 'v', specifier_kernel_release,  NULL },
                { 'w', specifier_os_version_id,   NULL },
                { 'W', specifier_os_variant_id,   NULL },
                {}
        };
        DnssdService *s = ASSERT_PTR(userdata);
        _cleanup_free_ char *name = NULL;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                s->name_template = mfree(s->name_template);
                return 0;
        }

        r = specifier_printf(rvalue, DNS_LABEL_MAX, specifier_table, NULL, NULL, &name);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid service instance name template '%s', ignoring assignment: %m", rvalue);
                return 0;
        }

        if (!dns_service_name_is_valid(name)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Service instance name template '%s' renders to invalid name '%s'. Ignoring assignment.",
                           rvalue, name);
                return 0;
        }

        return free_and_strdup_warn(&s->name_template, rvalue);
}

int config_parse_dnssd_service_type(
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

        DnssdService *s = ASSERT_PTR(userdata);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                s->type = mfree(s->type);
                return 0;
        }

        if (!dnssd_srv_type_is_valid(rvalue)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Service type is invalid. Ignoring.");
                return 0;
        }

        r = free_and_strdup(&s->type, rvalue);
        if (r < 0)
                return log_oom();

        return 0;
}

int config_parse_dnssd_txt(
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

        _cleanup_(dnssd_txtdata_freep) DnssdTxtData *txt_data = NULL;
        DnssdService *s = ASSERT_PTR(userdata);
        DnsTxtItem *last = NULL;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Flush out collected items */
                s->txt_data_items = dnssd_txtdata_free_all(s->txt_data_items);
                return 0;
        }

        txt_data = new0(DnssdTxtData, 1);
        if (!txt_data)
                return log_oom();

        for (;;) {
                _cleanup_free_ char *word = NULL, *key = NULL, *value = NULL;
                _cleanup_free_ void *decoded = NULL;
                size_t length = 0;
                DnsTxtItem *i;
                int r;

                r = extract_first_word(&rvalue, &word, NULL,
                                       EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_RELAX);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }

                r = split_pair(word, "=", &key, &value);
                if (r == -ENOMEM)
                        return log_oom();
                if (r == -EINVAL)
                        key = TAKE_PTR(word);

                if (!ascii_is_valid(key)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid key, ignoring: %s", key);
                        continue;
                }

                switch (ltype) {

                case DNS_TXT_ITEM_DATA:
                        if (value) {
                                r = unbase64mem(value, strlen(value), &decoded, &length);
                                if (r == -ENOMEM)
                                        return log_oom();
                                if (r < 0) {
                                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                                   "Invalid base64 encoding, ignoring: %s", value);
                                        continue;
                                }
                        }

                        r = dnssd_txt_item_new_from_data(key, decoded, length, &i);
                        if (r < 0)
                                return log_oom();
                        break;

                case DNS_TXT_ITEM_TEXT:
                        r = dnssd_txt_item_new_from_string(key, value, &i);
                        if (r < 0)
                                return log_oom();
                        break;

                default:
                        assert_not_reached();
                }

                LIST_INSERT_AFTER(items, txt_data->txts, last, i);
                last = i;
        }

        if (txt_data->txts) {
                LIST_PREPEND(items, s->txt_data_items, txt_data);
                TAKE_PTR(txt_data);
        }

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

int manager_parse_config_file(Manager *m) {
        int r;

        assert(m);

        r = config_parse_many_nulstr(
                        PKGSYSCONFDIR "/resolved.conf",
                        CONF_PATHS_NULSTR("systemd/resolved.conf.d"),
                        "Resolve\0",
                        config_item_perf_lookup, resolved_gperf_lookup,
                        CONFIG_PARSE_WARN,
                        m,
                        NULL);
        if (r < 0)
                return r;

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
