/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "constants.h"
#include "dns-domain.h"
#include "extract-word.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "log.h"
#include "path-util.h"
#include "resolved-dns-delegate.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-search-domain.h"
#include "resolved-dns-server.h"
#include "resolved-manager.h"
#include "socket-netlink.h"
#include "string-util.h"
#include "strv.h"

#define DNS_DELEGATES_MAX 4096U
#define DNS_DELEGATE_SEARCH_DIRS ((const char* const*) CONF_PATHS_STRV("systemd/dns-delegate.d"))

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                dns_delegate_hash_ops,
                char,
                string_hash_func,
                string_compare_func,
                DnsDelegate,
                dns_delegate_free);

int dns_delegate_new(Manager *m, const char *id, DnsDelegate **ret) {
        int r;

        assert(m);
        assert(id);

        if (hashmap_size(m->delegates) >= DNS_DELEGATES_MAX)
                return -E2BIG;

        _cleanup_free_ char *id_copy = strdup(id);
        if (!id_copy)
                return -ENOMEM;

        _cleanup_(dns_delegate_freep) DnsDelegate *d = new(DnsDelegate, 1);
        if (!d)
                return -ENOMEM;

        *d = (DnsDelegate) {
                .id = TAKE_PTR(id_copy),
                .default_route = -1,
        };

        r = dns_scope_new(
                        m,
                        &d->scope,
                        DNS_SCOPE_DELEGATE,
                        /* link= */ NULL,
                        d,
                        DNS_PROTOCOL_DNS,
                        AF_UNSPEC);
        if (r < 0)
                return r;

        r = hashmap_ensure_put(&m->delegates, &dns_delegate_hash_ops, d->id, d);
        if (r < 0)
                return r;

        d->manager = m;

        log_debug("New delegate '%s'.", id);

        if (ret)
                *ret = d;

        TAKE_PTR(d);
        return 0;
}

DnsDelegate *dns_delegate_free(DnsDelegate *d) {
        if (!d)
                return NULL;

        Manager *m = d->manager;

        log_debug("Removing delegate '%s'.", d->id);

        dns_server_unlink_all(d->dns_servers);
        dns_search_domain_unlink_all(d->search_domains);

        dns_scope_free(d->scope);

        if (m)
                hashmap_remove(m->delegates, d->id);

        free(d->id);

        return mfree(d);
}

DnsServer* dns_delegate_set_dns_server(DnsDelegate *d, DnsServer *s) {
        assert(d);

        if (d->current_dns_server == s)
                return s;

        if (s)
                log_debug("Switching delegate '%s' to DNS server %s.", d->id, strna(dns_server_string_full(s)));

        dns_server_unref(d->current_dns_server);
        d->current_dns_server = dns_server_ref(s);

        /* Skip flushing the cache if server stale feature is enabled. */
        if (d->manager->stale_retention_usec == 0)
                dns_cache_flush(&d->scope->cache);

        return s;
}

DnsServer *dns_delegate_get_dns_server(DnsDelegate *d) {
        assert(d);

        if (!d->current_dns_server)
                dns_delegate_set_dns_server(d, d->dns_servers);

        return d->current_dns_server;
}

void dns_delegate_next_dns_server(DnsDelegate *d, DnsServer *if_current) {
        assert(d);

        /* If we have issues with a DNS server, let's switch to the next one (in a round robin scheme). If
         * non-NULL if_current points to the DNS server that was selected at the beginning of whatever bigger
         * operation we are currently executing, and hence if we already switched away from it we suppress
         * switching again, so that each operation only results in a single switch, not multiple. */

        /* If the current server of the transaction is specified, and we already are at a different one,
         * don't do anything */
        if (if_current && d->current_dns_server != if_current)
                return;

        /* If currently have no DNS server, then don't do anything, we'll pick it lazily the next time a DNS
         * server is needed. */
        if (!d->current_dns_server)
                return;

        /* Change to the next one, but make sure to follow the linked list only if this server is actually
         * still linked. */
        if (d->current_dns_server->linked && d->current_dns_server->servers_next) {
                dns_delegate_set_dns_server(d, d->current_dns_server->servers_next);
                return;
        }

        /* Pick the first one again, after we reached the end */
        dns_delegate_set_dns_server(d, d->dns_servers);
}

static int dns_delegate_load(Manager *m, const char *path) {
        int r;

        assert(m);
        assert(path);

        _cleanup_free_ char *fn = NULL;
        r = path_extract_filename(path, &fn);
        if (r < 0)
                return log_error_errno(r, "Failed to extract filename from path '%s': %m", path);

        const char *e = endswith(fn, ".dns-delegate");
        if (!e)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "DNS delegate file name does not end in .dns-delegate, refusing: %s", fn);

        _cleanup_free_ char *id = strndup(fn, e - fn);
        if (!string_is_safe(id))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "DNS delegate file name contains weird characters, refusing: %s", fn);

        _cleanup_free_ char *dropin_dirname = strjoin(id, ".dns-delegate.d");
        if (!dropin_dirname)
                return log_oom();

        _cleanup_(dns_delegate_freep) DnsDelegate *d = NULL;
        r = dns_delegate_new(m, id, &d);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate delegate '%s': %m", id);

        r = config_parse_many(
                        STRV_MAKE_CONST(path),
                        DNS_DELEGATE_SEARCH_DIRS,
                        dropin_dirname,
                        /* root= */ NULL,
                        "Delegate\0",
                        config_item_perf_lookup,
                        resolved_dns_delegate_gperf_lookup,
                        /* flags= */ 0,
                        d,
                        /* ret_stats_by_path= */ NULL,
                        /* ret_drop_in_files= */ NULL);
        if (r < 0)
                return r;

        log_info("Successfully loaded delegate '%s'.", d->id);

        TAKE_PTR(d);
        return 0;
}

int manager_load_delegates(Manager *m) {
        _cleanup_strv_free_ char **files = NULL;
        int r;

        assert(m);

        r = conf_files_list_strv(&files, ".dns-delegate", /* root= */ NULL, /* flags= */ 0, DNS_DELEGATE_SEARCH_DIRS);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate .dns-delegate files: %m");

        STRV_FOREACH(f, files)
                (void) dns_delegate_load(m, *f);

        return 0;
}

int config_parse_delegate_dns_servers(
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

        DnsDelegate *d = ASSERT_PTR(userdata);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        /* Empty assignment means clear the list */
        if (isempty(rvalue)) {
                dns_server_unlink_all(d->dns_servers);
                return 0;
        }

        /* Otherwise, add to the list */
        for (;;) {
                _cleanup_free_ char *word = NULL;
                r = extract_first_word(&rvalue, &word, NULL, 0);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse DNS server string '%s', ignoring.", rvalue);
                        return 0;
                }
                if (r == 0)
                        break;

                _cleanup_free_ char *server_name = NULL;
                union in_addr_union address;
                int family, ifindex = 0;
                uint16_t port;
                r = in_addr_port_ifindex_name_from_string_auto(word, &family, &address, &port, &ifindex, &server_name);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse DNS server string '%s', ignoring.", word);
                        continue;
                }

                /* Silently filter out 0.0.0.0, 127.0.0.53, 127.0.0.54 (our own stub DNS listener) */
                if (!dns_server_address_valid(family, &address))
                        continue;

                /* By default, the port number is determined with the transaction feature level.
                 * See dns_transaction_port() and dns_server_port(). */
                if (IN_SET(port, 53, 853))
                        port = 0;

                /* Filter out duplicates */
                DnsServer *s = dns_server_find(d->dns_servers, family, &address, port, ifindex, server_name);
                if (s) {
                        /* Drop the marker. This is used to find the servers that ceased to exist, see
                         * manager_mark_dns_servers() and manager_flush_marked_dns_servers(). */
                        dns_server_move_back_and_unmark(s);
                        return 0;
                }

                r = dns_server_new(
                                d->manager,
                                /* ret= */ NULL,
                                DNS_SERVER_DELEGATE,
                                /* link= */ NULL,
                                d,
                                family,
                                &address,
                                port,
                                ifindex,
                                server_name,
                                RESOLVE_CONFIG_SOURCE_FILE);
                if (r < 0)
                        return log_error_errno(r, "Failed to add DNS server: %m");
        }

        return 0;
}

int config_parse_delegate_domains(
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

        DnsDelegate *d = ASSERT_PTR(userdata);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        /* Empty assignment means clear the list */
        if (isempty(rvalue)) {
                dns_search_domain_unlink_all(d->search_domains);
                return 0;
        }

        /* Otherwise, add to the list */
        for (;;) {
                _cleanup_free_ char *word = NULL;
                r = extract_first_word(&rvalue, &word, NULL, 0);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse search domains string '%s', ignoring.", rvalue);
                        return 0;
                }
                if (r == 0)
                        break;

                const char *name = word;

                bool route_only = name[0] == '~';
                if (route_only)
                        name++;

                if (dns_name_is_root(name) || streq(name, "*")) {
                        route_only = true;
                        name = ".";
                }

                DnsSearchDomain *domain;
                r = dns_search_domain_find(d->search_domains, name, &domain);
                if (r < 0)
                        return log_error_errno(r, "Failed to find search domain: %m");
                if (r > 0)
                        dns_search_domain_move_back_and_unmark(domain);
                else {
                        r = dns_search_domain_new(d->manager, &domain, DNS_SEARCH_DOMAIN_DELEGATE, /* link= */ NULL, d, name);
                        if (r < 0)
                                return r;
                }

                domain->route_only = route_only;
        }

        return 0;
}
