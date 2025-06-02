/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <resolv.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "label-util.h"
#include "log.h"
#include "ordered-set.h"
#include "path-util.h"
#include "resolved-dns-cache.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-search-domain.h"
#include "resolved-dns-server.h"
#include "resolved-dns-stub.h"
#include "resolved-manager.h"
#include "resolved-resolv-conf.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util-label.h"

int manager_check_resolv_conf(const Manager *m) {
        struct stat st, own;

        assert(m);

        /* This warns only when our stub listener is disabled and /etc/resolv.conf is a symlink to
         * PRIVATE_STATIC_RESOLV_CONF. */

        if (m->dns_stub_listener_mode != DNS_STUB_LISTENER_NO)
                return 0;

        if (stat("/etc/resolv.conf", &st) < 0) {
                if (errno == ENOENT)
                        return 0;

                return log_warning_errno(errno, "Failed to stat /etc/resolv.conf: %m");
        }

        /* Is it symlinked to our own uplink file? */
        if (stat(PRIVATE_STATIC_RESOLV_CONF, &own) >= 0 &&
            stat_inode_same(&st, &own))
                return log_warning_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                         "DNSStubListener= is disabled, but /etc/resolv.conf is a symlink to "
                                         PRIVATE_STATIC_RESOLV_CONF " which expects DNSStubListener= to be enabled.");

        return 0;
}

static bool file_is_our_own(const struct stat *st) {
        assert(st);

        FOREACH_STRING(path,
                       PRIVATE_UPLINK_RESOLV_CONF,
                       PRIVATE_STUB_RESOLV_CONF,
                       PRIVATE_STATIC_RESOLV_CONF) {

                struct stat own;

                /* Is it symlinked to our own uplink file? */
                if (stat(path, &own) >= 0 &&
                    stat_inode_same(st, &own))
                        return true;
        }

        return false;
}

int manager_read_resolv_conf(Manager *m) {
        _cleanup_fclose_ FILE *f = NULL;
        struct stat st;
        unsigned n = 0;
        int r;

        assert(m);

        /* Reads the system /etc/resolv.conf, if it exists and is not
         * symlinked to our own resolv.conf instance */

        if (!m->read_resolv_conf)
                return 0;

        r = stat("/etc/resolv.conf", &st);
        if (r < 0) {
                if (errno == ENOENT)
                        return 0;

                r = log_warning_errno(errno, "Failed to stat /etc/resolv.conf: %m");
                goto clear;
        }

        /* Have we already seen the file? */
        if (stat_inode_unmodified(&st, &m->resolv_conf_stat))
                return 0;

        if (file_is_our_own(&st))
                return 0;

        f = fopen("/etc/resolv.conf", "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                r = log_warning_errno(errno, "Failed to open %s: %m", "/etc/resolv.conf");
                goto clear;
        }

        if (fstat(fileno(f), &st) < 0) {
                r = log_error_errno(errno, "Failed to stat open file: %m");
                goto clear;
        }

        if (file_is_our_own(&st))
                return 0;

        dns_server_mark_all(m->dns_servers);
        dns_search_domain_mark_all(m->search_domains);

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *a;

                r = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (r < 0) {
                        log_error_errno(r, "Failed to read /etc/resolv.conf: %m");
                        goto clear;
                }
                if (r == 0)
                        break;

                n++;

                if (IN_SET(*line, '#', ';', 0))
                        continue;

                a = first_word(line, "nameserver");
                if (a) {
                        r = manager_parse_dns_server_string_and_warn(m, DNS_SERVER_SYSTEM, a);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse DNS server address '%s', ignoring.", a);

                        continue;
                }

                a = first_word(line, "domain");
                if (!a) /* We treat "domain" lines, and "search" lines as equivalent, and add both to our list. */
                        a = first_word(line, "search");
                if (a) {
                        r = manager_parse_search_domains_and_warn(m, a);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse search domain string '%s', ignoring.", a);

                        continue;
                }

                log_syntax(NULL, LOG_DEBUG, "/etc/resolv.conf", n, 0, "Ignoring resolv.conf line: %s", line);
        }

        m->resolv_conf_stat = st;

        /* Flush out all servers and search domains that are still
         * marked. Those are then ones that didn't appear in the new
         * /etc/resolv.conf */
        dns_server_unlink_marked(m->dns_servers);
        dns_search_domain_unlink_marked(m->search_domains);

        /* Whenever /etc/resolv.conf changes, start using the first
         * DNS server of it. This is useful to deal with broken
         * network managing implementations (like NetworkManager),
         * that when connecting to a VPN place both the VPN DNS
         * servers and the local ones in /etc/resolv.conf. Without
         * resetting the DNS server to use back to the first entry we
         * will continue to use the local one thus being unable to
         * resolve VPN domains. */
        manager_set_dns_server(m, m->dns_servers);

        /* Unconditionally flush the cache when /etc/resolv.conf is
         * modified, even if the data it contained was completely
         * identical to the previous version we used. We do this
         * because altering /etc/resolv.conf is typically done when
         * the network configuration changes, and that should be
         * enough to flush the global unicast DNS cache. */
        if (m->unicast_scope)
                dns_cache_flush(&m->unicast_scope->cache);

        /* If /etc/resolv.conf changed, make sure to forget everything we learned about the DNS servers. After all we
         * might now talk to a very different DNS server that just happens to have the same IP address as an old one
         * (think 192.168.1.1). */
        dns_server_reset_features_all(m->dns_servers);

        return 0;

clear:
        dns_server_unlink_all(m->dns_servers);
        dns_search_domain_unlink_all(m->search_domains);
        return r;
}

static void write_resolv_conf_server(DnsServer *s, FILE *f, unsigned *count) {
        DnsScope *scope;

        assert(s);
        assert(f);
        assert(count);

        if (!dns_server_string(s)) {
                log_warning("Out of memory, or invalid DNS address. Ignoring server.");
                return;
        }

        /* resolv.conf simply doesn't support any other ports than 53, hence there's nothing much we can
         * do — we have to suppress these entries */
        if (dns_server_port(s) != 53) {
                log_debug("DNS server %s with non-standard UDP port number, suppressing from generated resolv.conf.", dns_server_string(s));
                return;
        }

        /* Check if the scope this DNS server belongs to is suitable as 'default' route for lookups; resolv.conf does
         * not have a syntax to express that, so it must not appear as a global name server to avoid routing unrelated
         * domains to it (which is a privacy violation, will most probably fail anyway, and adds unnecessary load) */
        scope = dns_server_scope(s);
        if (scope && !dns_scope_is_default_route(scope)) {
                log_debug("Scope of DNS server %s has only route-only domains, not using as global name server", dns_server_string(s));
                return;
        }

        if (*count == MAXNS)
                fputs("# Too many DNS servers configured, the following entries may be ignored.\n", f);
        (*count)++;

        fprintf(f, "nameserver %s\n", dns_server_string(s));
}

static void write_resolv_conf_search(
                OrderedSet *domains,
                FILE *f) {
        char *domain;

        assert(domains);
        assert(f);

        fputs("search", f);

        ORDERED_SET_FOREACH(domain, domains) {
                fputc(' ', f);
                fputs(domain, f);
        }

        fputs("\n", f);
}

static int write_uplink_resolv_conf_contents(FILE *f, OrderedSet *dns, OrderedSet *domains) {

        fputs("# This is "PRIVATE_UPLINK_RESOLV_CONF" managed by man:systemd-resolved(8).\n"
              "# Do not edit.\n"
              "#\n"
              "# This file might be symlinked as /etc/resolv.conf. If you're looking at\n"
              "# /etc/resolv.conf and seeing this text, you have followed the symlink.\n"
              "#\n"
              "# This is a dynamic resolv.conf file for connecting local clients directly to\n"
              "# all known uplink DNS servers. This file lists all configured search domains.\n"
              "#\n"
              "# Third party programs should typically not access this file directly, but only\n"
              "# through the symlink at /etc/resolv.conf. To manage man:resolv.conf(5) in a\n"
              "# different way, replace this symlink by a static file or a different symlink.\n"
              "#\n"
              "# See man:systemd-resolved.service(8) for details about the supported modes of\n"
              "# operation for /etc/resolv.conf.\n"
              "\n", f);

        if (ordered_set_isempty(dns))
                fputs("# No DNS servers known.\n", f);
        else {
                unsigned count = 0;
                DnsServer *s;

                ORDERED_SET_FOREACH(s, dns)
                        write_resolv_conf_server(s, f, &count);
        }

        if (ordered_set_isempty(domains))
                fputs("search .\n", f); /* Make sure that if the local hostname is chosen as fqdn this does not
                                         * imply a search domain */
        else
                write_resolv_conf_search(domains, f);

        return fflush_and_check(f);
}

static int write_stub_resolv_conf_contents(FILE *f, OrderedSet *dns, OrderedSet *domains) {
        fputs("# This is "PRIVATE_STUB_RESOLV_CONF" managed by man:systemd-resolved(8).\n"
              "# Do not edit.\n"
              "#\n"
              "# This file might be symlinked as /etc/resolv.conf. If you're looking at\n"
              "# /etc/resolv.conf and seeing this text, you have followed the symlink.\n"
              "#\n"
              "# This is a dynamic resolv.conf file for connecting local clients to the\n"
              "# internal DNS stub resolver of systemd-resolved. This file lists all\n"
              "# configured search domains.\n"
              "#\n"
              "# Run \"resolvectl status\" to see details about the uplink DNS servers\n"
              "# currently in use.\n"
              "#\n"
              "# Third party programs should typically not access this file directly, but only\n"
              "# through the symlink at /etc/resolv.conf. To manage man:resolv.conf(5) in a\n"
              "# different way, replace this symlink by a static file or a different symlink.\n"
              "#\n"
              "# See man:systemd-resolved.service(8) for details about the supported modes of\n"
              "# operation for /etc/resolv.conf.\n"
              "\n"
              "nameserver 127.0.0.53\n"
              "options edns0 trust-ad\n", f);

        if (ordered_set_isempty(domains))
                fputs("search .\n", f); /* Make sure that if the local hostname is chosen as fqdn this does not
                                         * imply a search domain */
        else
                write_resolv_conf_search(domains, f);

        return fflush_and_check(f);
}

int manager_write_resolv_conf(Manager *m) {
        _cleanup_ordered_set_free_ OrderedSet *dns = NULL, *domains = NULL;
        _cleanup_(unlink_and_freep) char *temp_path_uplink = NULL, *temp_path_stub = NULL;
        _cleanup_fclose_ FILE *f_uplink = NULL, *f_stub = NULL;
        int r;

        assert(m);

        /* Read the system /etc/resolv.conf first */
        (void) manager_read_resolv_conf(m);

        /* Add the full list to a set, to filter out duplicates */
        r = manager_compile_dns_servers(m, &dns);
        if (r < 0)
                return log_warning_errno(r, "Failed to compile list of DNS servers, ignoring: %m");

        r = manager_compile_search_domains(m, &domains, false);
        if (r < 0)
                return log_warning_errno(r, "Failed to compile list of search domains, ignoring: %m");

        r = fopen_temporary_label(PRIVATE_UPLINK_RESOLV_CONF, PRIVATE_UPLINK_RESOLV_CONF, &f_uplink, &temp_path_uplink);
        if (r < 0)
                return log_warning_errno(r, "Failed to open new %s for writing, ignoring: %m", PRIVATE_UPLINK_RESOLV_CONF);

        (void) fchmod(fileno(f_uplink), 0644);

        r = write_uplink_resolv_conf_contents(f_uplink, dns, domains);
        if (r < 0)
                return log_warning_errno(r, "Failed to write new %s, ignoring: %m", PRIVATE_UPLINK_RESOLV_CONF);

        if (m->dns_stub_listener_mode != DNS_STUB_LISTENER_NO) {
                r = fopen_temporary_label(PRIVATE_STUB_RESOLV_CONF, PRIVATE_STUB_RESOLV_CONF, &f_stub, &temp_path_stub);
                if (r < 0)
                        return log_warning_errno(r, "Failed to open new %s for writing, ignoring: %m", PRIVATE_STUB_RESOLV_CONF);

                (void) fchmod(fileno(f_stub), 0644);

                r = write_stub_resolv_conf_contents(f_stub, dns, domains);
                if (r < 0)
                        return log_warning_errno(r, "Failed to write new %s, ignoring: %m", PRIVATE_STUB_RESOLV_CONF);

                r = conservative_rename(temp_path_stub, PRIVATE_STUB_RESOLV_CONF);
                if (r < 0)
                        log_warning_errno(r, "Failed to move new %s into place, ignoring: %m", PRIVATE_STUB_RESOLV_CONF);

                temp_path_stub = mfree(temp_path_stub); /* free the string explicitly, so that we don't unlink anymore */
        } else {
                _cleanup_free_ char *fname = NULL;
                r = path_extract_filename(PRIVATE_UPLINK_RESOLV_CONF, &fname);
                if (r < 0)
                        return log_warning_errno(r, "Failed to extract filename from path '" PRIVATE_UPLINK_RESOLV_CONF "', ignoring: %m");

                r = symlink_atomic_label(fname, PRIVATE_STUB_RESOLV_CONF);
                if (r < 0)
                        log_warning_errno(r, "Failed to symlink %s, ignoring: %m", PRIVATE_STUB_RESOLV_CONF);
        }

        r = conservative_rename(temp_path_uplink, PRIVATE_UPLINK_RESOLV_CONF);
        if (r < 0)
                log_warning_errno(r, "Failed to move new %s into place: %m", PRIVATE_UPLINK_RESOLV_CONF);

        temp_path_uplink = mfree(temp_path_uplink); /* free the string explicitly, so that we don't unlink anymore */
        return r;
}

int resolv_conf_mode(void) {
        static const char * const table[_RESOLV_CONF_MODE_MAX] = {
                [RESOLV_CONF_UPLINK] = PRIVATE_UPLINK_RESOLV_CONF,
                [RESOLV_CONF_STUB] = PRIVATE_STUB_RESOLV_CONF,
                [RESOLV_CONF_STATIC] = PRIVATE_STATIC_RESOLV_CONF,
        };

        struct stat system_st;

        if (stat("/etc/resolv.conf", &system_st) < 0) {
                if (errno == ENOENT)
                        return RESOLV_CONF_MISSING;

                return -errno;
        }

        for (ResolvConfMode m = 0; m < _RESOLV_CONF_MODE_MAX; m++) {
                struct stat our_st;

                if (!table[m])
                        continue;

                if (stat(table[m], &our_st) < 0) {
                        if (errno != ENOENT)
                                log_debug_errno(errno, "Failed to stat() %s, ignoring: %m", table[m]);

                        continue;
                }

                if (stat_inode_same(&system_st, &our_st))
                        return m;
        }

        return RESOLV_CONF_FOREIGN;
}

static const char* const resolv_conf_mode_table[_RESOLV_CONF_MODE_MAX] = {
        [RESOLV_CONF_UPLINK] = "uplink",
        [RESOLV_CONF_STUB] = "stub",
        [RESOLV_CONF_STATIC] = "static",
        [RESOLV_CONF_MISSING] = "missing",
        [RESOLV_CONF_FOREIGN] = "foreign",
};
DEFINE_STRING_TABLE_LOOKUP(resolv_conf_mode, ResolvConfMode);
