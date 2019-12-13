/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "fd-util.h"
#include "fileio.h"
#include "hostname-util.h"
#include "resolved-dns-synthesize.h"
#include "resolved-etc-hosts.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"

/* Recheck /etc/hosts at most once every 2s */
#define ETC_HOSTS_RECHECK_USEC (2*USEC_PER_SEC)

static void etc_hosts_item_free(EtcHostsItem *item) {
        strv_free(item->names);
        free(item);
}

static void etc_hosts_item_by_name_free(EtcHostsItemByName *item) {
        free(item->name);
        free(item->addresses);
        free(item);
}

void etc_hosts_free(EtcHosts *hosts) {
        hosts->by_address = hashmap_free_with_destructor(hosts->by_address, etc_hosts_item_free);
        hosts->by_name = hashmap_free_with_destructor(hosts->by_name, etc_hosts_item_by_name_free);
        hosts->no_address = set_free_free(hosts->no_address);
}

void manager_etc_hosts_flush(Manager *m) {
        etc_hosts_free(&m->etc_hosts);
        m->etc_hosts_mtime = USEC_INFINITY;
}

static int parse_line(EtcHosts *hosts, unsigned nr, const char *line) {
        _cleanup_free_ char *address_str = NULL;
        struct in_addr_data address = {};
        bool found = false;
        EtcHostsItem *item;
        int r;

        assert(hosts);
        assert(line);

        r = extract_first_word(&line, &address_str, NULL, EXTRACT_RELAX);
        if (r < 0)
                return log_error_errno(r, "/etc/hosts:%u: failed to extract address: %m", nr);
        assert(r > 0); /* We already checked that the line is not empty, so it should contain *something* */

        r = in_addr_ifindex_from_string_auto(address_str, &address.family, &address.address, NULL);
        if (r < 0) {
                log_warning_errno(r, "/etc/hosts:%u: address '%s' is invalid, ignoring: %m", nr, address_str);
                return 0;
        }

        r = in_addr_is_null(address.family, &address.address);
        if (r < 0) {
                log_warning_errno(r, "/etc/hosts:%u: address '%s' is invalid, ignoring: %m", nr, address_str);
                return 0;
        }
        if (r > 0)
                /* This is an 0.0.0.0 or :: item, which we assume means that we shall map the specified hostname to
                 * nothing. */
                item = NULL;
        else {
                /* If this is a normal address, then simply add entry mapping it to the specified names */

                item = hashmap_get(hosts->by_address, &address);
                if (!item) {
                        r = hashmap_ensure_allocated(&hosts->by_address, &in_addr_data_hash_ops);
                        if (r < 0)
                                return log_oom();

                        item = new0(EtcHostsItem, 1);
                        if (!item)
                                return log_oom();

                        item->address = address;

                        r = hashmap_put(hosts->by_address, &item->address, item);
                        if (r < 0) {
                                free(item);
                                return log_oom();
                        }
                }
        }

        for (;;) {
                _cleanup_free_ char *name = NULL;
                EtcHostsItemByName *bn;

                r = extract_first_word(&line, &name, NULL, EXTRACT_RELAX);
                if (r < 0)
                        return log_error_errno(r, "/etc/hosts:%u: couldn't extract host name: %m", nr);
                if (r == 0)
                        break;

                found = true;

                r = dns_name_is_valid_ldh(name);
                if (r <= 0) {
                        log_warning_errno(r, "/etc/hosts:%u: hostname \"%s\" is not valid, ignoring.", nr, name);
                        continue;
                }

                if (is_localhost(name))
                        /* Suppress the "localhost" line that is often seen */
                        continue;

                if (!item) {
                        /* Optimize the case where we don't need to store any addresses, by storing
                         * only the name in a dedicated Set instead of the hashmap */

                        r = set_ensure_allocated(&hosts->no_address, &dns_name_hash_ops);
                        if (r < 0)
                                return log_oom();

                        r = set_put(hosts->no_address, name);
                        if (r < 0)
                                return r;

                        TAKE_PTR(name);
                        continue;
                }

                r = strv_extend(&item->names, name);
                if (r < 0)
                        return log_oom();

                bn = hashmap_get(hosts->by_name, name);
                if (!bn) {
                        r = hashmap_ensure_allocated(&hosts->by_name, &dns_name_hash_ops);
                        if (r < 0)
                                return log_oom();

                        bn = new0(EtcHostsItemByName, 1);
                        if (!bn)
                                return log_oom();

                        r = hashmap_put(hosts->by_name, name, bn);
                        if (r < 0) {
                                free(bn);
                                return log_oom();
                        }

                        bn->name = TAKE_PTR(name);
                }

                if (!GREEDY_REALLOC(bn->addresses, bn->n_allocated, bn->n_addresses + 1))
                        return log_oom();

                bn->addresses[bn->n_addresses++] = &item->address;
        }

        if (!found)
                log_warning("/etc/hosts:%u: line is missing any host names", nr);

        return 0;
}

int etc_hosts_parse(EtcHosts *hosts, FILE *f) {
        _cleanup_(etc_hosts_free) EtcHosts t = {};
        unsigned nr = 0;
        int r;

        for (;;) {
                _cleanup_free_ char *line = NULL;
                char *l;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read /etc/hosts: %m");
                if (r == 0)
                        break;

                nr++;

                l = strchr(line, '#');
                if (l)
                        *l = '\0';

                l = strstrip(line);
                if (isempty(l))
                        continue;

                r = parse_line(&t, nr, l);
                if (r < 0)
                        return r;
        }

        etc_hosts_free(hosts);
        *hosts = t;
        t = (EtcHosts) {}; /* prevent cleanup */
        return 0;
}

static int manager_etc_hosts_read(Manager *m) {
        _cleanup_fclose_ FILE *f = NULL;
        struct stat st;
        usec_t ts;
        int r;

        assert_se(sd_event_now(m->event, clock_boottime_or_monotonic(), &ts) >= 0);

        /* See if we checked /etc/hosts recently already */
        if (m->etc_hosts_last != USEC_INFINITY && m->etc_hosts_last + ETC_HOSTS_RECHECK_USEC > ts)
                return 0;

        m->etc_hosts_last = ts;

        if (m->etc_hosts_mtime != USEC_INFINITY) {
                if (stat("/etc/hosts", &st) < 0) {
                        if (errno != ENOENT)
                                return log_error_errno(errno, "Failed to stat /etc/hosts: %m");

                        manager_etc_hosts_flush(m);
                        return 0;
                }

                /* Did the mtime change? If not, there's no point in re-reading the file. */
                if (timespec_load(&st.st_mtim) == m->etc_hosts_mtime)
                        return 0;
        }

        f = fopen("/etc/hosts", "re");
        if (!f) {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to open /etc/hosts: %m");

                manager_etc_hosts_flush(m);
                return 0;
        }

        /* Take the timestamp at the beginning of processing, so that any changes made later are read on the next
         * invocation */
        r = fstat(fileno(f), &st);
        if (r < 0)
                return log_error_errno(errno, "Failed to fstat() /etc/hosts: %m");

        r = etc_hosts_parse(&m->etc_hosts, f);
        if (r < 0)
                return r;

        m->etc_hosts_mtime = timespec_load(&st.st_mtim);
        m->etc_hosts_last = ts;

        return 1;
}

int manager_etc_hosts_lookup(Manager *m, DnsQuestion* q, DnsAnswer **answer) {
        bool found_a = false, found_aaaa = false;
        struct in_addr_data k = {};
        EtcHostsItemByName *bn;
        DnsResourceKey *t;
        const char *name;
        unsigned i;
        int r;

        assert(m);
        assert(q);
        assert(answer);

        if (!m->read_etc_hosts)
                return 0;

        (void) manager_etc_hosts_read(m);

        name = dns_question_first_name(q);
        if (!name)
                return 0;

        r = dns_name_address(name, &k.family, &k.address);
        if (r > 0) {
                EtcHostsItem *item;
                DnsResourceKey *found_ptr = NULL;

                item = hashmap_get(m->etc_hosts.by_address, &k);
                if (!item)
                        return 0;

                /* We have an address in /etc/hosts that matches the queried name. Let's return successful. Actual data
                 * we'll only return if the request was for PTR. */

                DNS_QUESTION_FOREACH(t, q) {
                        if (!IN_SET(t->type, DNS_TYPE_PTR, DNS_TYPE_ANY))
                                continue;
                        if (!IN_SET(t->class, DNS_CLASS_IN, DNS_CLASS_ANY))
                                continue;

                        r = dns_name_equal(dns_resource_key_name(t), name);
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                found_ptr = t;
                                break;
                        }
                }

                if (found_ptr) {
                        char **n;

                        r = dns_answer_reserve(answer, strv_length(item->names));
                        if (r < 0)
                                return r;

                        STRV_FOREACH(n, item->names) {
                                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

                                rr = dns_resource_record_new(found_ptr);
                                if (!rr)
                                        return -ENOMEM;

                                rr->ptr.name = strdup(*n);
                                if (!rr->ptr.name)
                                        return -ENOMEM;

                                r = dns_answer_add(*answer, rr, 0, DNS_ANSWER_AUTHENTICATED);
                                if (r < 0)
                                        return r;
                        }
                }

                return 1;
        }

        bn = hashmap_get(m->etc_hosts.by_name, name);
        if (bn) {
                r = dns_answer_reserve(answer, bn->n_addresses);
                if (r < 0)
                        return r;
        } else {
                /* Check if name was listed with no address. If yes, continue to return an answer. */
                if (!set_contains(m->etc_hosts.no_address, name))
                        return 0;
        }

        DNS_QUESTION_FOREACH(t, q) {
                if (!IN_SET(t->type, DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_ANY))
                        continue;
                if (!IN_SET(t->class, DNS_CLASS_IN, DNS_CLASS_ANY))
                        continue;

                r = dns_name_equal(dns_resource_key_name(t), name);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                if (IN_SET(t->type, DNS_TYPE_A, DNS_TYPE_ANY))
                        found_a = true;
                if (IN_SET(t->type, DNS_TYPE_AAAA, DNS_TYPE_ANY))
                        found_aaaa = true;

                if (found_a && found_aaaa)
                        break;
        }

        for (i = 0; bn && i < bn->n_addresses; i++) {
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

                if ((!found_a && bn->addresses[i]->family == AF_INET) ||
                    (!found_aaaa && bn->addresses[i]->family == AF_INET6))
                        continue;

                r = dns_resource_record_new_address(&rr, bn->addresses[i]->family, &bn->addresses[i]->address, bn->name);
                if (r < 0)
                        return r;

                r = dns_answer_add(*answer, rr, 0, DNS_ANSWER_AUTHENTICATED);
                if (r < 0)
                        return r;
        }

        return found_a || found_aaaa;
}
