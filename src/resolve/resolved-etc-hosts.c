/* SPDX-License-Identifier: LGPL-2.1+ */

#include "fd-util.h"
#include "fileio.h"
#include "hostname-util.h"
#include "resolved-etc-hosts.h"
#include "resolved-dns-synthesize.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"

/* Recheck /etc/hosts at most once every 2s */
#define ETC_HOSTS_RECHECK_USEC (2*USEC_PER_SEC)

typedef struct EtcHostsItem {
        struct in_addr_data address;

        char **names;
} EtcHostsItem;

typedef struct EtcHostsItemByName {
        char *name;

        struct in_addr_data **addresses;
        size_t n_addresses, n_allocated;
} EtcHostsItemByName;

void manager_etc_hosts_flush(Manager *m) {
        EtcHostsItem *item;
        EtcHostsItemByName *bn;

        while ((item = hashmap_steal_first(m->etc_hosts_by_address))) {
                strv_free(item->names);
                free(item);
        }

        while ((bn = hashmap_steal_first(m->etc_hosts_by_name))) {
                free(bn->name);
                free(bn->addresses);
                free(bn);
        }

        m->etc_hosts_by_address = hashmap_free(m->etc_hosts_by_address);
        m->etc_hosts_by_name = hashmap_free(m->etc_hosts_by_name);

        m->etc_hosts_mtime = USEC_INFINITY;
}

static int parse_line(Manager *m, unsigned nr, const char *line) {
        _cleanup_free_ char *address_str = NULL;
        struct in_addr_data address = {};
        bool suppressed = false;
        EtcHostsItem *item;
        int r;

        assert(m);
        assert(line);

        r = extract_first_word(&line, &address_str, NULL, EXTRACT_RELAX);
        if (r < 0)
                return log_error_errno(r, "Couldn't extract address, in line /etc/hosts:%u.", nr);
        if (r == 0) {
                log_error("Premature end of line, in line /etc/hosts:%u.", nr);
                return -EINVAL;
        }

        r = in_addr_from_string_auto(address_str, &address.family, &address.address);
        if (r < 0)
                return log_error_errno(r, "Address '%s' is invalid, in line /etc/hosts:%u.", address_str, nr);

        r = in_addr_is_null(address.family, &address.address);
        if (r < 0)
                return r;
        if (r > 0)
                /* This is an 0.0.0.0 or :: item, which we assume means that we shall map the specified hostname to
                 * nothing. */
                item = NULL;
        else {
                /* If this is a normal address, then, simply add entry mapping it to the specified names */

                item = hashmap_get(m->etc_hosts_by_address, &address);
                if (!item) {
                        r = hashmap_ensure_allocated(&m->etc_hosts_by_address, &in_addr_data_hash_ops);
                        if (r < 0)
                                return log_oom();

                        item = new0(EtcHostsItem, 1);
                        if (!item)
                                return log_oom();

                        item->address = address;

                        r = hashmap_put(m->etc_hosts_by_address, &item->address, item);
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
                        return log_error_errno(r, "Couldn't extract host name, in line /etc/hosts:%u.", nr);
                if (r == 0)
                        break;

                r = dns_name_is_valid(name);
                if (r <= 0)
                        return log_error_errno(r, "Hostname %s is not valid, ignoring, in line /etc/hosts:%u.", name, nr);

                if (is_localhost(name)) {
                        /* Suppress the "localhost" line that is often seen */
                        suppressed = true;
                        continue;
                }

                if (item) {
                        r = strv_extend(&item->names, name);
                        if (r < 0)
                                return log_oom();
                }

                bn = hashmap_get(m->etc_hosts_by_name, name);
                if (!bn) {
                        r = hashmap_ensure_allocated(&m->etc_hosts_by_name, &dns_name_hash_ops);
                        if (r < 0)
                                return log_oom();

                        bn = new0(EtcHostsItemByName, 1);
                        if (!bn)
                                return log_oom();

                        r = hashmap_put(m->etc_hosts_by_name, name, bn);
                        if (r < 0) {
                                free(bn);
                                return log_oom();
                        }

                        bn->name = TAKE_PTR(name);
                }

                if (item) {
                        if (!GREEDY_REALLOC(bn->addresses, bn->n_allocated, bn->n_addresses + 1))
                                return log_oom();

                        bn->addresses[bn->n_addresses++] = &item->address;
                }

                suppressed = true;
        }

        if (!suppressed) {
                log_error("Line is missing any host names, in line /etc/hosts:%u.", nr);
                return -EINVAL;
        }

        return 0;
}

static int manager_etc_hosts_read(Manager *m) {
        _cleanup_fclose_ FILE *f = NULL;
        char line[LINE_MAX];
        struct stat st;
        usec_t ts;
        unsigned nr = 0;
        int r;

        assert_se(sd_event_now(m->event, clock_boottime_or_monotonic(), &ts) >= 0);

        /* See if we checked /etc/hosts recently already */
        if (m->etc_hosts_last != USEC_INFINITY && m->etc_hosts_last + ETC_HOSTS_RECHECK_USEC > ts)
                return 0;

        m->etc_hosts_last = ts;

        if (m->etc_hosts_mtime != USEC_INFINITY) {
                if (stat("/etc/hosts", &st) < 0) {
                        if (errno == ENOENT) {
                                r = 0;
                                goto clear;
                        }

                        return log_error_errno(errno, "Failed to stat /etc/hosts: %m");
                }

                /* Did the mtime change? If not, there's no point in re-reading the file. */
                if (timespec_load(&st.st_mtim) == m->etc_hosts_mtime)
                        return 0;
        }

        f = fopen("/etc/hosts", "re");
        if (!f) {
                if (errno == ENOENT) {
                        r = 0;
                        goto clear;
                }

                return log_error_errno(errno, "Failed to open /etc/hosts: %m");
        }

        /* Take the timestamp at the beginning of processing, so that any changes made later are read on the next
         * invocation */
        r = fstat(fileno(f), &st);
        if (r < 0)
                return log_error_errno(errno, "Failed to fstat() /etc/hosts: %m");

        manager_etc_hosts_flush(m);

        FOREACH_LINE(line, f, return log_error_errno(errno, "Failed to read /etc/hosts: %m")) {
                char *l;

                nr++;

                l = strstrip(line);
                if (isempty(l))
                        continue;
                if (l[0] == '#')
                        continue;

                r = parse_line(m, nr, l);
                if (r == -ENOMEM) /* On OOM we abandon the half-built-up structure. All other errors we ignore and proceed */
                        goto clear;
        }

        m->etc_hosts_mtime = timespec_load(&st.st_mtim);
        m->etc_hosts_last = ts;

        return 1;

clear:
        manager_etc_hosts_flush(m);
        return r;
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

        r = manager_etc_hosts_read(m);
        if (r < 0)
                return r;

        name = dns_question_first_name(q);
        if (!name)
                return 0;

        r = dns_name_address(name, &k.family, &k.address);
        if (r > 0) {
                EtcHostsItem *item;
                DnsResourceKey *found_ptr = NULL;

                item = hashmap_get(m->etc_hosts_by_address, &k);
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

        bn = hashmap_get(m->etc_hosts_by_name, name);
        if (!bn)
                return 0;

        r = dns_answer_reserve(answer, bn->n_addresses);
        if (r < 0)
                return r;

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

        for (i = 0; i < bn->n_addresses; i++) {
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
