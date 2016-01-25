/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

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
        int family;
        union in_addr_union address;

        char **names;
} EtcHostsItem;

typedef struct EtcHostsItemByName {
        char *name;

        EtcHostsItem **items;
        size_t n_items, n_allocated;
} EtcHostsItemByName;

void manager_etc_hosts_flush(Manager *m) {
        EtcHostsItem *item;
        EtcHostsItemByName *bn;

        while ((item = set_steal_first(m->etc_hosts_by_address))) {
                strv_free(item->names);
                free(item);
        }

        while ((bn = hashmap_steal_first(m->etc_hosts_by_name))) {
                free(bn->name);
                free(bn->items);
                free(bn);
        }

        m->etc_hosts_by_address = set_free(m->etc_hosts_by_address);
        m->etc_hosts_by_name = hashmap_free(m->etc_hosts_by_name);

        m->etc_hosts_mtime = USEC_INFINITY;
}

static void etc_hosts_item_hash_func(const void *p, struct siphash *state) {
        const EtcHostsItem *item = p;

        siphash24_compress(&item->family, sizeof(item->family), state);

        if (item->family == AF_INET)
                siphash24_compress(&item->address.in, sizeof(item->address.in), state);
        else if (item->family == AF_INET6)
                siphash24_compress(&item->address.in6, sizeof(item->address.in6), state);
}

static int etc_hosts_item_compare_func(const void *a, const void *b) {
        const EtcHostsItem *x = a, *y = b;

        if (x->family != x->family)
                return x->family - y->family;

        if (x->family == AF_INET)
                return memcmp(&x->address.in.s_addr, &y->address.in.s_addr, sizeof(struct in_addr));

        if (x->family == AF_INET6)
                return memcmp(&x->address.in6.s6_addr, &y->address.in6.s6_addr, sizeof(struct in6_addr));

        return trivial_compare_func(a, b);
}

static const struct hash_ops etc_hosts_item_ops = {
        .hash = etc_hosts_item_hash_func,
        .compare = etc_hosts_item_compare_func,
};

static int add_item(Manager *m, int family, const union in_addr_union *address, char **names) {

        EtcHostsItem key = {
                .family = family,
                .address = *address,
        };
        EtcHostsItem *item;
        char **n;
        int r;

        assert(m);
        assert(address);

        r = in_addr_is_null(family, address);
        if (r < 0)
                return r;
        if (r > 0)
                /* This is an 0.0.0.0 or :: item, which we assume means that we shall map the specified hostname to
                 * nothing. */
                item = NULL;
        else {
                /* If this is a normal address, then, simply add entry mapping it to the specified names */

                item = set_get(m->etc_hosts_by_address, &key);
                if (item) {
                        r = strv_extend_strv(&item->names, names, true);
                        if (r < 0)
                                return log_oom();
                } else {

                        r = set_ensure_allocated(&m->etc_hosts_by_address, &etc_hosts_item_ops);
                        if (r < 0)
                                return log_oom();

                        item = new0(EtcHostsItem, 1);
                        if (!item)
                                return log_oom();

                        item->family = family;
                        item->address = *address;
                        item->names = names;

                        r = set_put(m->etc_hosts_by_address, item);
                        if (r < 0) {
                                free(item);
                                return log_oom();
                        }
                }
        }

        STRV_FOREACH(n, names) {
                EtcHostsItemByName *bn;

                bn = hashmap_get(m->etc_hosts_by_name, *n);
                if (!bn) {
                        r = hashmap_ensure_allocated(&m->etc_hosts_by_name, &dns_name_hash_ops);
                        if (r < 0)
                                return log_oom();

                        bn = new0(EtcHostsItemByName, 1);
                        if (!bn)
                                return log_oom();

                        bn->name = strdup(*n);
                        if (!bn->name) {
                                free(bn);
                                return log_oom();
                        }

                        r = hashmap_put(m->etc_hosts_by_name, bn->name, bn);
                        if (r < 0) {
                                free(bn->name);
                                free(bn);
                                return log_oom();
                        }
                }

                if (item) {
                        if (!GREEDY_REALLOC(bn->items, bn->n_allocated, bn->n_items+1))
                                return log_oom();

                        bn->items[bn->n_items++] = item;
                }
        }

        return 0;
}

static int parse_line(Manager *m, unsigned nr, const char *line) {
        _cleanup_free_ char *address = NULL;
        _cleanup_strv_free_ char **names = NULL;
        union in_addr_union in;
        bool suppressed = false;
        int family, r;

        assert(m);
        assert(line);

        r = extract_first_word(&line, &address, NULL, EXTRACT_RELAX);
        if (r < 0)
                return log_error_errno(r, "Couldn't extract address, in line /etc/hosts:%u.", nr);
        if (r == 0) {
                log_error("Premature end of line, in line /etc/hosts:%u.", nr);
                return -EINVAL;
        }

        r = in_addr_from_string_auto(address, &family, &in);
        if (r < 0)
                return log_error_errno(r, "Address '%s' is invalid, in line /etc/hosts:%u.", address, nr);

        for (;;) {
                _cleanup_free_ char *name = NULL;

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

                r = strv_push(&names, name);
                if (r < 0)
                        return log_oom();

                name = NULL;
        }

        if (strv_isempty(names)) {

                if (suppressed)
                        return 0;

                log_error("Line is missing any host names, in line /etc/hosts:%u.", nr);
                return -EINVAL;
        }

        /* Takes possession of the names strv */
        r = add_item(m, family, &in, names);
        if (r < 0)
                return r;

        names = NULL;
        return r;
}

int manager_etc_hosts_read(Manager *m) {
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

                nr ++;

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
        EtcHostsItemByName *bn;
        EtcHostsItem k = {};
        DnsResourceKey *t;
        const char *name;
        unsigned i;
        int r;

        assert(m);
        assert(q);
        assert(answer);

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

                item = set_get(m->etc_hosts_by_address, &k);
                if (!item)
                        return 0;

                /* We have an address in /etc/hosts that matches the queried name. Let's return successful. Actual data
                 * we'll only return if the request was for PTR. */

                DNS_QUESTION_FOREACH(t, q) {
                        if (!IN_SET(t->type, DNS_TYPE_PTR, DNS_TYPE_ANY))
                                continue;
                        if (!IN_SET(t->class, DNS_CLASS_IN, DNS_CLASS_ANY))
                                continue;

                        r = dns_name_equal(DNS_RESOURCE_KEY_NAME(t), name);
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

        r = dns_answer_reserve(answer, bn->n_items);
        if (r < 0)
                return r;

        DNS_QUESTION_FOREACH(t, q) {
                if (!IN_SET(t->type, DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_ANY))
                        continue;
                if (!IN_SET(t->class, DNS_CLASS_IN, DNS_CLASS_ANY))
                        continue;

                r = dns_name_equal(DNS_RESOURCE_KEY_NAME(t), name);
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

        for (i = 0; i < bn->n_items; i++) {
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

                if ((found_a && bn->items[i]->family != AF_INET) &&
                    (found_aaaa && bn->items[i]->family != AF_INET6))
                        continue;

                r = dns_resource_record_new_address(&rr, bn->items[i]->family, &bn->items[i]->address, bn->name);
                if (r < 0)
                        return r;

                r = dns_answer_add(*answer, rr, 0, DNS_ANSWER_AUTHENTICATED);
                if (r < 0)
                        return r;
        }

        return 1;
}
