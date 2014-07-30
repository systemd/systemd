/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include "resolved-dns-question.h"
#include "resolved-dns-domain.h"

DnsQuestion *dns_question_new(unsigned n) {
        DnsQuestion *q;

        assert(n > 0);

        q = malloc0(offsetof(DnsQuestion, keys) + sizeof(DnsResourceKey*) * n);
        if (!q)
                return NULL;

        q->n_ref = 1;
        q->n_allocated = n;

        return q;
}

DnsQuestion *dns_question_ref(DnsQuestion *q) {
        if (!q)
                return NULL;

        assert(q->n_ref > 0);
        q->n_ref++;
        return q;
}

DnsQuestion *dns_question_unref(DnsQuestion *q) {
        if (!q)
                return NULL;

        assert(q->n_ref > 0);

        if (q->n_ref == 1) {
                unsigned i;

                for (i = 0; i < q->n_keys; i++)
                        dns_resource_key_unref(q->keys[i]);
                free(q);
        } else
                q->n_ref--;

        return  NULL;
}

int dns_question_add(DnsQuestion *q, DnsResourceKey *key) {
        unsigned i;
        int r;

        assert(q);
        assert(key);

        for (i = 0; i < q->n_keys; i++) {
                r = dns_resource_key_equal(q->keys[i], key);
                if (r < 0)
                        return r;
                if (r > 0)
                        return 0;
        }

        if (q->n_keys >= q->n_allocated)
                return -ENOSPC;

        q->keys[q->n_keys++] = dns_resource_key_ref(key);
        return 0;
}

int dns_question_matches_rr(DnsQuestion *q, DnsResourceRecord *rr) {
        unsigned i;
        int r;

        assert(q);
        assert(rr);

        for (i = 0; i < q->n_keys; i++) {
                r = dns_resource_key_match_rr(q->keys[i], rr);
                if (r != 0)
                        return r;
        }

        return 0;
}

int dns_question_matches_cname(DnsQuestion *q, DnsResourceRecord *rr) {
        unsigned i;
        int r;

        assert(q);
        assert(rr);

        for (i = 0; i < q->n_keys; i++) {
                r = dns_resource_key_match_cname(q->keys[i], rr);
                if (r != 0)
                        return r;
        }

        return 0;
}

int dns_question_is_valid(DnsQuestion *q) {
        const char *name;
        unsigned i;
        int r;

        assert(q);

        if (q->n_keys <= 0)
                return 0;

        if (q->n_keys > 65535)
                return 0;

        name = DNS_RESOURCE_KEY_NAME(q->keys[0]);
        if (!name)
                return 0;

        /* Check that all keys in this question bear the same name */
        for (i = 1; i < q->n_keys; i++) {
                assert(q->keys[i]);

                r = dns_name_equal(DNS_RESOURCE_KEY_NAME(q->keys[i]), name);
                if (r <= 0)
                        return r;
        }

        return 1;
}

int dns_question_is_superset(DnsQuestion *q, DnsQuestion *other) {
        unsigned j;
        int r;

        assert(q);
        assert(other);

        /* Checks if all keys in "other" are also contained in "q" */

        for (j = 0; j < other->n_keys; j++) {
                DnsResourceKey *b = other->keys[j];
                bool found = false;
                unsigned i;

                for (i = 0; i < q->n_keys; i++) {
                        DnsResourceKey *a = q->keys[i];

                        r = dns_name_equal(DNS_RESOURCE_KEY_NAME(a), DNS_RESOURCE_KEY_NAME(b));
                        if (r < 0)
                                return r;

                        if (r == 0)
                                continue;

                        if (a->class != b->class && a->class != DNS_CLASS_ANY)
                                continue;

                        if (a->type != b->type && a->type != DNS_TYPE_ANY)
                                continue;

                        found = true;
                        break;
                }

                if (!found)
                        return 0;
        }

        return 1;
}

int dns_question_cname_redirect(DnsQuestion *q, const char *name, DnsQuestion **ret) {
        _cleanup_(dns_question_unrefp) DnsQuestion *n = NULL;
        bool same = true;
        unsigned i;
        int r;

        assert(q);
        assert(name);
        assert(ret);

        for (i = 0; i < q->n_keys; i++) {
                r = dns_name_equal(DNS_RESOURCE_KEY_NAME(q->keys[i]), name);
                if (r < 0)
                        return r;

                if (r == 0) {
                        same = false;
                        break;
                }
        }

        if (same) {
                /* Shortcut, the names are already right */
                *ret = dns_question_ref(q);
                return 0;
        }

        n = dns_question_new(q->n_keys);
        if (!n)
                return -ENOMEM;

        /* Create a new question, and patch in the new name */
        for (i = 0; i < q->n_keys; i++) {
                _cleanup_(dns_resource_key_unrefp) DnsResourceKey *k = NULL;

                k = dns_resource_key_new(q->keys[i]->class, q->keys[i]->type, name);
                if (!k)
                        return -ENOMEM;

                r = dns_question_add(n, k);
                if (r < 0)
                        return r;
        }

        *ret = n;
        n = NULL;

        return 1;
}

int dns_question_endswith(DnsQuestion *q, const char *suffix) {
        unsigned i;

        assert(q);
        assert(suffix);

        for (i = 0; i < q->n_keys; i++) {
                int k;

                k = dns_name_endswith(DNS_RESOURCE_KEY_NAME(q->keys[i]), suffix);
                if (k <= 0)
                        return k;
        }

        return 1;
}

int dns_question_extract_reverse_address(DnsQuestion *q, int *family, union in_addr_union *address) {
        unsigned i;

        assert(q);
        assert(family);
        assert(address);

        for (i = 0; i < q->n_keys; i++) {
                int k;

                k = dns_name_address(DNS_RESOURCE_KEY_NAME(q->keys[i]), family, address);
                if (k != 0)
                        return k;
        }

        return 0;
}
