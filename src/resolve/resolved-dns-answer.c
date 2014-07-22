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

#include "resolved-dns-answer.h"

DnsAnswer *dns_answer_new(unsigned n) {
        DnsAnswer *a;

        assert(n > 0);

        a = malloc0(offsetof(DnsAnswer, rrs) + sizeof(DnsResourceRecord*) * n);
        if (!a)
                return NULL;

        a->n_ref = 1;
        a->n_allocated = n;

        return a;
}

DnsAnswer *dns_answer_ref(DnsAnswer *a) {
        if (!a)
                return NULL;

        assert(a->n_ref > 0);
        a->n_ref++;
        return a;
}

DnsAnswer *dns_answer_unref(DnsAnswer *a) {
        if (!a)
                return NULL;

        assert(a->n_ref > 0);

        if (a->n_ref == 1) {
                unsigned i;

                for (i = 0; i < a->n_rrs; i++)
                        dns_resource_record_unref(a->rrs[i]);

                free(a);
        } else
                a->n_ref--;

        return NULL;
}

int dns_answer_add(DnsAnswer *a, DnsResourceRecord *rr) {
        assert(a);
        assert(rr);

        if (a->n_rrs >= a->n_allocated)
                return -ENOSPC;

        a->rrs[a->n_rrs++] = dns_resource_record_ref(rr);
        return 0;
}
