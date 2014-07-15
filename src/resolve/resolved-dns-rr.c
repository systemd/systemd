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

#include "resolved-dns-rr.h"

void dns_resource_key_free(DnsResourceKey *key) {
        if (!key)
                return;

        free(key->name);
        zero(*key);
}

DnsResourceRecord* dns_resource_record_new(void) {
        DnsResourceRecord *rr;

        rr = new0(DnsResourceRecord, 1);
        if (!rr)
                return NULL;

        rr->n_ref = 1;
        return rr;
}

DnsResourceRecord* dns_resource_record_ref(DnsResourceRecord *rr) {
        if (!rr)
                return NULL;

        assert(rr->n_ref > 0);
        rr->n_ref++;

        return rr;
}

DnsResourceRecord* dns_resource_record_unref(DnsResourceRecord *rr) {
        if (!rr)
                return NULL;

        assert(rr->n_ref > 0);

        if (rr->n_ref > 1) {
                rr->n_ref--;
                return NULL;
        }

        if (IN_SET(rr->key.type, DNS_TYPE_PTR, DNS_TYPE_NS, DNS_TYPE_CNAME))
                free(rr->ptr.name);
        else if (rr->key.type == DNS_TYPE_HINFO) {
                free(rr->hinfo.cpu);
                free(rr->hinfo.os);
        } else if (!IN_SET(rr->key.type, DNS_TYPE_A, DNS_TYPE_AAAA))
                free(rr->generic.data);

        dns_resource_key_free(&rr->key);
        free(rr);

        return NULL;
}
