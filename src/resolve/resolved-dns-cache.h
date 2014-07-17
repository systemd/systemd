/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

#include <sys/types.h>

#include "hashmap.h"
#include "prioq.h"
#include "time-util.h"
#include "list.h"

typedef struct DnsCacheItem DnsCacheItem;

typedef struct DnsCache {
        Hashmap *rrsets;
        Prioq *expire;
} DnsCache;

#include "resolved-dns-rr.h"

typedef struct DnsCacheItem {
        DnsResourceRecord *rr;
        usec_t timestamp;
        unsigned expire_prioq_idx;
        LIST_FIELDS(DnsCacheItem, rrsets);
} DnsCacheItem;

void dns_cache_flush(DnsCache *c);
void dns_cache_prune(DnsCache *c);

void dns_cache_remove(DnsCache *c, DnsResourceKey *key);

int dns_cache_put(DnsCache *c, DnsResourceRecord *rr, usec_t timestamp);
int dns_cache_put_rrs(DnsCache *c, DnsResourceRecord **rrs, unsigned n_rrs, usec_t timestamp);

DnsCacheItem* dns_cache_lookup(DnsCache *c, DnsResourceKey *key);
DnsCacheItem* dns_cache_get(DnsCache *c, DnsResourceRecord *rr);
int dns_cache_lookup_many(DnsCache *c, DnsResourceKey *keys, unsigned n_keys, DnsResourceRecord ***rrs);
