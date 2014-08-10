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

#include "hashmap.h"

typedef struct DnsZone {
        Hashmap *by_key;
        Hashmap *by_name;
} DnsZone;

typedef struct DnsZoneItem DnsZoneItem;
typedef enum DnsZoneItemState DnsZoneItemState;

#include "resolved-dns-rr.h"
#include "resolved-dns-question.h"
#include "resolved-dns-answer.h"
#include "resolved-dns-transaction.h"

/* RFC 4795 Section 2.8. suggests a TTL of 30s by default */
#define LLMNR_DEFAULT_TTL (30)

enum DnsZoneItemState {
        DNS_ZONE_ITEM_PROBING,
        DNS_ZONE_ITEM_ESTABLISHED,
        DNS_ZONE_ITEM_VERIFYING,
        DNS_ZONE_ITEM_WITHDRAWN,
};

struct DnsZoneItem {
        DnsScope *scope;
        DnsResourceRecord *rr;

        DnsZoneItemState state;

        unsigned block_ready;

        bool probing_enabled;

        LIST_FIELDS(DnsZoneItem, by_key);
        LIST_FIELDS(DnsZoneItem, by_name);

        DnsTransaction *probe_transaction;
};

void dns_zone_flush(DnsZone *z);

int dns_zone_put(DnsZone *z, DnsScope *s, DnsResourceRecord *rr, bool probe);
void dns_zone_remove_rr(DnsZone *z, DnsResourceRecord *rr);

int dns_zone_lookup(DnsZone *z, DnsQuestion *q, DnsAnswer **answer, DnsAnswer **soa, bool *tentative);

void dns_zone_item_conflict(DnsZoneItem *i);
void dns_zone_item_ready(DnsZoneItem *i);

int dns_zone_check_conflicts(DnsZone *zone, DnsResourceRecord *rr);
int dns_zone_verify_conflicts(DnsZone *zone, DnsResourceKey *key);

void dns_zone_verify_all(DnsZone *zone);

void dns_zone_item_probe_stop(DnsZoneItem *i);
