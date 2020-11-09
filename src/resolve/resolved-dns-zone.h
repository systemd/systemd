/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "hashmap.h"

typedef struct DnsZone {
        Hashmap *by_key;
        Hashmap *by_name;
} DnsZone;

typedef struct DnsZoneItem DnsZoneItem;
typedef enum DnsZoneItemState DnsZoneItemState;

#include "resolved-dns-answer.h"
#include "resolved-dns-question.h"
#include "resolved-dns-rr.h"
#include "resolved-dns-transaction.h"

/* RFC 4795 Section 2.8. suggests a TTL of 30s by default */
#define LLMNR_DEFAULT_TTL (30)

/* RFC 6762 Section 10. suggests a TTL of 120s by default */
#define MDNS_DEFAULT_TTL (120)

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
DnsZoneItem* dns_zone_get(DnsZone *z, DnsResourceRecord *rr);
void dns_zone_remove_rr(DnsZone *z, DnsResourceRecord *rr);
int dns_zone_remove_rrs_by_key(DnsZone *z, DnsResourceKey *key);

int dns_zone_lookup(DnsZone *z, DnsResourceKey *key, int ifindex, DnsAnswer **answer, DnsAnswer **soa, bool *tentative);

void dns_zone_item_conflict(DnsZoneItem *i);
void dns_zone_item_notify(DnsZoneItem *i);

int dns_zone_check_conflicts(DnsZone *zone, DnsResourceRecord *rr);
int dns_zone_verify_conflicts(DnsZone *zone, DnsResourceKey *key);

void dns_zone_verify_all(DnsZone *zone);

void dns_zone_item_probe_stop(DnsZoneItem *i);

void dns_zone_dump(DnsZone *zone, FILE *f);
bool dns_zone_is_empty(DnsZone *zone);
bool dns_zone_contains_name(DnsZone *z, const char *name);
