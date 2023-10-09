/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

typedef struct DnsServiceBrowser DnsServiceBrowser;

#include "resolved-dns-query.h"
#include "resolved-manager.h"
#include "varlink.h"

typedef struct DnsService DnsService;

typedef enum DnsRecordTTLState DnsRecordTTLState;

enum DnsRecordTTLState {
        MDNS_TTL_80_PERCENT,
        MDNS_TTL_85_PERCENT,
        MDNS_TTL_90_PERCENT,
        MDNS_TTL_95_PERCENT,
        MDNS_TTL_100_PERCENT
};

struct DnsService {
        unsigned n_ref;
        DnsServiceBrowser *sb;
        sd_event_source *schedule_event;
        DnsResourceRecord *rr;
        int family;
        usec_t until;
        DnsRecordTTLState rr_ttl_state;
        DnsQuery *query;
        LIST_FIELDS(DnsService, dns_services);
};

struct DnsServiceBrowser {
        unsigned n_ref;
        Manager *m;
        Varlink *link;
        DnsQuestion *question_idna;
        DnsQuestion *question_utf8;
        uint64_t flags;
        sd_event_source *schedule_event;
        usec_t delay;
        DnsResourceKey *key;
        int ifindex;
        uint64_t token;
        LIST_HEAD(DnsService, dns_services);
};

DnsServiceBrowser *dns_service_browser_free(DnsServiceBrowser *sb);
void dns_remove_service(DnsServiceBrowser *sb, DnsService *service);
DnsService *dns_service_free(DnsService *service);

DnsServiceBrowser* dns_service_browser_ref(DnsServiceBrowser *sb);
DnsServiceBrowser* dns_service_browser_unref(DnsServiceBrowser *sb);

DnsService* dns_service_ref(DnsService *service);
DnsService* dns_service_unref(DnsService *service);

void dns_browse_services_purge(Manager *m, int family);
void dns_service_browser_reset(Manager *m);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsServiceBrowser*, dns_service_browser_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(DnsService*, dns_service_unref);

bool dns_service_contains(DnsService *services, DnsResourceRecord *rr, int owner_family);
int mdns_manage_services_answer(DnsServiceBrowser *sb, DnsAnswer *answer, int owner_family);
int dns_add_new_service(DnsServiceBrowser *sb, DnsResourceRecord *rr, int owner_family);
int mdns_service_update(DnsService *service, DnsResourceRecord *rr, usec_t t);
int mdns_browser_lookup_cache(DnsServiceBrowser *sb, int owner_family);
int dns_subscribe_browse_service(Manager *m,
                Varlink *link,
                const char *domain,
                const char * name,
                const char * type,
                int ifindex,
                uint64_t flags);
int mdns_notify_browsers_unsolicited_updates(Manager *m, DnsAnswer *answer, int owner_family, bool has_goodbye);
