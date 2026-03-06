/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-varlink.h"

#include "dns-answer.h"
#include "dns-question.h"
#include "dns-rr.h"

typedef struct DnsServiceBrowser DnsServiceBrowser;
typedef struct DnssdDiscoveredService DnssdDiscoveredService;
typedef struct DnsQuery DnsQuery;
typedef struct DnsScope DnsScope;
typedef struct Manager Manager;
typedef enum DnsRecordTTLState DnsRecordTTLState;

enum DnsRecordTTLState {
        DNS_RECORD_TTL_STATE_80_PERCENT,
        DNS_RECORD_TTL_STATE_85_PERCENT,
        DNS_RECORD_TTL_STATE_90_PERCENT,
        DNS_RECORD_TTL_STATE_95_PERCENT,
        DNS_RECORD_TTL_STATE_100_PERCENT,
        _DNS_RECORD_TTL_STATE_MAX,
        _DNS_RECORD_TTL_STATE_INVALID = -EINVAL
};

struct DnssdDiscoveredService {
        unsigned n_ref;
        DnsServiceBrowser *service_browser;
        sd_event_source *schedule_event;
        DnsResourceRecord *rr;
        int family;
        int ifindex;
        usec_t until;
        DnsRecordTTLState rr_ttl_state;
        DnsQuery *query;
        LIST_FIELDS(DnssdDiscoveredService, dns_services);
};

struct DnsServiceBrowser {
        unsigned n_ref;
        Manager *manager;
        sd_varlink *link;
        DnsQuestion *question_idna;
        DnsQuestion *question_utf8;
        uint64_t flags;
        sd_event_source *schedule_event;
        usec_t delay;
        DnsResourceKey *key;
        int ifindex;
        uint64_t token;
        LIST_HEAD(DnssdDiscoveredService, dns_services);
};

DnsServiceBrowser *dns_service_browser_free(DnsServiceBrowser *sb);
void dns_remove_service(DnsServiceBrowser *sb, DnssdDiscoveredService *service);
DnssdDiscoveredService *dns_service_free(DnssdDiscoveredService *service);

DECLARE_TRIVIAL_REF_UNREF_FUNC(DnsServiceBrowser, dns_service_browser);
DECLARE_TRIVIAL_REF_UNREF_FUNC(DnssdDiscoveredService, dnssd_discovered_service);

void dns_browse_services_purge(Manager *m, int family);
void dns_browse_services_restart(Manager *m);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsServiceBrowser *, dns_service_browser_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(DnssdDiscoveredService *, dnssd_discovered_service_unref);

bool dns_service_match_and_update(DnssdDiscoveredService *services, DnsResourceRecord *rr, int owner_family, usec_t until);
int mdns_manage_services_answer(DnsServiceBrowser *sb, DnsAnswer *answer, int owner_family);
int dns_add_new_service(DnsServiceBrowser *sb, DnsResourceRecord *rr, int owner_family, int ifindex, usec_t until);
int mdns_service_update(DnssdDiscoveredService *service, DnsResourceRecord *rr, usec_t t, usec_t until);
int mdns_browser_revisit_cache(DnsServiceBrowser *sb, int owner_family);
int dns_subscribe_browse_service(
                Manager *m,
                sd_varlink *link,
                const char *domain,
                const char *type,
                int ifindex,
                uint64_t flags);
int mdns_notify_browsers_unsolicited_updates(Manager *m, DnsAnswer *answer, int owner_family);
int mdns_notify_browsers_goodbye(DnsScope *scope);
