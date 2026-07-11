/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-varlink.h"

#include "dns-answer.h"
#include "dns-question.h"
#include "dns-rr.h"

typedef struct DnsServiceBrowser DnsServiceBrowser;
typedef struct DnsServiceQuerier DnsServiceQuerier;
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
        DnsResourceRecord *rr;
        int family;
        int ifindex;
        usec_t until;
        LIST_FIELDS(DnssdDiscoveredService, dns_services);
};

/* The shared browse engine: everything needed to keep one browse question answered — the continuous
 * query, the TTL re-confirmation ladder and the discovered-service list — exists once per
 * (question, ifindex, flags), no matter how many clients subscribed to it. */
struct DnsServiceQuerier {
        unsigned n_ref;
        Manager *manager;
        DnsQuestion *question_idna;
        DnsQuestion *question_utf8;
        DnsResourceKey *key;
        uint64_t flags;
        int ifindex;
        usec_t delay;
        sd_event_source *schedule_event;      /* continuous browse query (RFC 6762 §5.2 backoff) */
        sd_event_source *maintenance_event;   /* single TTL re-confirmation ladder for the whole RRset */
        DnsQuery *maintenance_query;          /* in-flight ladder query; cleared by its completion handler */
        DnsRecordTTLState rr_ttl_state;       /* the ladder's rung: wound back to 80% whenever the list
                                                 changes or an instance is seen again, advanced only by
                                                 mdns_querier_maintenance(), re-armed once per
                                                 reconciliation (re-arming skips the rungs already
                                                 behind us, so a wind-back only takes effect once an
                                                 expiry moved) */
        LIST_HEAD(DnssdDiscoveredService, dns_services);
        LIST_HEAD(DnsServiceBrowser, subscribers);
};

/* One per varlink BrowseServices subscription; just the client's connection plus its seat on the
 * shared querier. */
struct DnsServiceBrowser {
        Manager *manager;
        sd_varlink *link;
        DnsServiceQuerier *querier;
        LIST_FIELDS(DnsServiceBrowser, subscribers);
};

DnsServiceBrowser *dns_service_browser_free(DnsServiceBrowser *sb);
DnsServiceQuerier *dns_service_querier_free(DnsServiceQuerier *sq);
void dns_remove_service(DnsServiceQuerier *sq, DnssdDiscoveredService *service);
DnssdDiscoveredService *dnssd_discovered_service_free(DnssdDiscoveredService *service);

DECLARE_TRIVIAL_REF_UNREF_FUNC(DnsServiceQuerier, dns_service_querier);

void dns_browse_services_purge(Manager *m, int family);
void dns_browse_services_restart(Manager *m);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsServiceBrowser *, dns_service_browser_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(DnsServiceQuerier *, dns_service_querier_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(DnssdDiscoveredService *, dnssd_discovered_service_free);

int dns_service_match_and_update(
                DnssdDiscoveredService *services,
                DnsResourceRecord *rr,
                int owner_family,
                int ifindex,
                usec_t until);
int mdns_answer_contains_service(
                DnsServiceQuerier *sq,
                DnsAnswer *answer,
                DnssdDiscoveredService *service);
int mdns_manage_services_answer(DnsServiceQuerier *sq, DnsAnswer *answer, int owner_family);
int dns_add_new_service(DnsServiceQuerier *sq, DnsResourceRecord *rr, int owner_family, int ifindex, usec_t until);
void mdns_service_update(DnssdDiscoveredService *service, DnsResourceRecord *rr, usec_t until);
int mdns_querier_revisit_cache(DnsServiceQuerier *sq, int owner_family);
void mdns_querier_abort_maintenance_query(DnsServiceQuerier *sq);
int mdns_querier_maintenance(sd_event_source *s, uint64_t usec, void *userdata);
int dns_subscribe_browse_service(
                Manager *m,
                sd_varlink *link,
                const char *domain,
                const char *type,
                int ifindex,
                uint64_t flags);
int mdns_notify_browsers_unsolicited_updates(Manager *m, DnsAnswer *answer, int owner_family);
int mdns_notify_browsers_goodbye(DnsScope *scope);
