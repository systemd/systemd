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
        DnsResourceRecord *rr;
        int family;
        int ifindex;
        usec_t until;
        LIST_FIELDS(DnssdDiscoveredService, dns_services);
};

struct DnsServiceBrowser {
        unsigned n_ref;
        Manager *manager;
        sd_varlink *link;
        DnsQuestion *question_idna;
        DnsQuestion *question_utf8;
        uint64_t flags;
        sd_event_source *schedule_event;      /* continuous browse query (RFC 6762 §5.2 backoff) */
        sd_event_source *maintenance_event;   /* single TTL re-confirmation ladder for the whole RRset */
        DnsQuery *maintenance_query;          /* in-flight ladder query; cleared by dns_query_free() */
        DnsRecordTTLState rr_ttl_state;       /* the ladder's rung: wound back to 80% whenever the list
                                                 changes or an instance is seen again, advanced only by
                                                 mdns_browser_maintenance(), re-armed once per
                                                 reconciliation (re-arming skips the rungs already
                                                 behind us, so a wind-back only takes effect once an
                                                 expiry moved) */
        usec_t delay;
        DnsResourceKey *key;
        int ifindex;
        LIST_HEAD(DnssdDiscoveredService, dns_services);
};

DnsServiceBrowser *dns_service_browser_free(DnsServiceBrowser *sb);
void dns_remove_service(DnsServiceBrowser *sb, DnssdDiscoveredService *service);

DECLARE_TRIVIAL_REF_UNREF_FUNC(DnsServiceBrowser, dns_service_browser);

void dns_browse_services_purge(Manager *m, int family);
void dns_browse_services_restart(Manager *m);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsServiceBrowser *, dns_service_browser_unref);

int dns_service_match_and_update(
                DnssdDiscoveredService *services,
                DnsResourceRecord *rr,
                int owner_family,
                int ifindex,
                usec_t until);
int mdns_answer_contains_service(
                DnsServiceBrowser *sb,
                DnsAnswer *answer,
                DnssdDiscoveredService *service);
int mdns_manage_services_answer(DnsServiceBrowser *sb, DnsAnswer *answer, int owner_family);
int dns_add_new_service(DnsServiceBrowser *sb, DnsResourceRecord *rr, int owner_family, int ifindex, usec_t until);
int mdns_browser_revisit_cache(DnsServiceBrowser *sb, int owner_family);
int mdns_browser_maintenance(sd_event_source *s, uint64_t usec, void *userdata);
int dns_subscribe_browse_service(
                Manager *m,
                sd_varlink *link,
                const char *domain,
                const char *type,
                int ifindex,
                uint64_t flags);
void dns_unsubscribe_browse_service(Manager *m, sd_varlink *link);
int mdns_notify_browsers_unsolicited_updates(Manager *m, DnsAnswer *answer, int owner_family);
int mdns_notify_browsers_goodbye(DnsScope *scope);
