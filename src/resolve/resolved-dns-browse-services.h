/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-varlink.h"

#include "dns-answer.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "ratelimit.h"

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
        DnsQuery *in_flight_query;            /* the one query in flight, whichever emitter sent it;
                                                 cleared by dns_query_free() */
        DnsRecordTTLState rr_ttl_state;       /* the ladder's rung: wound back to 80% whenever the list
                                                 changes or an instance is seen again, advanced only by
                                                 mdns_querier_run_maintenance(), re-armed once per
                                                 reconciliation (re-arming skips the rungs already
                                                 behind us, so a wind-back only takes effect once an
                                                 expiry moved) */
        usec_t last_wire_query_usec;          /* when this question last went to the network, from
                                                 whichever of the four emitters sent it -- the
                                                 ladder, the continuous schedule, the goodbye rescue
                                                 or a joining subscriber's catch-up. The §5.2
                                                 one-second floor is a property of the question, so
                                                 each of them checks it before adding to the wire */
        RateLimit goodbye_rescue_ratelimit;   /* caps a sustained §10.1 goodbye flood per querier */
        bool initial_query_done;              /* whether the schedule's first query has gone out; only
                                                 that one is cache-served on the schedule's behalf,
                                                 a joining subscriber's catch-up asks separately */
        LIST_HEAD(DnssdDiscoveredService, dns_services);
        LIST_HEAD(DnsServiceBrowser, subscribers);
};

DECLARE_TRIVIAL_REF_UNREF_FUNC(DnsServiceQuerier, dns_service_querier);
DEFINE_TRIVIAL_CLEANUP_FUNC(DnsServiceQuerier *, dns_service_querier_unref);

/* The interface the rest of resolved uses. What follows the marker further down is reconciliation
 * internals, exposed for the unit test alone: reaching into those from elsewhere would rebuild the
 * coupling this split exists to remove. */
void dns_browse_services_purge(Manager *m, int family, int ifindex);
void dns_browse_services_restart(Manager *m, int ifindex);

int dns_subscribe_browse_service(
                Manager *m,
                sd_varlink *link,
                const char *domain,
                const char *type,
                int ifindex,
                uint64_t flags);
void dns_unsubscribe_browse_service(Manager *m, sd_varlink *link);
void dns_service_querier_forget_query(DnsServiceQuerier *sq, DnsQuery *q);
bool mdns_queriers_exist(Manager *m);
/* The goodbye-rescue budgets share one window, and the per-scope burst deliberately sits above the
 * per-querier one: a handful of distinct browse questions on a link can each still be rescued,
 * while one received packet cannot multiply into unbounded multicasts. Coupled here so neither
 * moves without the other being seen. */
#define MDNS_RESCUE_RATELIMIT_INTERVAL_USEC (5 * USEC_PER_MINUTE)
#define MDNS_RESCUE_RATELIMIT_QUERIER_BURST 6U
#define MDNS_RESCUE_RATELIMIT_SCOPE_BURST (2 * MDNS_RESCUE_RATELIMIT_QUERIER_BURST)

void mdns_queriers_notify_unsolicited_updates(DnsScope *scope, DnsAnswer *answer, int owner_family);
void mdns_queriers_rescue_goodbyes(DnsScope *scope, DnsAnswer *goodbyes);

/* Exposed for src/resolve/test-dns-browse-services.c only; not part of the interface above. */
void dns_remove_service(DnsServiceQuerier *sq, DnssdDiscoveredService *service);
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
int dns_add_new_service(
                DnsServiceQuerier *sq,
                DnsResourceRecord *rr,
                int owner_family,
                int ifindex,
                usec_t until);
void mdns_querier_run_maintenance(DnsServiceQuerier *sq);
bool mdns_goodbyes_hit_discovered(DnsServiceQuerier *sq, DnsAnswer *goodbyes, int ifindex);
uint64_t mdns_restrict_flags_to_family(uint64_t flags, int family);
