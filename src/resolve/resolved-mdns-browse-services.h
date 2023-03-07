/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

typedef struct mDnsServiceSubscriber mDnsServiceSubscriber;

#include "resolved-manager.h"
#include "varlink.h"

typedef struct mDnsServices mDnsServices;

typedef enum mDnsRecordTTLState mDnsRecordTTLState;

enum mDnsRecordTTLState {
        MDNS_TTL_80_PERCENT,
        MDNS_TTL_85_PERCENT,
        MDNS_TTL_90_PERCENT,
        MDNS_TTL_95_PERCENT,
        MDNS_TTL_100_PERCENT
};

struct mDnsServices {
        unsigned n_ref;
        mDnsServiceSubscriber *ss;
        sd_event_source *schedule_event;
        DnsResourceRecord *rr;
        int family;
        usec_t until;
        mDnsRecordTTLState rr_ttl_state;
        DnsQuery *query;
        LIST_FIELDS(mDnsServices, mdns_services);
};

struct mDnsServiceSubscriber {
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
        LIST_HEAD(mDnsServices, mdns_services);
};

mDnsServiceSubscriber *mdns_service_subscriber_free(mDnsServiceSubscriber *ss);
void mdns_remove_service(mDnsServiceSubscriber *ss, mDnsServices *service);
mDnsServices *mdns_service_free(mDnsServices *service);

mDnsServiceSubscriber* mdns_service_subscriber_ref(mDnsServiceSubscriber *ss);
mDnsServiceSubscriber* mdns_service_subscriber_unref(mDnsServiceSubscriber *ss);

mDnsServices* mdns_service_ref(mDnsServices *service);
mDnsServices* mdns_service_unref(mDnsServices *service);

DEFINE_TRIVIAL_CLEANUP_FUNC(mDnsServiceSubscriber*, mdns_service_subscriber_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(mDnsServices*, mdns_service_unref);

bool mdns_service_contains(mDnsServices *services, DnsResourceRecord *rr, int owner_family);
int mdns_manage_services_answer(mDnsServiceSubscriber *ss, DnsAnswer *answer, int owner_family);
int mdns_add_new_service(mDnsServiceSubscriber *ss, DnsResourceRecord *rr, int owner_family);
int mdns_service_update(mDnsServices *service, DnsResourceRecord *rr, usec_t t);
int mdns_subscriber_lookup_cache(mDnsServiceSubscriber *ss, int owner_family);
int mdns_subscribe_browse_service(Manager *m,
                Varlink *link,
                const char *domain,
                const char * name,
                const char * type,
                const char * ifname,
                const uint64_t token);
int mdns_unsubscribe_browse_service(Manager *m, Varlink *link, uint64_t token);
int mdns_notify_subscribers_unsolicited_updates(Manager *m, DnsAnswer *answer, int owner_family, bool has_goodbye);
