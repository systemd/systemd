/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "hash-funcs.h"

typedef struct DnsStubListenerExtra DnsStubListenerExtra;

typedef enum DnsStubListenerMode {
        DNS_STUB_LISTENER_NO,
        DNS_STUB_LISTENER_UDP = 1 << 0,
        DNS_STUB_LISTENER_TCP = 1 << 1,
        DNS_STUB_LISTENER_YES = DNS_STUB_LISTENER_UDP | DNS_STUB_LISTENER_TCP,
        _DNS_STUB_LISTENER_MODE_MAX,
        _DNS_STUB_LISTENER_MODE_INVALID = -EINVAL,
} DnsStubListenerMode;

#include "resolved-manager.h"

struct DnsStubListenerExtra {
        Manager *manager;

        DnsStubListenerMode mode;

        int family;
        union in_addr_union address;
        uint16_t port;

        sd_event_source *udp_event_source;
        sd_event_source *tcp_event_source;

        Hashmap *queries_by_packet;
};

extern const struct hash_ops dns_stub_listener_extra_hash_ops;

int dns_stub_listener_extra_new(Manager *m, DnsStubListenerExtra **ret);
DnsStubListenerExtra *dns_stub_listener_extra_free(DnsStubListenerExtra *p);
static inline uint16_t dns_stub_listener_extra_port(DnsStubListenerExtra *p) {
        assert(p);

        return p->port > 0 ? p->port : 53;
}

void manager_dns_stub_stop(Manager *m);
int manager_dns_stub_start(Manager *m);

const char* dns_stub_listener_mode_to_string(DnsStubListenerMode p) _const_;
DnsStubListenerMode dns_stub_listener_mode_from_string(const char *s) _pure_;
