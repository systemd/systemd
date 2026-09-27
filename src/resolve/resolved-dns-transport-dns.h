/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-dns-transport.h"
#include "resolved-forward.h"

/* Classic DNS, RFC 1035: UDP, falling back to TCP */
typedef struct DnsTransportDns {
        DnsServerTransport meta;

        size_t received_udp_fragment_max;   /* largest packet or fragment (without IP/UDP header) we saw so far */

        unsigned n_failed_udp;
        unsigned n_failed_tcp;

        bool packet_truncated:1;            /* Set when TC bit was set on reply */
        bool packet_fragmented:1;           /* Set when we ever saw a fragmented packet */
} DnsTransportDns;

extern const DnsTransportVTable dns_transport_dns_vtable;

DEFINE_DNS_TRANSPORT_CAST(DNS, DnsTransportDns);

void dns_transport_dns_packet_fragmented(DnsTransportDns *d, size_t fragsize);
