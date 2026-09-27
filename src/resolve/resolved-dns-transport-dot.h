/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if ENABLE_DNS_OVER_TLS

#include "resolved-dns-transport.h"
#include "resolved-dnstls.h"
#include "resolved-forward.h"

/* DNS over TLS, RFC 7858 */
typedef struct DnsTransportDot {
        DnsServerTransport meta;

        unsigned n_failed;

        DnsTlsServerData tls_data;
} DnsTransportDot;

extern const DnsTransportVTable dns_transport_dot_vtable;

DEFINE_DNS_TRANSPORT_CAST(DOT, DnsTransportDot);

#endif
