/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-forward.h"

/* The wire transports used to talk to unicast DNS servers. The enum order is significant: when comparing
 * feature levels, a later transport ranks higher than an earlier one. */
typedef enum DnsTransportKind {
        DNS_TRANSPORT_DNS,       /* RFC 1035: UDP with TCP fallback */
        DNS_TRANSPORT_DOT,       /* RFC 7858: DNS over TLS */
        _DNS_TRANSPORT_KIND_MAX,
        _DNS_TRANSPORT_KIND_INVALID = -EINVAL,
} DnsTransportKind;

DECLARE_STRING_TABLE_LOOKUP(dns_transport_kind, DnsTransportKind);
