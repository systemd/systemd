/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "resolved-dns-transport.h"
#include "string-table.h"

static const char* const dns_transport_kind_table[_DNS_TRANSPORT_KIND_MAX] = {
        [DNS_TRANSPORT_DNS] = "dns",
        [DNS_TRANSPORT_DOT] = "dot",
};
DEFINE_STRING_TABLE_LOOKUP(dns_transport_kind, DnsTransportKind);
