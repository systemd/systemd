/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

#include "time-util.h"

/* Input + Output: The various protocols we can use */
#define SD_RESOLVED_DNS             (UINT64_C(1) << 0)
#define SD_RESOLVED_LLMNR_IPV4      (UINT64_C(1) << 1)
#define SD_RESOLVED_LLMNR_IPV6      (UINT64_C(1) << 2)
#define SD_RESOLVED_MDNS_IPV4       (UINT64_C(1) << 3)
#define SD_RESOLVED_MDNS_IPV6       (UINT64_C(1) << 4)

/* Input: Don't follow CNAMEs/DNAMEs */
#define SD_RESOLVED_NO_CNAME        (UINT64_C(1) << 5)

/* Input: When doing service (SRV) resolving, don't resolve associated mDNS-style TXT records */
#define SD_RESOLVED_NO_TXT          (UINT64_C(1) << 6)

/* Input: When doing service (SRV) resolving, don't resolve A/AAA RR for included hostname */
#define SD_RESOLVED_NO_ADDRESS      (UINT64_C(1) << 7)

/* Input: Don't apply search domain logic to request */
#define SD_RESOLVED_NO_SEARCH       (UINT64_C(1) << 8)

/* Output: Result is authenticated */
#define SD_RESOLVED_AUTHENTICATED   (UINT64_C(1) << 9)

/* Input: Don't DNSSEC validate request */
#define SD_RESOLVED_NO_VALIDATE     (UINT64_C(1) << 10)

/* Input: Don't answer request from locally synthesized records (which includes /etc/hosts) */
#define SD_RESOLVED_NO_SYNTHESIZE   (UINT64_C(1) << 11)

/* Input: Don't answer request from cache */
#define SD_RESOLVED_NO_CACHE        (UINT64_C(1) << 12)

/* Input: Don't answer request from locally registered public LLMNR/mDNS RRs */
#define SD_RESOLVED_NO_ZONE         (UINT64_C(1) << 13)

/* Input: Don't answer request from locally configured trust anchors. */
#define SD_RESOLVED_NO_TRUST_ANCHOR (UINT64_C(1) << 14)

/* Input: Don't go to network for this request */
#define SD_RESOLVED_NO_NETWORK      (UINT64_C(1) << 15)

/* Input: Require that request is answered from a "primary" answer, i.e. not from RRs acquired as
 * side-effect of a previous transaction */
#define SD_RESOLVED_REQUIRE_PRIMARY (UINT64_C(1) << 16)

/* Input: If reply is answered from cache, the TTLs will be adjusted by age of cache entry */
#define SD_RESOLVED_CLAMP_TTL       (UINT64_C(1) << 17)

/* Output: Result was only sent via encrypted channels, or never left this system */
#define SD_RESOLVED_CONFIDENTIAL    (UINT64_C(1) << 18)

/* Output: Result was (at least partially) synthesized locally */
#define SD_RESOLVED_SYNTHETIC       (UINT64_C(1) << 19)

/* Output: Result was (at least partially) answered from cache */
#define SD_RESOLVED_FROM_CACHE      (UINT64_C(1) << 20)

/* Output: Result was (at least partially) answered from local zone */
#define SD_RESOLVED_FROM_ZONE       (UINT64_C(1) << 21)

/* Output: Result was (at least partially) answered from trust anchor */
#define SD_RESOLVED_FROM_TRUST_ANCHOR (UINT64_C(1) << 22)

/* Output: Result was (at least partially) answered from network */
#define SD_RESOLVED_FROM_NETWORK    (UINT64_C(1) << 23)

#define SD_RESOLVED_LLMNR           (SD_RESOLVED_LLMNR_IPV4|SD_RESOLVED_LLMNR_IPV6)
#define SD_RESOLVED_MDNS            (SD_RESOLVED_MDNS_IPV4|SD_RESOLVED_MDNS_IPV6)
#define SD_RESOLVED_PROTOCOLS_ALL   (SD_RESOLVED_MDNS|SD_RESOLVED_LLMNR|SD_RESOLVED_DNS)

#define SD_RESOLVED_FROM_MASK       (SD_RESOLVED_FROM_CACHE|SD_RESOLVED_FROM_ZONE|SD_RESOLVED_FROM_TRUST_ANCHOR|SD_RESOLVED_FROM_NETWORK)

#define SD_RESOLVED_QUERY_TIMEOUT_USEC (120 * USEC_PER_SEC)
