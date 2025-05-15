/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-def.h"
#include "time-util.h"

/* LLMNR Jitter interval, see RFC 4795 Section 7 */
#define LLMNR_JITTER_INTERVAL_USEC (100 * USEC_PER_MSEC)

/* mDNS probing interval, see RFC 6762 Section 8.1 */
#define MDNS_PROBING_INTERVAL_USEC (250 * USEC_PER_MSEC)

/* Maximum attempts to send DNS requests, across all DNS servers */
#define DNS_TRANSACTION_ATTEMPTS_MAX 24

/* Maximum attempts to send LLMNR requests, see RFC 4795 Section 2.7 */
#define LLMNR_TRANSACTION_ATTEMPTS_MAX 3

/* Maximum attempts to send MDNS requests, see RFC 6762 Section 8.1 */
#define MDNS_TRANSACTION_ATTEMPTS_MAX 3

/* Maximum attempts to send an mDNS continuous query.
 *
 * RFC 6762 Section 5.2 does not specify a maximum number of attempts directly.
 * However, it outlines two important guidelines:
 *
 * 1. The interval between the first two queries MUST be at least one second.
 * 2. The intervals between successive queries MUST increase by at least a factor of two.
 *
 * To adhere to these timing requirements for continuous queries,
 * the maximum number of attempts should be set to 1.
 */
#define MDNS_TRANSACTION_CONTINUOUS_QUERY_MAX 1U

static inline unsigned dns_transaction_attempts_max(DnsProtocol p, uint64_t query_flags) {
        switch (p) {

        case DNS_PROTOCOL_LLMNR:
                return LLMNR_TRANSACTION_ATTEMPTS_MAX;

        case DNS_PROTOCOL_MDNS:
                if (FLAGS_SET(query_flags, SD_RESOLVED_QUERY_CONTINUOUS))
                        return MDNS_TRANSACTION_CONTINUOUS_QUERY_MAX;
                else
                        return MDNS_TRANSACTION_ATTEMPTS_MAX;

        default:
                return DNS_TRANSACTION_ATTEMPTS_MAX;
        }
}

/* After how much time to repeat classic DNS requests */
#define TRANSACTION_UDP_TIMEOUT_USEC (SD_RESOLVED_QUERY_TIMEOUT_USEC / DNS_TRANSACTION_ATTEMPTS_MAX)

/* When we do TCP, grant a much longer timeout, as in this case there's no need for us to quickly
 * resend, as the kernel does that anyway for us, and we really don't want to interrupt it in that
 * needlessly. */
#define TRANSACTION_TCP_TIMEOUT_USEC (10 * USEC_PER_SEC)

/* Should be longer than transaction timeout for a single UDP transaction, so we get at least
 * one transaction retry before timeouting the whole candidate */
#define CANDIDATE_EXPEDITED_TIMEOUT_USEC (TRANSACTION_UDP_TIMEOUT_USEC + 1 * USEC_PER_SEC)
