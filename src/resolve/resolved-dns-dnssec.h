/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

typedef enum DnssecMode DnssecMode;
typedef enum DnssecResult DnssecResult;

#include "dns-domain.h"
#include "resolved-dns-answer.h"
#include "resolved-dns-rr.h"

enum DnssecMode {
        /* No DNSSEC validation is done */
        DNSSEC_NO,

        /* Validate locally, if the server knows DO, but if not,
         * don't. Don't trust the AD bit. If the server doesn't do
         * DNSSEC properly, downgrade to non-DNSSEC operation. Of
         * course, we then are vulnerable to a downgrade attack, but
         * that's life and what is configured. */
        DNSSEC_DOWNGRADE_OK,

        /* Insist on DNSSEC server support, and rather fail than downgrading. */
        DNSSEC_YES,

        _DNSSEC_MODE_MAX,
        _DNSSEC_MODE_INVALID = -1
};

enum DnssecResult {
        /* These four are returned by dnssec_verify_rrset() */
        DNSSEC_VALIDATED,
        DNSSEC_INVALID,
        DNSSEC_SIGNATURE_EXPIRED,
        DNSSEC_UNSUPPORTED_ALGORITHM,

        /* These two are added by dnssec_verify_rrset_search() */
        DNSSEC_NO_SIGNATURE,
        DNSSEC_MISSING_KEY,

        /* These two are added by the DnsTransaction logic */
        DNSSEC_UNSIGNED,
        DNSSEC_FAILED_AUXILIARY,
        DNSSEC_NSEC_MISMATCH,
        DNSSEC_INCOMPATIBLE_SERVER,

        _DNSSEC_RESULT_MAX,
        _DNSSEC_RESULT_INVALID = -1
};

#define DNSSEC_CANONICAL_HOSTNAME_MAX (DNS_HOSTNAME_MAX + 2)

/* The longest digest we'll ever generate, of all digest algorithms we support */
#define DNSSEC_HASH_SIZE_MAX (MAX(20, 32))

int dnssec_rrsig_match_dnskey(DnsResourceRecord *rrsig, DnsResourceRecord *dnskey);
int dnssec_key_match_rrsig(const DnsResourceKey *key, DnsResourceRecord *rrsig);

int dnssec_verify_rrset(DnsAnswer *answer, DnsResourceKey *key, DnsResourceRecord *rrsig, DnsResourceRecord *dnskey, usec_t realtime, DnssecResult *result);
int dnssec_verify_rrset_search(DnsAnswer *answer, DnsResourceKey *key, DnsAnswer *validated_dnskeys, usec_t realtime, DnssecResult *result);

int dnssec_verify_dnskey(DnsResourceRecord *dnskey, DnsResourceRecord *ds);
int dnssec_verify_dnskey_search(DnsResourceRecord *dnskey, DnsAnswer *validated_ds);

int dnssec_has_rrsig(DnsAnswer *a, const DnsResourceKey *key);

uint16_t dnssec_keytag(DnsResourceRecord *dnskey);

int dnssec_canonicalize(const char *n, char *buffer, size_t buffer_max);

int dnssec_nsec3_hash(DnsResourceRecord *nsec3, const char *name, void *ret);

typedef enum DnssecNsecResult {
        DNSSEC_NSEC_NO_RR,     /* No suitable NSEC/NSEC3 RR found */
        DNSSEC_NSEC_UNSUPPORTED_ALGORITHM,
        DNSSEC_NSEC_NXDOMAIN,
        DNSSEC_NSEC_NODATA,
        DNSSEC_NSEC_FOUND,
        DNSSEC_NSEC_OPTOUT,
} DnssecNsecResult;

int dnssec_test_nsec(DnsAnswer *answer, DnsResourceKey *key, DnssecNsecResult *result, bool *authenticated);

const char* dnssec_mode_to_string(DnssecMode m) _const_;
DnssecMode dnssec_mode_from_string(const char *s) _pure_;

const char* dnssec_result_to_string(DnssecResult m) _const_;
DnssecResult dnssec_result_from_string(const char *s) _pure_;
