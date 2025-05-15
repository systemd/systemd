/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-forward.h"

typedef enum DnssecResult {
        /* These six are returned by dnssec_verify_rrset() */
        DNSSEC_VALIDATED,
        DNSSEC_VALIDATED_WILDCARD, /* Validated via a wildcard RRSIG, further NSEC/NSEC3 checks necessary */
        DNSSEC_INVALID,
        DNSSEC_SIGNATURE_EXPIRED,
        DNSSEC_UNSUPPORTED_ALGORITHM,
        DNSSEC_TOO_MANY_VALIDATIONS,

        /* These two are added by dnssec_verify_rrset_search() */
        DNSSEC_NO_SIGNATURE,
        DNSSEC_MISSING_KEY,

        /* These five are added by the DnsTransaction logic */
        DNSSEC_UNSIGNED,
        DNSSEC_FAILED_AUXILIARY,
        DNSSEC_NSEC_MISMATCH,
        DNSSEC_INCOMPATIBLE_SERVER,
        DNSSEC_UPSTREAM_FAILURE,

        _DNSSEC_RESULT_MAX,
        _DNSSEC_RESULT_INVALID = -EINVAL,
} DnssecResult;

typedef enum DnssecVerdict {
        DNSSEC_SECURE,
        DNSSEC_INSECURE,
        DNSSEC_BOGUS,
        DNSSEC_INDETERMINATE,

        _DNSSEC_VERDICT_MAX,
        _DNSSEC_VERDICT_INVALID = -EINVAL,
} DnssecVerdict;

#define DNSSEC_CANONICAL_HOSTNAME_MAX (DNS_HOSTNAME_MAX + 2)

/* The longest digest we'll ever generate, of all digest algorithms we support */
#define DNSSEC_HASH_SIZE_MAX (MAX(20, 32))

/* The most invalid signatures we will tolerate for a single rrset */
#define DNSSEC_INVALID_MAX 5

/* The total number of signature validations we will tolerate for a single transaction */
#define DNSSEC_VALIDATION_MAX 64

int dnssec_rrsig_match_dnskey(DnsResourceRecord *rrsig, DnsResourceRecord *dnskey, bool revoked_ok);
int dnssec_key_match_rrsig(const DnsResourceKey *key, DnsResourceRecord *rrsig);

int dnssec_verify_rrset(DnsAnswer *answer, const DnsResourceKey *key, DnsResourceRecord *rrsig, DnsResourceRecord *dnskey, usec_t realtime, DnssecResult *result);
int dnssec_verify_rrset_search(DnsAnswer *answer, const DnsResourceKey *key, DnsAnswer *validated_dnskeys, usec_t realtime, DnssecResult *result, DnsResourceRecord **rrsig);

int dnssec_verify_dnskey_by_ds(DnsResourceRecord *dnskey, DnsResourceRecord *ds, bool mask_revoke);
int dnssec_verify_dnskey_by_ds_search(DnsResourceRecord *dnskey, DnsAnswer *validated_ds);

int dnssec_has_rrsig(DnsAnswer *a, const DnsResourceKey *key);

uint16_t dnssec_keytag(DnsResourceRecord *dnskey, bool mask_revoke);

int dnssec_nsec3_hash(DnsResourceRecord *nsec3, const char *name, void *ret);

typedef enum DnssecNsecResult {
        DNSSEC_NSEC_NO_RR,     /* No suitable NSEC/NSEC3 RR found */
        DNSSEC_NSEC_CNAME,     /* Didn't find what was asked for, but did find CNAME */
        DNSSEC_NSEC_UNSUPPORTED_ALGORITHM,
        DNSSEC_NSEC_NXDOMAIN,
        DNSSEC_NSEC_NODATA,
        DNSSEC_NSEC_FOUND,
        DNSSEC_NSEC_OPTOUT,
} DnssecNsecResult;

int dnssec_nsec_test(DnsAnswer *answer, DnsResourceKey *key, DnssecNsecResult *result, bool *authenticated, uint32_t *ttl);

int dnssec_test_positive_wildcard(DnsAnswer *a, const char *name, const char *source, const char *zone, bool *authenticated);

const char* dnssec_result_to_string(DnssecResult m) _const_;
DnssecResult dnssec_result_from_string(const char *s) _pure_;

const char* dnssec_verdict_to_string(DnssecVerdict m) _const_;
DnssecVerdict dnssec_verdict_from_string(const char *s) _pure_;
