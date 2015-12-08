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

#include "dns-domain.h"
#include "resolved-dns-answer.h"
#include "resolved-dns-rr.h"

enum DnssecMode {
        /* No DNSSEC validation is done */
        DNSSEC_NO,

        /* Trust the AD bit sent by the server. UNSAFE! */
        DNSSEC_TRUST,

        /* Validate locally, if the server knows DO, but if not, don't. Don't trust the AD bit */
        DNSSEC_YES,

        _DNSSEC_MODE_MAX,
        _DNSSEC_MODE_INVALID = -1
};

enum {
        DNSSEC_VERIFIED,
        DNSSEC_INVALID,
        DNSSEC_NO_SIGNATURE,
        DNSSEC_MISSING_KEY,
        DNSSEC_SIGNATURE_EXPIRED,
};

#define DNSSEC_CANONICAL_HOSTNAME_MAX (DNS_HOSTNAME_MAX + 2)

int dnssec_rrsig_match_dnskey(DnsResourceRecord *rrsig, DnsResourceRecord *dnskey);
int dnssec_key_match_rrsig(DnsResourceKey *key, DnsResourceRecord *rrsig);

int dnssec_verify_rrset(DnsAnswer *answer, DnsResourceKey *key, DnsResourceRecord *rrsig, DnsResourceRecord *dnskey, usec_t realtime);
int dnssec_verify_rrset_search(DnsAnswer *a, DnsResourceKey *key, DnsAnswer *validated_dnskeys, usec_t realtime);

int dnssec_verify_dnskey(DnsResourceRecord *dnskey, DnsResourceRecord *ds);

uint16_t dnssec_keytag(DnsResourceRecord *dnskey);

int dnssec_canonicalize(const char *n, char *buffer, size_t buffer_max);

const char* dnssec_mode_to_string(DnssecMode m) _const_;
DnssecMode dnssec_mode_from_string(const char *s) _pure_;
