/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Zbigniew Jędrzejewski-Szmek

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

#pragma once

#include "macro.h"

const char *dns_type_to_string(int type);
int dns_type_from_string(const char *s);

/* DNS record types, taken from
 * http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml.
 */
enum {
        /* Normal records */
        DNS_TYPE_A          = 0x01,
        DNS_TYPE_NS,
        DNS_TYPE_MD,
        DNS_TYPE_MF,
        DNS_TYPE_CNAME,
        DNS_TYPE_SOA,
        DNS_TYPE_MB,
        DNS_TYPE_MG,
        DNS_TYPE_MR,
        DNS_TYPE_NULL,
        DNS_TYPE_WKS,
        DNS_TYPE_PTR,
        DNS_TYPE_HINFO,
        DNS_TYPE_MINFO,
        DNS_TYPE_MX,
        DNS_TYPE_TXT,
        DNS_TYPE_RP,
        DNS_TYPE_AFSDB,
        DNS_TYPE_X25,
        DNS_TYPE_ISDN,
        DNS_TYPE_RT,
        DNS_TYPE_NSAP,
        DNS_TYPE_NSAP_PTR,
        DNS_TYPE_SIG,
        DNS_TYPE_KEY,
        DNS_TYPE_PX,
        DNS_TYPE_GPOS,
        DNS_TYPE_AAAA,
        DNS_TYPE_LOC,
        DNS_TYPE_NXT,
        DNS_TYPE_EID,
        DNS_TYPE_NIMLOC,
        DNS_TYPE_SRV,
        DNS_TYPE_ATMA,
        DNS_TYPE_NAPTR,
        DNS_TYPE_KX,
        DNS_TYPE_CERT,
        DNS_TYPE_A6,
        DNS_TYPE_DNAME,
        DNS_TYPE_SINK,
        DNS_TYPE_OPT,          /* EDNS0 option */
        DNS_TYPE_APL,
        DNS_TYPE_DS,
        DNS_TYPE_SSHFP,
        DNS_TYPE_IPSECKEY,
        DNS_TYPE_RRSIG,
        DNS_TYPE_NSEC,
        DNS_TYPE_DNSKEY,
        DNS_TYPE_DHCID,
        DNS_TYPE_NSEC3,
        DNS_TYPE_NSEC3PARAM,
        DNS_TYPE_TLSA,

        DNS_TYPE_HIP        = 0x37,
        DNS_TYPE_NINFO,
        DNS_TYPE_RKEY,
        DNS_TYPE_TALINK,
        DNS_TYPE_CDS,
        DNS_TYPE_CDNSKEY,

        DNS_TYPE_SPF        = 0x63,
        DNS_TYPE_NID,
        DNS_TYPE_L32,
        DNS_TYPE_L64,
        DNS_TYPE_LP,
        DNS_TYPE_EUI48,
        DNS_TYPE_EUI64,

        DNS_TYPE_TKEY       = 0xF9,
        DNS_TYPE_TSIG,
        DNS_TYPE_IXFR,
        DNS_TYPE_AXFR,
        DNS_TYPE_MAILB,
        DNS_TYPE_MAILA,
        DNS_TYPE_ANY,
        DNS_TYPE_URI,
        DNS_TYPE_CAA,
        DNS_TYPE_TA         = 0x8000,
        DNS_TYPE_DLV,

        _DNS_TYPE_MAX,
        _DNS_TYPE_INVALID = -1
};

assert_cc(DNS_TYPE_SSHFP == 44);
assert_cc(DNS_TYPE_TLSA == 52);
assert_cc(DNS_TYPE_ANY == 255);
