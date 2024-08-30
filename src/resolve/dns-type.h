/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"

/* DNS record types, taken from
 * http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml.
 */
enum {
        /* 0 is reserved */
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
        DNS_TYPE_SMIMEA, /* RFC 8162 */
        /* 0x36 (54) is not assigned */
        DNS_TYPE_HIP        = 0x37,
        DNS_TYPE_NINFO,
        DNS_TYPE_RKEY,
        DNS_TYPE_TALINK,
        DNS_TYPE_CDS,
        DNS_TYPE_CDNSKEY,
        DNS_TYPE_OPENPGPKEY,
        DNS_TYPE_CSYNC,
        DNS_TYPE_ZONEMD,
        DNS_TYPE_SVCB, /* RFC 9460 */
        DNS_TYPE_HTTPS, /* RFC 9460 */
        /* 0x42…0x62 (66…98) are not assigned */
        DNS_TYPE_SPF        = 0x63,
        DNS_TYPE_UINFO,
        DNS_TYPE_UID,
        DNS_TYPE_GID,
        DNS_TYPE_UNSPEC,
        DNS_TYPE_NID,
        DNS_TYPE_L32,
        DNS_TYPE_L64,
        DNS_TYPE_LP,
        DNS_TYPE_EUI48,
        DNS_TYPE_EUI64,
        /* 0x6e…0xf8 (110…248) are not assigned */
        DNS_TYPE_TKEY       = 0xF9,
        DNS_TYPE_TSIG,
        DNS_TYPE_IXFR,
        DNS_TYPE_AXFR,
        DNS_TYPE_MAILB,
        DNS_TYPE_MAILA,
        DNS_TYPE_ANY,
        DNS_TYPE_URI,
        DNS_TYPE_CAA,
        DNS_TYPE_AVC,
        DNS_TYPE_DOA,
        DNS_TYPE_AMTRELAY,
        DNS_TYPE_RESINFO,
        /* 0x106…0x7fff (262…32767) are not assigned */
        DNS_TYPE_TA         = 0x8000,
        DNS_TYPE_DLV,
        /* 32770…65279 are not assigned */
        /* 65280…65534 are for private use */
        /* 65535 is reserved */
        _DNS_TYPE_MAX,
        _DNS_TYPE_INVALID = -EINVAL,
};

assert_cc(DNS_TYPE_SMIMEA == 53);
assert_cc(DNS_TYPE_HTTPS == 65);
assert_cc(DNS_TYPE_EUI64 == 109);
assert_cc(DNS_TYPE_RESINFO == 261);
assert_cc(DNS_TYPE_ANY == 255);

/* DNS record classes, see RFC 1035 */
enum {
        DNS_CLASS_IN   = 0x01,
        DNS_CLASS_ANY  = 0xFF,

        _DNS_CLASS_MAX,
        _DNS_CLASS_INVALID = -EINVAL,
};

#define _DNS_CLASS_STRING_MAX (sizeof "CLASS" + DECIMAL_STR_MAX(uint16_t))
#define _DNS_TYPE_STRING_MAX (sizeof "CLASS" + DECIMAL_STR_MAX(uint16_t))

bool dns_type_is_pseudo(uint16_t type);
bool dns_type_is_valid_query(uint16_t type);
bool dns_type_is_valid_rr(uint16_t type);
bool dns_type_may_redirect(uint16_t type);
bool dns_type_is_dnssec(uint16_t type);
bool dns_type_is_obsolete(uint16_t type);
bool dns_type_may_wildcard(uint16_t type);
bool dns_type_apex_only(uint16_t type);
bool dns_type_needs_authentication(uint16_t type);
bool dns_type_is_zone_transfer(uint16_t type);
int dns_type_to_af(uint16_t type);

bool dns_class_is_pseudo(uint16_t class);
bool dns_class_is_valid_rr(uint16_t class);

/* TYPE?? follows http://tools.ietf.org/html/rfc3597#section-5 */
const char* dns_type_to_string(int type);
int dns_type_from_string(const char *s);

const char* dns_class_to_string(uint16_t class);
int dns_class_from_string(const char *name);

/* https://tools.ietf.org/html/draft-ietf-dane-protocol-23#section-7.2 */
const char* tlsa_cert_usage_to_string(uint8_t cert_usage);

/* https://tools.ietf.org/html/draft-ietf-dane-protocol-23#section-7.3 */
const char* tlsa_selector_to_string(uint8_t selector);

/* https://tools.ietf.org/html/draft-ietf-dane-protocol-23#section-7.4 */
const char* tlsa_matching_type_to_string(uint8_t selector);

/* https://tools.ietf.org/html/rfc6844#section-5.1 */
#define CAA_FLAG_CRITICAL (1u << 7)
