/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <netinet/in.h>

#include "bitmap.h"
#include "dns-def.h"
#include "dns-type.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "json.h"
#include "list.h"
#include "string-util.h"
#include "time-util.h"

typedef struct DnsResourceKey DnsResourceKey;
typedef struct DnsResourceRecord DnsResourceRecord;
typedef struct DnsTxtItem DnsTxtItem;
typedef struct DnsSvcParam DnsSvcParam;

/* DNSKEY RR flags */
#define DNSKEY_FLAG_SEP            (UINT16_C(1) << 0)
#define DNSKEY_FLAG_REVOKE         (UINT16_C(1) << 7)
#define DNSKEY_FLAG_ZONE_KEY       (UINT16_C(1) << 8)

/* mDNS RR flags */
#define MDNS_RR_CACHE_FLUSH_OR_QU  (UINT16_C(1) << 15)

/* DNSSEC algorithm identifiers, see
 * http://tools.ietf.org/html/rfc4034#appendix-A.1 and
 * https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml */
enum {
        DNSSEC_ALGORITHM_RSAMD5 = 1,
        DNSSEC_ALGORITHM_DH,
        DNSSEC_ALGORITHM_DSA,
        DNSSEC_ALGORITHM_ECC,
        DNSSEC_ALGORITHM_RSASHA1,
        DNSSEC_ALGORITHM_DSA_NSEC3_SHA1,
        DNSSEC_ALGORITHM_RSASHA1_NSEC3_SHA1,
        DNSSEC_ALGORITHM_RSASHA256 = 8,        /* RFC 5702 */
        DNSSEC_ALGORITHM_RSASHA512 = 10,       /* RFC 5702 */
        DNSSEC_ALGORITHM_ECC_GOST = 12,        /* RFC 5933 */
        DNSSEC_ALGORITHM_ECDSAP256SHA256 = 13, /* RFC 6605 */
        DNSSEC_ALGORITHM_ECDSAP384SHA384 = 14, /* RFC 6605 */
        DNSSEC_ALGORITHM_ED25519 = 15,         /* RFC 8080 */
        DNSSEC_ALGORITHM_ED448 = 16,           /* RFC 8080 */
        DNSSEC_ALGORITHM_INDIRECT = 252,
        DNSSEC_ALGORITHM_PRIVATEDNS,
        DNSSEC_ALGORITHM_PRIVATEOID,
        _DNSSEC_ALGORITHM_MAX_DEFINED
};

/* DNSSEC digest identifiers, see
 * https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml */
enum {
        DNSSEC_DIGEST_SHA1 = 1,
        DNSSEC_DIGEST_SHA256 = 2,              /* RFC 4509 */
        DNSSEC_DIGEST_GOST_R_34_11_94 = 3,     /* RFC 5933 */
        DNSSEC_DIGEST_SHA384 = 4,              /* RFC 6605 */
        _DNSSEC_DIGEST_MAX_DEFINED
};

/* DNSSEC NSEC3 hash algorithms, see
 * https://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml */
enum {
        NSEC3_ALGORITHM_SHA1 = 1,
        _NSEC3_ALGORITHM_MAX_DEFINED
};

struct DnsResourceKey {
        unsigned n_ref; /* (unsigned -1) for const keys, see below */
        uint16_t class, type;
        char *_name; /* don't access directly, use dns_resource_key_name()! */
};

/* Creates a temporary resource key. This is only useful to quickly
 * look up something, without allocating a full DnsResourceKey object
 * for it. Note that it is not OK to take references to this kind of
 * resource key object. */
#define DNS_RESOURCE_KEY_CONST(c, t, n)                 \
        ((DnsResourceKey) {                             \
                .n_ref = UINT_MAX,                      \
                .class = c,                             \
                .type = t,                              \
                ._name = (char*) n,                     \
        })

struct DnsTxtItem {
        size_t length;
        LIST_FIELDS(DnsTxtItem, items);
        uint8_t data[];
};

struct DnsSvcParam {
        uint16_t key;
        size_t length;
        LIST_FIELDS(DnsSvcParam, params);
        /* Alignment is convinient for reading ip addresses */
        _alignas_(in_addr_t) uint8_t value[];
};

struct DnsResourceRecord {
        unsigned n_ref;
        uint32_t ttl;
        usec_t expiry; /* RRSIG signature expiry */

        DnsResourceKey *key;

        char *to_string;

        /* How many labels to strip to determine "signer" of the RRSIG (aka, the zone). -1 if not signed. */
        uint8_t n_skip_labels_signer;
        /* How many labels to strip to determine "synthesizing source" of this RR, i.e. the wildcard's immediate parent. -1 if not signed. */
        uint8_t n_skip_labels_source;

        bool unparsable;
        bool wire_format_canonical;

        void *wire_format;
        size_t wire_format_size;
        size_t wire_format_rdata_offset;

        union {
                struct {
                        void *data;
                        size_t data_size;
                } generic, opt;

                struct {
                        char *name;
                        uint16_t priority;
                        uint16_t weight;
                        uint16_t port;
                } srv;

                struct {
                        char *name;
                } ptr, ns, cname, dname;

                struct {
                        char *cpu;
                        char *os;
                } hinfo;

                struct {
                        DnsTxtItem *items;
                } txt, spf;

                struct {
                        struct in_addr in_addr;
                } a;

                struct {
                        struct in6_addr in6_addr;
                } aaaa;

                struct {
                        char *mname;
                        char *rname;
                        uint32_t serial;
                        uint32_t refresh;
                        uint32_t retry;
                        uint32_t expire;
                        uint32_t minimum;
                } soa;

                struct {
                        char *exchange;
                        uint16_t priority;
                } mx;

                /* https://tools.ietf.org/html/rfc1876 */
                struct {
                        uint8_t version;
                        uint8_t size;
                        uint8_t horiz_pre;
                        uint8_t vert_pre;
                        uint32_t latitude;
                        uint32_t longitude;
                        uint32_t altitude;
                } loc;

                /* https://tools.ietf.org/html/rfc4255#section-3.1 */
                struct {
                        void *fingerprint;
                        size_t fingerprint_size;

                        uint8_t algorithm;
                        uint8_t fptype;
                } sshfp;

                /* http://tools.ietf.org/html/rfc4034#section-2.1 */
                struct {
                        void* key;
                        size_t key_size;

                        uint16_t flags;
                        uint8_t protocol;
                        uint8_t algorithm;
                } dnskey;

                /* http://tools.ietf.org/html/rfc4034#section-3.1 */
                struct {
                        char *signer;
                        void *signature;
                        size_t signature_size;

                        uint16_t type_covered;
                        uint8_t algorithm;
                        uint8_t labels;
                        uint32_t original_ttl;
                        uint32_t expiration;
                        uint32_t inception;
                        uint16_t key_tag;
                } rrsig;

                /* https://tools.ietf.org/html/rfc4034#section-4.1 */
                struct {
                        char *next_domain_name;
                        Bitmap *types;
                } nsec;

                /* https://tools.ietf.org/html/rfc4034#section-5.1 */
                struct {
                        void *digest;
                        size_t digest_size;

                        uint16_t key_tag;
                        uint8_t algorithm;
                        uint8_t digest_type;
                } ds;

                struct {
                        Bitmap *types;
                        void *salt;
                        size_t salt_size;
                        void *next_hashed_name;
                        size_t next_hashed_name_size;

                        uint8_t algorithm;
                        uint8_t flags;
                        uint16_t iterations;
                } nsec3;

                /* https://tools.ietf.org/html/draft-ietf-dane-protocol-23 */
                struct {
                        void *data;
                        size_t data_size;

                        uint8_t cert_usage;
                        uint8_t selector;
                        uint8_t matching_type;
                } tlsa;

                /* https://tools.ietf.org/html/rfc9460 */
                struct {
                        uint16_t priority;
                        char *target_name;
                        DnsSvcParam *params;
                } svcb, https;

                /* https://tools.ietf.org/html/rfc6844 */
                struct {
                        char *tag;
                        void *value;
                        size_t value_size;

                        uint8_t flags;
                } caa;
        };

        /* Note: fields should be ordered to minimize alignment gaps. Use pahole! */
};

/* We use uint8_t for label counts above, and UINT8_MAX/-1 has special meaning. */
assert_cc(DNS_N_LABELS_MAX < UINT8_MAX);

static inline const void* DNS_RESOURCE_RECORD_RDATA(const DnsResourceRecord *rr) {
        if (!rr)
                return NULL;

        if (!rr->wire_format)
                return NULL;

        assert(rr->wire_format_rdata_offset <= rr->wire_format_size);
        return (uint8_t*) rr->wire_format + rr->wire_format_rdata_offset;
}

static inline size_t DNS_RESOURCE_RECORD_RDATA_SIZE(const DnsResourceRecord *rr) {
        if (!rr)
                return 0;
        if (!rr->wire_format)
                return 0;

        assert(rr->wire_format_rdata_offset <= rr->wire_format_size);
        return rr->wire_format_size - rr->wire_format_rdata_offset;
}

static inline uint8_t DNS_RESOURCE_RECORD_OPT_VERSION_SUPPORTED(const DnsResourceRecord *rr) {
        assert(rr);
        assert(rr->key->type == DNS_TYPE_OPT);

        return ((rr->ttl >> 16) & 0xFF) == 0;
}

DnsResourceKey* dns_resource_key_new(uint16_t class, uint16_t type, const char *name);
DnsResourceKey* dns_resource_key_new_redirect(const DnsResourceKey *key, const DnsResourceRecord *cname);
int dns_resource_key_new_append_suffix(DnsResourceKey **ret, DnsResourceKey *key, char *name);
DnsResourceKey* dns_resource_key_new_consume(uint16_t class, uint16_t type, char *name);
DnsResourceKey* dns_resource_key_ref(DnsResourceKey *key);
DnsResourceKey* dns_resource_key_unref(DnsResourceKey *key);

#define DNS_RESOURCE_KEY_REPLACE(a, b)          \
        do {                                    \
                typeof(a)* _a = &(a);           \
                typeof(b) _b = (b);             \
                dns_resource_key_unref(*_a);    \
                *_a = _b;                       \
        } while(0)

const char* dns_resource_key_name(const DnsResourceKey *key);
bool dns_resource_key_is_address(const DnsResourceKey *key);
bool dns_resource_key_is_dnssd_ptr(const DnsResourceKey *key);
int dns_resource_key_equal(const DnsResourceKey *a, const DnsResourceKey *b);
int dns_resource_key_match_rr(const DnsResourceKey *key, DnsResourceRecord *rr, const char *search_domain);
int dns_resource_key_match_cname_or_dname(const DnsResourceKey *key, const DnsResourceKey *cname, const char *search_domain);
int dns_resource_key_match_soa(const DnsResourceKey *key, const DnsResourceKey *soa);

/* _DNS_{CLASS,TYPE}_STRING_MAX include one byte for NUL, which we use for space instead below.
 * DNS_HOSTNAME_MAX does not include the NUL byte, so we need to add 1. */
#define DNS_RESOURCE_KEY_STRING_MAX (_DNS_CLASS_STRING_MAX + _DNS_TYPE_STRING_MAX + DNS_HOSTNAME_MAX + 1)

char* dns_resource_key_to_string(const DnsResourceKey *key, char *buf, size_t buf_size);
ssize_t dns_resource_record_payload(DnsResourceRecord *rr, void **out);

#define DNS_RESOURCE_KEY_TO_STRING(key) \
        dns_resource_key_to_string(key, (char[DNS_RESOURCE_KEY_STRING_MAX]) {}, DNS_RESOURCE_KEY_STRING_MAX)

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsResourceKey*, dns_resource_key_unref);

static inline bool dns_key_is_shared(const DnsResourceKey *key) {
        return key->type == DNS_TYPE_PTR;
}

bool dns_resource_key_reduce(DnsResourceKey **a, DnsResourceKey **b);

DnsResourceRecord* dns_resource_record_new(DnsResourceKey *key);
DnsResourceRecord* dns_resource_record_new_full(uint16_t class, uint16_t type, const char *name);
DnsResourceRecord* dns_resource_record_ref(DnsResourceRecord *rr);
DnsResourceRecord* dns_resource_record_unref(DnsResourceRecord *rr);

#define DNS_RR_REPLACE(a, b)                    \
        do {                                    \
                typeof(a)* _a = &(a);           \
                typeof(b) _b = (b);             \
                dns_resource_record_unref(*_a); \
                *_a = _b;                       \
        } while(0)

int dns_resource_record_new_reverse(DnsResourceRecord **ret, int family, const union in_addr_union *address, const char *name);
int dns_resource_record_new_address(DnsResourceRecord **ret, int family, const union in_addr_union *address, const char *name);
int dns_resource_record_equal(const DnsResourceRecord *a, const DnsResourceRecord *b);
int dns_resource_record_payload_equal(const DnsResourceRecord *a, const DnsResourceRecord *b);

const char* dns_resource_record_to_string(DnsResourceRecord *rr);
DnsResourceRecord *dns_resource_record_copy(DnsResourceRecord *rr);
DEFINE_TRIVIAL_CLEANUP_FUNC(DnsResourceRecord*, dns_resource_record_unref);

int dns_resource_record_to_wire_format(DnsResourceRecord *rr, bool canonical);

int dns_resource_record_signer(DnsResourceRecord *rr, const char **ret);
int dns_resource_record_source(DnsResourceRecord *rr, const char **ret);
int dns_resource_record_is_signer(DnsResourceRecord *rr, const char *zone);
int dns_resource_record_is_synthetic(DnsResourceRecord *rr);

int dns_resource_record_clamp_ttl(DnsResourceRecord **rr, uint32_t max_ttl);

bool dns_resource_record_is_link_local_address(DnsResourceRecord *rr);

int dns_resource_record_get_cname_target(DnsResourceKey *key, DnsResourceRecord *cname, char **ret);

DnsTxtItem *dns_txt_item_free_all(DnsTxtItem *i);
bool dns_txt_item_equal(DnsTxtItem *a, DnsTxtItem *b);
DnsTxtItem *dns_txt_item_copy(DnsTxtItem *i);
int dns_txt_item_new_empty(DnsTxtItem **ret);

DnsSvcParam *dns_svc_param_free_all(DnsSvcParam *i);
bool dns_svc_params_equal(DnsSvcParam *a, DnsSvcParam *b);
DnsSvcParam *dns_svc_params_copy(DnsSvcParam *first);

int dns_resource_record_new_from_raw(DnsResourceRecord **ret, const void *data, size_t size);

int dns_resource_key_to_json(DnsResourceKey *key, JsonVariant **ret);
int dns_resource_key_from_json(JsonVariant *v, DnsResourceKey **ret);
int dns_resource_record_to_json(DnsResourceRecord *rr, JsonVariant **ret);

void dns_resource_record_hash_func(const DnsResourceRecord *i, struct siphash *state);
int dns_resource_record_compare_func(const DnsResourceRecord *x, const DnsResourceRecord *y);

extern const struct hash_ops dns_resource_key_hash_ops;
extern const struct hash_ops dns_resource_record_hash_ops;

int dnssec_algorithm_to_string_alloc(int i, char **ret);
int dnssec_algorithm_from_string(const char *s) _pure_;

int dnssec_digest_to_string_alloc(int i, char **ret);
int dnssec_digest_from_string(const char *s) _pure_;
