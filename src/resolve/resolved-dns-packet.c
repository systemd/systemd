/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_GCRYPT
#  include <gcrypt.h>
#endif

#include "alloc-util.h"
#include "dns-domain.h"
#include "memory-util.h"
#include "resolved-dns-packet.h"
#include "set.h"
#include "stdio-util.h"
#include "string-table.h"
#include "strv.h"
#include "unaligned.h"
#include "utf8.h"

#define EDNS0_OPT_DO (1<<15)

assert_cc(DNS_PACKET_SIZE_START > DNS_PACKET_HEADER_SIZE);

typedef struct DnsPacketRewinder {
        DnsPacket *packet;
        size_t saved_rindex;
} DnsPacketRewinder;

static void rewind_dns_packet(DnsPacketRewinder *rewinder) {
        if (rewinder->packet)
                dns_packet_rewind(rewinder->packet, rewinder->saved_rindex);
}

#define REWINDER_INIT(p) {                              \
                .packet = (p),                          \
                .saved_rindex = (p)->rindex,            \
        }
#define CANCEL_REWINDER(rewinder) do { (rewinder).packet = NULL; } while (0)

int dns_packet_new(
                DnsPacket **ret,
                DnsProtocol protocol,
                size_t min_alloc_dsize,
                size_t max_size) {

        DnsPacket *p;
        size_t a;

        assert(ret);
        assert(max_size >= DNS_PACKET_HEADER_SIZE);

        if (max_size > DNS_PACKET_SIZE_MAX)
                max_size = DNS_PACKET_SIZE_MAX;

        /* The caller may not check what is going to be truly allocated, so do not allow to
         * allocate a DNS packet bigger than DNS_PACKET_SIZE_MAX.
         */
        if (min_alloc_dsize > DNS_PACKET_SIZE_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(EFBIG),
                                       "Requested packet data size too big: %zu",
                                       min_alloc_dsize);

        /* When dns_packet_new() is called with min_alloc_dsize == 0, allocate more than the
         * absolute minimum (which is the dns packet header size), to avoid
         * resizing immediately again after appending the first data to the packet.
         */
        if (min_alloc_dsize < DNS_PACKET_HEADER_SIZE)
                a = DNS_PACKET_SIZE_START;
        else
                a = min_alloc_dsize;

        /* round up to next page size */
        a = PAGE_ALIGN(ALIGN(sizeof(DnsPacket)) + a) - ALIGN(sizeof(DnsPacket));

        /* make sure we never allocate more than useful */
        if (a > max_size)
                a = max_size;

        p = malloc0(ALIGN(sizeof(DnsPacket)) + a);
        if (!p)
                return -ENOMEM;

        *p = (DnsPacket) {
                .n_ref = 1,
                .protocol = protocol,
                .size = DNS_PACKET_HEADER_SIZE,
                .rindex = DNS_PACKET_HEADER_SIZE,
                .allocated = a,
                .max_size = max_size,
                .opt_start = SIZE_MAX,
                .opt_size = SIZE_MAX,
        };

        *ret = p;

        return 0;
}

void dns_packet_set_flags(DnsPacket *p, bool dnssec_checking_disabled, bool truncated) {

        DnsPacketHeader *h;

        assert(p);

        h = DNS_PACKET_HEADER(p);

        switch (p->protocol) {
        case DNS_PROTOCOL_LLMNR:
                assert(!truncated);

                h->flags = htobe16(DNS_PACKET_MAKE_FLAGS(0 /* qr */,
                                                         0 /* opcode */,
                                                         0 /* c */,
                                                         0 /* tc */,
                                                         0 /* t */,
                                                         0 /* ra */,
                                                         0 /* ad */,
                                                         0 /* cd */,
                                                         0 /* rcode */));
                break;

        case DNS_PROTOCOL_MDNS:
                h->flags = htobe16(DNS_PACKET_MAKE_FLAGS(0         /* qr */,
                                                         0         /* opcode */,
                                                         0         /* aa */,
                                                         truncated /* tc */,
                                                         0         /* rd (ask for recursion) */,
                                                         0         /* ra */,
                                                         0         /* ad */,
                                                         0         /* cd */,
                                                         0         /* rcode */));
                break;

        default:
                assert(!truncated);

                h->flags = htobe16(DNS_PACKET_MAKE_FLAGS(0 /* qr */,
                                                         0 /* opcode */,
                                                         0 /* aa */,
                                                         0 /* tc */,
                                                         1 /* rd (ask for recursion) */,
                                                         0 /* ra */,
                                                         0 /* ad */,
                                                         dnssec_checking_disabled /* cd */,
                                                         0 /* rcode */));
        }
}

int dns_packet_new_query(DnsPacket **ret, DnsProtocol protocol, size_t min_alloc_dsize, bool dnssec_checking_disabled) {
        DnsPacket *p;
        int r;

        assert(ret);

        r = dns_packet_new(&p, protocol, min_alloc_dsize, DNS_PACKET_SIZE_MAX);
        if (r < 0)
                return r;

        /* Always set the TC bit to 0 initially.
         * If there are multiple packets later, we'll update the bit shortly before sending.
         */
        dns_packet_set_flags(p, dnssec_checking_disabled, false);

        *ret = p;
        return 0;
}

int dns_packet_dup(DnsPacket **ret, DnsPacket *p) {
        DnsPacket *c;
        int r;

        assert(ret);
        assert(p);

        r = dns_packet_validate(p);
        if (r < 0)
                return r;

        c = malloc(ALIGN(sizeof(DnsPacket)) + p->size);
        if (!c)
                return -ENOMEM;

        *c = (DnsPacket) {
                .n_ref = 1,
                .protocol = p->protocol,
                .size = p->size,
                .rindex = DNS_PACKET_HEADER_SIZE,
                .allocated = p->size,
                .max_size = p->max_size,
                .opt_start = SIZE_MAX,
                .opt_size = SIZE_MAX,
        };

        memcpy(DNS_PACKET_DATA(c), DNS_PACKET_DATA(p), p->size);

        *ret = c;
        return 0;
}

DnsPacket *dns_packet_ref(DnsPacket *p) {

        if (!p)
                return NULL;

        assert(!p->on_stack);

        assert(p->n_ref > 0);
        p->n_ref++;
        return p;
}

static void dns_packet_free(DnsPacket *p) {
        char *s;

        assert(p);

        dns_question_unref(p->question);
        dns_answer_unref(p->answer);
        dns_resource_record_unref(p->opt);

        while ((s = hashmap_steal_first_key(p->names)))
                free(s);
        hashmap_free(p->names);

        free(p->_data);

        if (!p->on_stack)
                free(p);
}

DnsPacket *dns_packet_unref(DnsPacket *p) {
        if (!p)
                return NULL;

        assert(p->n_ref > 0);

        dns_packet_unref(p->more);

        if (p->n_ref == 1)
                dns_packet_free(p);
        else
                p->n_ref--;

        return NULL;
}

int dns_packet_validate(DnsPacket *p) {
        assert(p);

        if (p->size < DNS_PACKET_HEADER_SIZE)
                return -EBADMSG;

        if (p->size > DNS_PACKET_SIZE_MAX)
                return -EBADMSG;

        return 1;
}

int dns_packet_validate_reply(DnsPacket *p) {
        int r;

        assert(p);

        r = dns_packet_validate(p);
        if (r < 0)
                return r;

        if (DNS_PACKET_QR(p) != 1)
                return 0;

        if (DNS_PACKET_OPCODE(p) != 0)
                return -EBADMSG;

        switch (p->protocol) {

        case DNS_PROTOCOL_LLMNR:
                /* RFC 4795, Section 2.1.1. says to discard all replies with QDCOUNT != 1 */
                if (DNS_PACKET_QDCOUNT(p) != 1)
                        return -EBADMSG;

                break;

        case DNS_PROTOCOL_MDNS:
                /* RFC 6762, Section 18 */
                if (DNS_PACKET_RCODE(p) != 0)
                        return -EBADMSG;

                break;

        default:
                break;
        }

        return 1;
}

int dns_packet_validate_query(DnsPacket *p) {
        int r;

        assert(p);

        r = dns_packet_validate(p);
        if (r < 0)
                return r;

        if (DNS_PACKET_QR(p) != 0)
                return 0;

        if (DNS_PACKET_OPCODE(p) != 0)
                return -EBADMSG;

        switch (p->protocol) {

        case DNS_PROTOCOL_LLMNR:
        case DNS_PROTOCOL_DNS:
                if (DNS_PACKET_TC(p)) /* mDNS query may have truncation flag. */
                        return -EBADMSG;

                /* RFC 4795, Section 2.1.1. says to discard all queries with QDCOUNT != 1 */
                if (DNS_PACKET_QDCOUNT(p) != 1)
                        return -EBADMSG;

                /* RFC 4795, Section 2.1.1. says to discard all queries with ANCOUNT != 0 */
                if (DNS_PACKET_ANCOUNT(p) > 0)
                        return -EBADMSG;

                /* RFC 4795, Section 2.1.1. says to discard all queries with NSCOUNT != 0 */
                if (DNS_PACKET_NSCOUNT(p) > 0)
                        return -EBADMSG;

                break;

        case DNS_PROTOCOL_MDNS:
                /* RFC 6762, Section 18 specifies that messages with non-zero RCODE
                 * must be silently ignored, and that we must ignore the values of
                 * AA, RD, RA, AD, and CD bits. */
                if (DNS_PACKET_RCODE(p) != 0)
                        return -EBADMSG;

                break;

        default:
                break;
        }

        return 1;
}

static int dns_packet_extend(DnsPacket *p, size_t add, void **ret, size_t *start) {
        assert(p);

        if (p->size + add > p->allocated) {
                size_t a, ms;

                a = PAGE_ALIGN((p->size + add) * 2);

                ms = dns_packet_size_max(p);
                if (a > ms)
                        a = ms;

                if (p->size + add > a)
                        return -EMSGSIZE;

                if (p->_data) {
                        void *d;

                        d = realloc(p->_data, a);
                        if (!d)
                                return -ENOMEM;

                        p->_data = d;
                } else {
                        p->_data = malloc(a);
                        if (!p->_data)
                                return -ENOMEM;

                        memcpy(p->_data, (uint8_t*) p + ALIGN(sizeof(DnsPacket)), p->size);
                        memzero((uint8_t*) p->_data + p->size, a - p->size);
                }

                p->allocated = a;
        }

        if (start)
                *start = p->size;

        if (ret)
                *ret = (uint8_t*) DNS_PACKET_DATA(p) + p->size;

        p->size += add;
        return 0;
}

void dns_packet_truncate(DnsPacket *p, size_t sz) {
        char *s;
        void *n;

        assert(p);

        if (p->size <= sz)
                return;

        HASHMAP_FOREACH_KEY(n, s, p->names) {

                if (PTR_TO_SIZE(n) < sz)
                        continue;

                hashmap_remove(p->names, s);
                free(s);
        }

        p->size = sz;
}

int dns_packet_append_blob(DnsPacket *p, const void *d, size_t l, size_t *start) {
        void *q;
        int r;

        assert(p);

        r = dns_packet_extend(p, l, &q, start);
        if (r < 0)
                return r;

        memcpy_safe(q, d, l);
        return 0;
}

int dns_packet_append_uint8(DnsPacket *p, uint8_t v, size_t *start) {
        void *d;
        int r;

        assert(p);

        r = dns_packet_extend(p, sizeof(uint8_t), &d, start);
        if (r < 0)
                return r;

        ((uint8_t*) d)[0] = v;

        return 0;
}

int dns_packet_append_uint16(DnsPacket *p, uint16_t v, size_t *start) {
        void *d;
        int r;

        assert(p);

        r = dns_packet_extend(p, sizeof(uint16_t), &d, start);
        if (r < 0)
                return r;

        unaligned_write_be16(d, v);

        return 0;
}

int dns_packet_append_uint32(DnsPacket *p, uint32_t v, size_t *start) {
        void *d;
        int r;

        assert(p);

        r = dns_packet_extend(p, sizeof(uint32_t), &d, start);
        if (r < 0)
                return r;

        unaligned_write_be32(d, v);

        return 0;
}

int dns_packet_append_string(DnsPacket *p, const char *s, size_t *start) {
        assert(p);
        assert(s);

        return dns_packet_append_raw_string(p, s, strlen(s), start);
}

int dns_packet_append_raw_string(DnsPacket *p, const void *s, size_t size, size_t *start) {
        void *d;
        int r;

        assert(p);
        assert(s || size == 0);

        if (size > 255)
                return -E2BIG;

        r = dns_packet_extend(p, 1 + size, &d, start);
        if (r < 0)
                return r;

        ((uint8_t*) d)[0] = (uint8_t) size;

        memcpy_safe(((uint8_t*) d) + 1, s, size);

        return 0;
}

int dns_packet_append_label(DnsPacket *p, const char *d, size_t l, bool canonical_candidate, size_t *start) {
        uint8_t *w;
        int r;

        /* Append a label to a packet. Optionally, does this in DNSSEC
         * canonical form, if this label is marked as a candidate for
         * it, and the canonical form logic is enabled for the
         * packet */

        assert(p);
        assert(d);

        if (l > DNS_LABEL_MAX)
                return -E2BIG;

        r = dns_packet_extend(p, 1 + l, (void**) &w, start);
        if (r < 0)
                return r;

        *(w++) = (uint8_t) l;

        if (p->canonical_form && canonical_candidate)
                /* Generate in canonical form, as defined by DNSSEC
                 * RFC 4034, Section 6.2, i.e. all lower-case. */
                for (size_t i = 0; i < l; i++)
                        w[i] = (uint8_t) ascii_tolower(d[i]);
        else
                /* Otherwise, just copy the string unaltered. This is
                 * essential for DNS-SD, where the casing of labels
                 * matters and needs to be retained. */
                memcpy(w, d, l);

        return 0;
}

int dns_packet_append_name(
                DnsPacket *p,
                const char *name,
                bool allow_compression,
                bool canonical_candidate,
                size_t *start) {

        size_t saved_size;
        int r;

        assert(p);
        assert(name);

        if (p->refuse_compression)
                allow_compression = false;

        saved_size = p->size;

        while (!dns_name_is_root(name)) {
                const char *z = name;
                char label[DNS_LABEL_MAX+1];
                size_t n = 0;

                if (allow_compression)
                        n = PTR_TO_SIZE(hashmap_get(p->names, name));
                if (n > 0) {
                        assert(n < p->size);

                        if (n < 0x4000) {
                                r = dns_packet_append_uint16(p, 0xC000 | n, NULL);
                                if (r < 0)
                                        goto fail;

                                goto done;
                        }
                }

                r = dns_label_unescape(&name, label, sizeof label, 0);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_label(p, label, r, canonical_candidate, &n);
                if (r < 0)
                        goto fail;

                if (allow_compression) {
                        _cleanup_free_ char *s = NULL;

                        s = strdup(z);
                        if (!s) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        r = hashmap_ensure_put(&p->names, &dns_name_hash_ops, s, SIZE_TO_PTR(n));
                        if (r < 0)
                                goto fail;

                        TAKE_PTR(s);
                }
        }

        r = dns_packet_append_uint8(p, 0, NULL);
        if (r < 0)
                return r;

done:
        if (start)
                *start = saved_size;

        return 0;

fail:
        dns_packet_truncate(p, saved_size);
        return r;
}

int dns_packet_append_key(DnsPacket *p, const DnsResourceKey *k, const DnsAnswerFlags flags, size_t *start) {
        size_t saved_size;
        uint16_t class;
        int r;

        assert(p);
        assert(k);

        saved_size = p->size;

        r = dns_packet_append_name(p, dns_resource_key_name(k), true, true, NULL);
        if (r < 0)
                goto fail;

        r = dns_packet_append_uint16(p, k->type, NULL);
        if (r < 0)
                goto fail;

        class = flags & DNS_ANSWER_CACHE_FLUSH ? k->class | MDNS_RR_CACHE_FLUSH_OR_QU : k->class;
        r = dns_packet_append_uint16(p, class, NULL);
        if (r < 0)
                goto fail;

        if (start)
                *start = saved_size;

        return 0;

fail:
        dns_packet_truncate(p, saved_size);
        return r;
}

static int dns_packet_append_type_window(DnsPacket *p, uint8_t window, uint8_t length, const uint8_t *types, size_t *start) {
        size_t saved_size;
        int r;

        assert(p);
        assert(types);
        assert(length > 0);

        saved_size = p->size;

        r = dns_packet_append_uint8(p, window, NULL);
        if (r < 0)
                goto fail;

        r = dns_packet_append_uint8(p, length, NULL);
        if (r < 0)
                goto fail;

        r = dns_packet_append_blob(p, types, length, NULL);
        if (r < 0)
                goto fail;

        if (start)
                *start = saved_size;

        return 0;
fail:
        dns_packet_truncate(p, saved_size);
        return r;
}

static int dns_packet_append_types(DnsPacket *p, Bitmap *types, size_t *start) {
        uint8_t window = 0;
        uint8_t entry = 0;
        uint8_t bitmaps[32] = {};
        unsigned n;
        size_t saved_size;
        int r;

        assert(p);

        saved_size = p->size;

        BITMAP_FOREACH(n, types) {
                assert(n <= 0xffff);

                if ((n >> 8) != window && bitmaps[entry / 8] != 0) {
                        r = dns_packet_append_type_window(p, window, entry / 8 + 1, bitmaps, NULL);
                        if (r < 0)
                                goto fail;

                        zero(bitmaps);
                }

                window = n >> 8;
                entry = n & 255;

                bitmaps[entry / 8] |= 1 << (7 - (entry % 8));
        }

        if (bitmaps[entry / 8] != 0) {
                r = dns_packet_append_type_window(p, window, entry / 8 + 1, bitmaps, NULL);
                if (r < 0)
                        goto fail;
        }

        if (start)
                *start = saved_size;

        return 0;
fail:
        dns_packet_truncate(p, saved_size);
        return r;
}

/* Append the OPT pseudo-RR described in RFC6891 */
int dns_packet_append_opt(
                DnsPacket *p,
                uint16_t max_udp_size,
                bool edns0_do,
                bool include_rfc6975,
                const char *nsid,
                int rcode,
                size_t *ret_start) {

        size_t saved_size;
        int r;

        assert(p);
        /* we must never advertise supported packet size smaller than the legacy max */
        assert(max_udp_size >= DNS_PACKET_UNICAST_SIZE_MAX);
        assert(rcode >= 0);
        assert(rcode <= _DNS_RCODE_MAX);

        if (p->opt_start != SIZE_MAX)
                return -EBUSY;

        assert(p->opt_size == SIZE_MAX);

        saved_size = p->size;

        /* empty name */
        r = dns_packet_append_uint8(p, 0, NULL);
        if (r < 0)
                return r;

        /* type */
        r = dns_packet_append_uint16(p, DNS_TYPE_OPT, NULL);
        if (r < 0)
                goto fail;

        /* class: maximum udp packet that can be received */
        r = dns_packet_append_uint16(p, max_udp_size, NULL);
        if (r < 0)
                goto fail;

        /* extended RCODE and VERSION */
        r = dns_packet_append_uint16(p, ((uint16_t) rcode & 0x0FF0) << 4, NULL);
        if (r < 0)
                goto fail;

        /* flags: DNSSEC OK (DO), see RFC3225 */
        r = dns_packet_append_uint16(p, edns0_do ? EDNS0_OPT_DO : 0, NULL);
        if (r < 0)
                goto fail;

        if (edns0_do && include_rfc6975) {
                /* If DO is on and this is requested, also append RFC6975 Algorithm data. This is supposed to
                 * be done on queries, not on replies, hencer callers should turn this off when finishing off
                 * replies. */

                static const uint8_t rfc6975[] = {

                        0, 5, /* OPTION_CODE: DAU */
#if PREFER_OPENSSL || (HAVE_GCRYPT && GCRYPT_VERSION_NUMBER >= 0x010600)
                        0, 7, /* LIST_LENGTH */
#else
                        0, 6, /* LIST_LENGTH */
#endif
                        DNSSEC_ALGORITHM_RSASHA1,
                        DNSSEC_ALGORITHM_RSASHA1_NSEC3_SHA1,
                        DNSSEC_ALGORITHM_RSASHA256,
                        DNSSEC_ALGORITHM_RSASHA512,
                        DNSSEC_ALGORITHM_ECDSAP256SHA256,
                        DNSSEC_ALGORITHM_ECDSAP384SHA384,
#if PREFER_OPENSSL || (HAVE_GCRYPT && GCRYPT_VERSION_NUMBER >= 0x010600)
                        DNSSEC_ALGORITHM_ED25519,
#endif

                        0, 6, /* OPTION_CODE: DHU */
                        0, 3, /* LIST_LENGTH */
                        DNSSEC_DIGEST_SHA1,
                        DNSSEC_DIGEST_SHA256,
                        DNSSEC_DIGEST_SHA384,

                        0, 7, /* OPTION_CODE: N3U */
                        0, 1, /* LIST_LENGTH */
                        NSEC3_ALGORITHM_SHA1,
                };

                r = dns_packet_append_uint16(p, sizeof(rfc6975), NULL); /* RDLENGTH */
                if (r < 0)
                        goto fail;

                r = dns_packet_append_blob(p, rfc6975, sizeof(rfc6975), NULL); /* the payload, as defined above */

        } else if (nsid) {

                if (strlen(nsid) > UINT16_MAX - 4) {
                        r = -E2BIG;
                        goto fail;
                }

                r = dns_packet_append_uint16(p, 4 + strlen(nsid), NULL); /* RDLENGTH */
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint16(p, 3, NULL); /* OPTION-CODE: NSID */
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint16(p, strlen(nsid), NULL); /* OPTION-LENGTH */
                if (r < 0)
                        goto fail;

                r = dns_packet_append_blob(p, nsid, strlen(nsid), NULL);
        } else
                r = dns_packet_append_uint16(p, 0, NULL);
        if (r < 0)
                goto fail;

        DNS_PACKET_HEADER(p)->arcount = htobe16(DNS_PACKET_ARCOUNT(p) + 1);

        p->opt_start = saved_size;
        p->opt_size = p->size - saved_size;

        if (ret_start)
                *ret_start = saved_size;

        return 0;

fail:
        dns_packet_truncate(p, saved_size);
        return r;
}

int dns_packet_truncate_opt(DnsPacket *p) {
        assert(p);

        if (p->opt_start == SIZE_MAX) {
                assert(p->opt_size == SIZE_MAX);
                return 0;
        }

        assert(p->opt_size != SIZE_MAX);
        assert(DNS_PACKET_ARCOUNT(p) > 0);

        if (p->opt_start + p->opt_size != p->size)
                return -EBUSY;

        dns_packet_truncate(p, p->opt_start);
        DNS_PACKET_HEADER(p)->arcount = htobe16(DNS_PACKET_ARCOUNT(p) - 1);
        p->opt_start = p->opt_size = SIZE_MAX;

        return 1;
}

int dns_packet_append_rr(DnsPacket *p, const DnsResourceRecord *rr, const DnsAnswerFlags flags, size_t *start, size_t *rdata_start) {

        size_t saved_size, rdlength_offset, end, rdlength, rds;
        uint32_t ttl;
        int r;

        assert(p);
        assert(rr);

        saved_size = p->size;

        r = dns_packet_append_key(p, rr->key, flags, NULL);
        if (r < 0)
                goto fail;

        ttl = flags & DNS_ANSWER_GOODBYE ? 0 : rr->ttl;
        r = dns_packet_append_uint32(p, ttl, NULL);
        if (r < 0)
                goto fail;

        /* Initially we write 0 here */
        r = dns_packet_append_uint16(p, 0, &rdlength_offset);
        if (r < 0)
                goto fail;

        rds = p->size - saved_size;

        switch (rr->unparsable ? _DNS_TYPE_INVALID : rr->key->type) {

        case DNS_TYPE_SRV:
                r = dns_packet_append_uint16(p, rr->srv.priority, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint16(p, rr->srv.weight, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint16(p, rr->srv.port, NULL);
                if (r < 0)
                        goto fail;

                /* RFC 2782 states "Unless and until permitted by future standards action, name compression
                 * is not to be used for this field." Hence we turn off compression here. */
                r = dns_packet_append_name(p, rr->srv.name, /* allow_compression= */ false, /* canonical_candidate= */ true, NULL);
                break;

        case DNS_TYPE_PTR:
        case DNS_TYPE_NS:
        case DNS_TYPE_CNAME:
        case DNS_TYPE_DNAME:
                r = dns_packet_append_name(p, rr->ptr.name, true, true, NULL);
                break;

        case DNS_TYPE_HINFO:
                r = dns_packet_append_string(p, rr->hinfo.cpu, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_string(p, rr->hinfo.os, NULL);
                break;

        case DNS_TYPE_SPF: /* exactly the same as TXT */
        case DNS_TYPE_TXT:

                if (!rr->txt.items) {
                        /* RFC 6763, section 6.1 suggests to generate
                         * single empty string for an empty array. */

                        r = dns_packet_append_raw_string(p, NULL, 0, NULL);
                        if (r < 0)
                                goto fail;
                } else
                        LIST_FOREACH(items, i, rr->txt.items) {
                                r = dns_packet_append_raw_string(p, i->data, i->length, NULL);
                                if (r < 0)
                                        goto fail;
                        }

                r = 0;
                break;

        case DNS_TYPE_A:
                r = dns_packet_append_blob(p, &rr->a.in_addr, sizeof(struct in_addr), NULL);
                break;

        case DNS_TYPE_AAAA:
                r = dns_packet_append_blob(p, &rr->aaaa.in6_addr, sizeof(struct in6_addr), NULL);
                break;

        case DNS_TYPE_SOA:
                r = dns_packet_append_name(p, rr->soa.mname, true, true, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_name(p, rr->soa.rname, true, true, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint32(p, rr->soa.serial, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint32(p, rr->soa.refresh, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint32(p, rr->soa.retry, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint32(p, rr->soa.expire, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint32(p, rr->soa.minimum, NULL);
                break;

        case DNS_TYPE_MX:
                r = dns_packet_append_uint16(p, rr->mx.priority, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_name(p, rr->mx.exchange, true, true, NULL);
                break;

        case DNS_TYPE_LOC:
                r = dns_packet_append_uint8(p, rr->loc.version, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint8(p, rr->loc.size, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint8(p, rr->loc.horiz_pre, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint8(p, rr->loc.vert_pre, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint32(p, rr->loc.latitude, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint32(p, rr->loc.longitude, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint32(p, rr->loc.altitude, NULL);
                break;

        case DNS_TYPE_DS:
                r = dns_packet_append_uint16(p, rr->ds.key_tag, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint8(p, rr->ds.algorithm, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint8(p, rr->ds.digest_type, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_blob(p, rr->ds.digest, rr->ds.digest_size, NULL);
                break;

        case DNS_TYPE_SSHFP:
                r = dns_packet_append_uint8(p, rr->sshfp.algorithm, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint8(p, rr->sshfp.fptype, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_blob(p, rr->sshfp.fingerprint, rr->sshfp.fingerprint_size, NULL);
                break;

        case DNS_TYPE_DNSKEY:
                r = dns_packet_append_uint16(p, rr->dnskey.flags, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint8(p, rr->dnskey.protocol, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint8(p, rr->dnskey.algorithm, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_blob(p, rr->dnskey.key, rr->dnskey.key_size, NULL);
                break;

        case DNS_TYPE_RRSIG:
                r = dns_packet_append_uint16(p, rr->rrsig.type_covered, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint8(p, rr->rrsig.algorithm, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint8(p, rr->rrsig.labels, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint32(p, rr->rrsig.original_ttl, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint32(p, rr->rrsig.expiration, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint32(p, rr->rrsig.inception, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint16(p, rr->rrsig.key_tag, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_name(p, rr->rrsig.signer, false, true, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_blob(p, rr->rrsig.signature, rr->rrsig.signature_size, NULL);
                break;

        case DNS_TYPE_NSEC:
                r = dns_packet_append_name(p, rr->nsec.next_domain_name, false, false, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_types(p, rr->nsec.types, NULL);
                if (r < 0)
                        goto fail;

                break;

        case DNS_TYPE_NSEC3:
                r = dns_packet_append_uint8(p, rr->nsec3.algorithm, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint8(p, rr->nsec3.flags, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint16(p, rr->nsec3.iterations, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint8(p, rr->nsec3.salt_size, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_blob(p, rr->nsec3.salt, rr->nsec3.salt_size, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint8(p, rr->nsec3.next_hashed_name_size, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_blob(p, rr->nsec3.next_hashed_name, rr->nsec3.next_hashed_name_size, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_types(p, rr->nsec3.types, NULL);
                if (r < 0)
                        goto fail;

                break;

        case DNS_TYPE_TLSA:
                r = dns_packet_append_uint8(p, rr->tlsa.cert_usage, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint8(p, rr->tlsa.selector, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint8(p, rr->tlsa.matching_type, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_blob(p, rr->tlsa.data, rr->tlsa.data_size, NULL);
                break;

        case DNS_TYPE_CAA:
                r = dns_packet_append_uint8(p, rr->caa.flags, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_string(p, rr->caa.tag, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_blob(p, rr->caa.value, rr->caa.value_size, NULL);
                break;

        case DNS_TYPE_OPT:
        case DNS_TYPE_OPENPGPKEY:
        case _DNS_TYPE_INVALID: /* unparsable */
        default:

                r = dns_packet_append_blob(p, rr->generic.data, rr->generic.data_size, NULL);
                break;
        }
        if (r < 0)
                goto fail;

        /* Let's calculate the actual data size and update the field */
        rdlength = p->size - rdlength_offset - sizeof(uint16_t);
        if (rdlength > 0xFFFF) {
                r = -ENOSPC;
                goto fail;
        }

        end = p->size;
        p->size = rdlength_offset;
        r = dns_packet_append_uint16(p, rdlength, NULL);
        if (r < 0)
                goto fail;
        p->size = end;

        if (start)
                *start = saved_size;

        if (rdata_start)
                *rdata_start = rds;

        return 0;

fail:
        dns_packet_truncate(p, saved_size);
        return r;
}

int dns_packet_append_question(DnsPacket *p, DnsQuestion *q) {
        DnsResourceKey *key;
        int r;

        assert(p);

        DNS_QUESTION_FOREACH(key, q) {
                r = dns_packet_append_key(p, key, 0, NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

int dns_packet_append_answer(DnsPacket *p, DnsAnswer *a, unsigned *completed) {
        DnsResourceRecord *rr;
        DnsAnswerFlags flags;
        int r;

        assert(p);

        DNS_ANSWER_FOREACH_FLAGS(rr, flags, a) {
                r = dns_packet_append_rr(p, rr, flags, NULL, NULL);
                if (r < 0)
                        return r;

                if (completed)
                        (*completed)++;
        }

        return 0;
}

int dns_packet_read(DnsPacket *p, size_t sz, const void **ret, size_t *start) {
        assert(p);
        assert(p->rindex <= p->size);

        if (sz > p->size - p->rindex)
                return -EMSGSIZE;

        if (ret)
                *ret = (uint8_t*) DNS_PACKET_DATA(p) + p->rindex;

        if (start)
                *start = p->rindex;

        p->rindex += sz;
        return 0;
}

void dns_packet_rewind(DnsPacket *p, size_t idx) {
        assert(p);
        assert(idx <= p->size);
        assert(idx >= DNS_PACKET_HEADER_SIZE);

        p->rindex = idx;
}

int dns_packet_read_blob(DnsPacket *p, void *d, size_t sz, size_t *start) {
        const void *q;
        int r;

        assert(p);
        assert(d);

        r = dns_packet_read(p, sz, &q, start);
        if (r < 0)
                return r;

        memcpy(d, q, sz);
        return 0;
}

static int dns_packet_read_memdup(
                DnsPacket *p, size_t size,
                void **ret, size_t *ret_size,
                size_t *ret_start) {

        const void *src;
        size_t start;
        int r;

        assert(p);
        assert(ret);

        r = dns_packet_read(p, size, &src, &start);
        if (r < 0)
                return r;

        if (size <= 0)
                *ret = NULL;
        else {
                void *copy;

                copy = memdup(src, size);
                if (!copy)
                        return -ENOMEM;

                *ret = copy;
        }

        if (ret_size)
                *ret_size = size;
        if (ret_start)
                *ret_start = start;

        return 0;
}

int dns_packet_read_uint8(DnsPacket *p, uint8_t *ret, size_t *start) {
        const void *d;
        int r;

        assert(p);

        r = dns_packet_read(p, sizeof(uint8_t), &d, start);
        if (r < 0)
                return r;

        *ret = ((uint8_t*) d)[0];
        return 0;
}

int dns_packet_read_uint16(DnsPacket *p, uint16_t *ret, size_t *start) {
        const void *d;
        int r;

        assert(p);

        r = dns_packet_read(p, sizeof(uint16_t), &d, start);
        if (r < 0)
                return r;

        if (ret)
                *ret = unaligned_read_be16(d);

        return 0;
}

int dns_packet_read_uint32(DnsPacket *p, uint32_t *ret, size_t *start) {
        const void *d;
        int r;

        assert(p);

        r = dns_packet_read(p, sizeof(uint32_t), &d, start);
        if (r < 0)
                return r;

        *ret = unaligned_read_be32(d);

        return 0;
}

int dns_packet_read_string(DnsPacket *p, char **ret, size_t *start) {
        _cleanup_(rewind_dns_packet) DnsPacketRewinder rewinder = REWINDER_INIT(p);
        _cleanup_free_ char *t = NULL;
        const void *d;
        uint8_t c;
        int r;

        assert(p);

        r = dns_packet_read_uint8(p, &c, NULL);
        if (r < 0)
                return r;

        r = dns_packet_read(p, c, &d, NULL);
        if (r < 0)
                return r;

        r = make_cstring(d, c, MAKE_CSTRING_REFUSE_TRAILING_NUL, &t);
        if (r < 0)
                return r;

        if (!utf8_is_valid(t))
                return -EBADMSG;

        *ret = TAKE_PTR(t);

        if (start)
                *start = rewinder.saved_rindex;
        CANCEL_REWINDER(rewinder);

        return 0;
}

int dns_packet_read_raw_string(DnsPacket *p, const void **ret, size_t *size, size_t *start) {
        assert(p);

        _cleanup_(rewind_dns_packet) DnsPacketRewinder rewinder = REWINDER_INIT(p);
        uint8_t c;
        int r;

        r = dns_packet_read_uint8(p, &c, NULL);
        if (r < 0)
                return r;

        r = dns_packet_read(p, c, ret, NULL);
        if (r < 0)
                return r;

        if (size)
                *size = c;
        if (start)
                *start = rewinder.saved_rindex;
        CANCEL_REWINDER(rewinder);

        return 0;
}

int dns_packet_read_name(
                DnsPacket *p,
                char **ret,
                bool allow_compression,
                size_t *ret_start) {

        assert(p);

        _cleanup_(rewind_dns_packet) DnsPacketRewinder rewinder = REWINDER_INIT(p);
        size_t after_rindex = 0, jump_barrier = p->rindex;
        _cleanup_free_ char *name = NULL;
        bool first = true;
        size_t n = 0;
        int r;

        if (p->refuse_compression)
                allow_compression = false;

        for (;;) {
                uint8_t c, d;

                r = dns_packet_read_uint8(p, &c, NULL);
                if (r < 0)
                        return r;

                if (c == 0)
                        /* End of name */
                        break;
                else if (c <= 63) {
                        const char *label;

                        /* Literal label */
                        r = dns_packet_read(p, c, (const void**) &label, NULL);
                        if (r < 0)
                                return r;

                        if (!GREEDY_REALLOC(name, n + !first + DNS_LABEL_ESCAPED_MAX))
                                return -ENOMEM;

                        if (first)
                                first = false;
                        else
                                name[n++] = '.';

                        r = dns_label_escape(label, c, name + n, DNS_LABEL_ESCAPED_MAX);
                        if (r < 0)
                                return r;

                        n += r;
                        continue;
                } else if (allow_compression && FLAGS_SET(c, 0xc0)) {
                        uint16_t ptr;

                        /* Pointer */
                        r = dns_packet_read_uint8(p, &d, NULL);
                        if (r < 0)
                                return r;

                        ptr = (uint16_t) (c & ~0xc0) << 8 | (uint16_t) d;
                        if (ptr < DNS_PACKET_HEADER_SIZE || ptr >= jump_barrier)
                                return -EBADMSG;

                        if (after_rindex == 0)
                                after_rindex = p->rindex;

                        /* Jumps are limited to a "prior occurrence" (RFC-1035 4.1.4) */
                        jump_barrier = ptr;
                        p->rindex = ptr;
                } else
                        return -EBADMSG;
        }

        if (!GREEDY_REALLOC(name, n + 1))
                return -ENOMEM;

        name[n] = 0;

        if (after_rindex != 0)
                p->rindex= after_rindex;

        if (ret)
                *ret = TAKE_PTR(name);
        if (ret_start)
                *ret_start = rewinder.saved_rindex;

        CANCEL_REWINDER(rewinder);

        return 0;
}

static int dns_packet_read_type_window(DnsPacket *p, Bitmap **types, size_t *start) {
        assert(p);
        assert(types);

        _cleanup_(rewind_dns_packet) DnsPacketRewinder rewinder = REWINDER_INIT(p);
        uint8_t window, length;
        const uint8_t *bitmap;
        uint8_t bit = 0;
        bool found = false;
        int r;

        r = bitmap_ensure_allocated(types);
        if (r < 0)
                return r;

        r = dns_packet_read_uint8(p, &window, NULL);
        if (r < 0)
                return r;

        r = dns_packet_read_uint8(p, &length, NULL);
        if (r < 0)
                return r;

        if (length == 0 || length > 32)
                return -EBADMSG;

        r = dns_packet_read(p, length, (const void **)&bitmap, NULL);
        if (r < 0)
                return r;

        for (uint8_t i = 0; i < length; i++) {
                uint8_t bitmask = 1 << 7;

                if (!bitmap[i]) {
                        found = false;
                        bit += 8;
                        continue;
                }

                found = true;

                for (; bitmask; bit++, bitmask >>= 1)
                        if (bitmap[i] & bitmask) {
                                uint16_t n;

                                n = (uint16_t) window << 8 | (uint16_t) bit;

                                /* Ignore pseudo-types. see RFC4034 section 4.1.2 */
                                if (dns_type_is_pseudo(n))
                                        continue;

                                r = bitmap_set(*types, n);
                                if (r < 0)
                                        return r;
                        }
        }

        if (!found)
                return -EBADMSG;

        if (start)
                *start = rewinder.saved_rindex;
        CANCEL_REWINDER(rewinder);

        return 0;
}

static int dns_packet_read_type_windows(DnsPacket *p, Bitmap **types, size_t size, size_t *start) {
        _cleanup_(rewind_dns_packet) DnsPacketRewinder rewinder = REWINDER_INIT(p);
        int r;

        while (p->rindex - rewinder.saved_rindex < size) {
                r = dns_packet_read_type_window(p, types, NULL);
                if (r < 0)
                        return r;

                assert(p->rindex >= rewinder.saved_rindex);

                /* don't read past end of current RR */
                if (p->rindex - rewinder.saved_rindex > size)
                        return -EBADMSG;
        }

        if (p->rindex - rewinder.saved_rindex != size)
                return -EBADMSG;

        if (start)
                *start = rewinder.saved_rindex;
        CANCEL_REWINDER(rewinder);

        return 0;
}

int dns_packet_read_key(
                DnsPacket *p,
                DnsResourceKey **ret,
                bool *ret_cache_flush_or_qu,
                size_t *ret_start) {

        assert(p);

        _cleanup_(rewind_dns_packet) DnsPacketRewinder rewinder = REWINDER_INIT(p);
        _cleanup_free_ char *name = NULL;
        bool cache_flush_or_qu = false;
        uint16_t class, type;
        int r;

        r = dns_packet_read_name(p, &name, true, NULL);
        if (r < 0)
                return r;

        r = dns_packet_read_uint16(p, &type, NULL);
        if (r < 0)
                return r;

        r = dns_packet_read_uint16(p, &class, NULL);
        if (r < 0)
                return r;

        if (p->protocol == DNS_PROTOCOL_MDNS) {
                /* See RFC6762, sections 5.4 and 10.2 */

                if (type != DNS_TYPE_OPT && (class & MDNS_RR_CACHE_FLUSH_OR_QU)) {
                        class &= ~MDNS_RR_CACHE_FLUSH_OR_QU;
                        cache_flush_or_qu = true;
                }
        }

        if (ret) {
                DnsResourceKey *key;

                key = dns_resource_key_new_consume(class, type, name);
                if (!key)
                        return -ENOMEM;

                TAKE_PTR(name);
                *ret = key;
        }

        if (ret_cache_flush_or_qu)
                *ret_cache_flush_or_qu = cache_flush_or_qu;
        if (ret_start)
                *ret_start = rewinder.saved_rindex;

        CANCEL_REWINDER(rewinder);
        return 0;
}

static bool loc_size_ok(uint8_t size) {
        uint8_t m = size >> 4, e = size & 0xF;

        return m <= 9 && e <= 9 && (m > 0 || e == 0);
}

int dns_packet_read_rr(
                DnsPacket *p,
                DnsResourceRecord **ret,
                bool *ret_cache_flush,
                size_t *ret_start) {

        assert(p);

        _cleanup_(rewind_dns_packet) DnsPacketRewinder rewinder = REWINDER_INIT(p);
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        size_t offset;
        uint16_t rdlength;
        bool cache_flush;
        int r;

        r = dns_packet_read_key(p, &key, &cache_flush, NULL);
        if (r < 0)
                return r;

        if (!dns_class_is_valid_rr(key->class) || !dns_type_is_valid_rr(key->type))
                return -EBADMSG;

        rr = dns_resource_record_new(key);
        if (!rr)
                return -ENOMEM;

        r = dns_packet_read_uint32(p, &rr->ttl, NULL);
        if (r < 0)
                return r;

        /* RFC 2181, Section 8, suggests to
         * treat a TTL with the MSB set as a zero TTL. */
        if (rr->ttl & UINT32_C(0x80000000))
                rr->ttl = 0;

        r = dns_packet_read_uint16(p, &rdlength, NULL);
        if (r < 0)
                return r;

        if (rdlength > p->size - p->rindex)
                return -EBADMSG;

        offset = p->rindex;

        switch (rr->key->type) {

        case DNS_TYPE_SRV:
                r = dns_packet_read_uint16(p, &rr->srv.priority, NULL);
                if (r < 0)
                        return r;
                r = dns_packet_read_uint16(p, &rr->srv.weight, NULL);
                if (r < 0)
                        return r;
                r = dns_packet_read_uint16(p, &rr->srv.port, NULL);
                if (r < 0)
                        return r;

                /* RFC 2782 states "Unless and until permitted by future standards action, name compression
                 * is not to be used for this field." Nonetheless, we support it here, in the interest of
                 * increasing compatibility with implementations that do not implement this correctly. After
                 * all we didn't do this right once upon a time ourselves (see
                 * https://github.com/systemd/systemd/issues/9793). */
                r = dns_packet_read_name(p, &rr->srv.name, /* allow_compression= */ true, NULL);
                break;

        case DNS_TYPE_PTR:
        case DNS_TYPE_NS:
        case DNS_TYPE_CNAME:
        case DNS_TYPE_DNAME:
                r = dns_packet_read_name(p, &rr->ptr.name, true, NULL);
                break;

        case DNS_TYPE_HINFO:
                r = dns_packet_read_string(p, &rr->hinfo.cpu, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_string(p, &rr->hinfo.os, NULL);
                break;

        case DNS_TYPE_SPF: /* exactly the same as TXT */
        case DNS_TYPE_TXT:
                if (rdlength <= 0) {
                        r = dns_txt_item_new_empty(&rr->txt.items);
                        if (r < 0)
                                return r;
                } else {
                        DnsTxtItem *last = NULL;

                        while (p->rindex - offset < rdlength) {
                                DnsTxtItem *i;
                                const void *data;
                                size_t sz;

                                r = dns_packet_read_raw_string(p, &data, &sz, NULL);
                                if (r < 0)
                                        return r;

                                i = malloc0(offsetof(DnsTxtItem, data) + sz + 1); /* extra NUL byte at the end */
                                if (!i)
                                        return -ENOMEM;

                                memcpy(i->data, data, sz);
                                i->length = sz;

                                LIST_INSERT_AFTER(items, rr->txt.items, last, i);
                                last = i;
                        }
                }

                r = 0;
                break;

        case DNS_TYPE_A:
                r = dns_packet_read_blob(p, &rr->a.in_addr, sizeof(struct in_addr), NULL);
                break;

        case DNS_TYPE_AAAA:
                r = dns_packet_read_blob(p, &rr->aaaa.in6_addr, sizeof(struct in6_addr), NULL);
                break;

        case DNS_TYPE_SOA:
                r = dns_packet_read_name(p, &rr->soa.mname, true, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_name(p, &rr->soa.rname, true, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_uint32(p, &rr->soa.serial, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_uint32(p, &rr->soa.refresh, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_uint32(p, &rr->soa.retry, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_uint32(p, &rr->soa.expire, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_uint32(p, &rr->soa.minimum, NULL);
                break;

        case DNS_TYPE_MX:
                r = dns_packet_read_uint16(p, &rr->mx.priority, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_name(p, &rr->mx.exchange, true, NULL);
                break;

        case DNS_TYPE_LOC: {
                uint8_t t;
                size_t pos;

                r = dns_packet_read_uint8(p, &t, &pos);
                if (r < 0)
                        return r;

                if (t == 0) {
                        rr->loc.version = t;

                        r = dns_packet_read_uint8(p, &rr->loc.size, NULL);
                        if (r < 0)
                                return r;

                        if (!loc_size_ok(rr->loc.size))
                                return -EBADMSG;

                        r = dns_packet_read_uint8(p, &rr->loc.horiz_pre, NULL);
                        if (r < 0)
                                return r;

                        if (!loc_size_ok(rr->loc.horiz_pre))
                                return -EBADMSG;

                        r = dns_packet_read_uint8(p, &rr->loc.vert_pre, NULL);
                        if (r < 0)
                                return r;

                        if (!loc_size_ok(rr->loc.vert_pre))
                                return -EBADMSG;

                        r = dns_packet_read_uint32(p, &rr->loc.latitude, NULL);
                        if (r < 0)
                                return r;

                        r = dns_packet_read_uint32(p, &rr->loc.longitude, NULL);
                        if (r < 0)
                                return r;

                        r = dns_packet_read_uint32(p, &rr->loc.altitude, NULL);
                        if (r < 0)
                                return r;

                        break;
                } else {
                        dns_packet_rewind(p, pos);
                        rr->unparsable = true;
                        goto unparsable;
                }
        }

        case DNS_TYPE_DS:
                r = dns_packet_read_uint16(p, &rr->ds.key_tag, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_uint8(p, &rr->ds.algorithm, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_uint8(p, &rr->ds.digest_type, NULL);
                if (r < 0)
                        return r;

                if (rdlength < 4)
                        return -EBADMSG;

                r = dns_packet_read_memdup(p, rdlength - 4,
                                           &rr->ds.digest, &rr->ds.digest_size,
                                           NULL);
                if (r < 0)
                        return r;

                if (rr->ds.digest_size <= 0)
                        /* the accepted size depends on the algorithm, but for now
                           just ensure that the value is greater than zero */
                        return -EBADMSG;

                break;

        case DNS_TYPE_SSHFP:
                r = dns_packet_read_uint8(p, &rr->sshfp.algorithm, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_uint8(p, &rr->sshfp.fptype, NULL);
                if (r < 0)
                        return r;

                if (rdlength < 2)
                        return -EBADMSG;

                r = dns_packet_read_memdup(p, rdlength - 2,
                                           &rr->sshfp.fingerprint, &rr->sshfp.fingerprint_size,
                                           NULL);

                if (rr->sshfp.fingerprint_size <= 0)
                        /* the accepted size depends on the algorithm, but for now
                           just ensure that the value is greater than zero */
                        return -EBADMSG;

                break;

        case DNS_TYPE_DNSKEY:
                r = dns_packet_read_uint16(p, &rr->dnskey.flags, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_uint8(p, &rr->dnskey.protocol, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_uint8(p, &rr->dnskey.algorithm, NULL);
                if (r < 0)
                        return r;

                if (rdlength < 4)
                        return -EBADMSG;

                r = dns_packet_read_memdup(p, rdlength - 4,
                                           &rr->dnskey.key, &rr->dnskey.key_size,
                                           NULL);

                if (rr->dnskey.key_size <= 0)
                        /* the accepted size depends on the algorithm, but for now
                           just ensure that the value is greater than zero */
                        return -EBADMSG;

                break;

        case DNS_TYPE_RRSIG:
                r = dns_packet_read_uint16(p, &rr->rrsig.type_covered, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_uint8(p, &rr->rrsig.algorithm, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_uint8(p, &rr->rrsig.labels, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_uint32(p, &rr->rrsig.original_ttl, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_uint32(p, &rr->rrsig.expiration, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_uint32(p, &rr->rrsig.inception, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_uint16(p, &rr->rrsig.key_tag, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_name(p, &rr->rrsig.signer, false, NULL);
                if (r < 0)
                        return r;

                if (rdlength < p->rindex - offset)
                        return -EBADMSG;

                r = dns_packet_read_memdup(p, offset + rdlength - p->rindex,
                                           &rr->rrsig.signature, &rr->rrsig.signature_size,
                                           NULL);

                if (rr->rrsig.signature_size <= 0)
                        /* the accepted size depends on the algorithm, but for now
                           just ensure that the value is greater than zero */
                        return -EBADMSG;

                break;

        case DNS_TYPE_NSEC: {

                /*
                 * RFC6762, section 18.14 explicitly states mDNS should use name compression.
                 * This contradicts RFC3845, section 2.1.1
                 */

                bool allow_compressed = p->protocol == DNS_PROTOCOL_MDNS;

                r = dns_packet_read_name(p, &rr->nsec.next_domain_name, allow_compressed, NULL);
                if (r < 0)
                        return r;

                if (rdlength < p->rindex - offset)
                        return -EBADMSG;

                r = dns_packet_read_type_windows(p, &rr->nsec.types, offset + rdlength - p->rindex, NULL);

                /* We accept empty NSEC bitmaps. The bit indicating the presence of the NSEC record itself
                 * is redundant and in e.g., RFC4956 this fact is used to define a use for NSEC records
                 * without the NSEC bit set. */

                break;
        }
        case DNS_TYPE_NSEC3: {
                uint8_t size;

                r = dns_packet_read_uint8(p, &rr->nsec3.algorithm, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_uint8(p, &rr->nsec3.flags, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_uint16(p, &rr->nsec3.iterations, NULL);
                if (r < 0)
                        return r;

                /* this may be zero */
                r = dns_packet_read_uint8(p, &size, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_memdup(p, size, &rr->nsec3.salt, &rr->nsec3.salt_size, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_uint8(p, &size, NULL);
                if (r < 0)
                        return r;

                if (size <= 0)
                        return -EBADMSG;

                r = dns_packet_read_memdup(p, size,
                                           &rr->nsec3.next_hashed_name, &rr->nsec3.next_hashed_name_size,
                                           NULL);
                if (r < 0)
                        return r;

                if (rdlength < p->rindex - offset)
                        return -EBADMSG;

                r = dns_packet_read_type_windows(p, &rr->nsec3.types, offset + rdlength - p->rindex, NULL);

                /* empty non-terminals can have NSEC3 records, so empty bitmaps are allowed */

                break;
        }

        case DNS_TYPE_TLSA:
                r = dns_packet_read_uint8(p, &rr->tlsa.cert_usage, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_uint8(p, &rr->tlsa.selector, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_uint8(p, &rr->tlsa.matching_type, NULL);
                if (r < 0)
                        return r;

                if (rdlength < 3)
                        return -EBADMSG;

                r = dns_packet_read_memdup(p, rdlength - 3,
                                           &rr->tlsa.data, &rr->tlsa.data_size,
                                           NULL);

                if (rr->tlsa.data_size <= 0)
                        /* the accepted size depends on the algorithm, but for now
                           just ensure that the value is greater than zero */
                        return -EBADMSG;

                break;

        case DNS_TYPE_CAA:
                r = dns_packet_read_uint8(p, &rr->caa.flags, NULL);
                if (r < 0)
                        return r;

                r = dns_packet_read_string(p, &rr->caa.tag, NULL);
                if (r < 0)
                        return r;

                if (rdlength < p->rindex - offset)
                        return -EBADMSG;

                r = dns_packet_read_memdup(p,
                                           rdlength + offset - p->rindex,
                                           &rr->caa.value, &rr->caa.value_size, NULL);

                break;

        case DNS_TYPE_OPT: /* we only care about the header of OPT for now. */
        case DNS_TYPE_OPENPGPKEY:
        default:
        unparsable:
                r = dns_packet_read_memdup(p, rdlength, &rr->generic.data, &rr->generic.data_size, NULL);

                break;
        }
        if (r < 0)
                return r;
        if (p->rindex - offset != rdlength)
                return -EBADMSG;

        if (ret)
                *ret = TAKE_PTR(rr);
        if (ret_cache_flush)
                *ret_cache_flush = cache_flush;
        if (ret_start)
                *ret_start = rewinder.saved_rindex;

        CANCEL_REWINDER(rewinder);
        return 0;
}

static bool opt_is_good(DnsResourceRecord *rr, bool *rfc6975) {
        const uint8_t* p;
        bool found_dau_dhu_n3u = false;
        size_t l;

        /* Checks whether the specified OPT RR is well-formed and whether it contains RFC6975 data (which is not OK in
         * a reply). */

        assert(rr);
        assert(rr->key->type == DNS_TYPE_OPT);

        /* Check that the version is 0 */
        if (((rr->ttl >> 16) & UINT32_C(0xFF)) != 0) {
                *rfc6975 = false;
                return true; /* if it's not version 0, it's OK, but we will ignore the OPT field contents */
        }

        p = rr->opt.data;
        l = rr->opt.data_size;
        while (l > 0) {
                uint16_t option_code, option_length;

                /* At least four bytes for OPTION-CODE and OPTION-LENGTH are required */
                if (l < 4U)
                        return false;

                option_code = unaligned_read_be16(p);
                option_length = unaligned_read_be16(p + 2);

                if (l < option_length + 4U)
                        return false;

                /* RFC 6975 DAU, DHU or N3U fields found. */
                if (IN_SET(option_code, 5, 6, 7))
                        found_dau_dhu_n3u = true;

                p += option_length + 4U;
                l -= option_length + 4U;
        }

        *rfc6975 = found_dau_dhu_n3u;
        return true;
}

static int dns_packet_extract_question(DnsPacket *p, DnsQuestion **ret_question) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        unsigned n;
        int r;

        n = DNS_PACKET_QDCOUNT(p);
        if (n > 0) {
                question = dns_question_new(n);
                if (!question)
                        return -ENOMEM;

                _cleanup_set_free_ Set *keys = NULL; /* references to keys are kept by Question */

                keys = set_new(&dns_resource_key_hash_ops);
                if (!keys)
                        return log_oom();

                r = set_reserve(keys, n * 2); /* Higher multipliers give slightly higher efficiency through
                                               * hash collisions, but the gains quickly drop off after 2. */
                if (r < 0)
                        return r;

                for (unsigned i = 0; i < n; i++) {
                        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
                        bool qu;

                        r = dns_packet_read_key(p, &key, &qu, NULL);
                        if (r < 0)
                                return r;

                        if (!dns_type_is_valid_query(key->type))
                                return -EBADMSG;

                        r = set_put(keys, key);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                /* Already in the Question, let's skip */
                                continue;

                        r = dns_question_add_raw(question, key, qu ? DNS_QUESTION_WANTS_UNICAST_REPLY : 0);
                        if (r < 0)
                                return r;
                }
        }

        *ret_question = TAKE_PTR(question);

        return 0;
}

static int dns_packet_extract_answer(DnsPacket *p, DnsAnswer **ret_answer) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        unsigned n;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *previous = NULL;
        bool bad_opt = false;
        int r;

        n = DNS_PACKET_RRCOUNT(p);
        if (n == 0)
                return 0;

        answer = dns_answer_new(n);
        if (!answer)
                return -ENOMEM;

        for (unsigned i = 0; i < n; i++) {
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
                bool cache_flush = false;
                size_t start;

                if (p->rindex == p->size && p->opt) {
                        /* If we reached the end of the packet already, but there are still more RRs
                         * declared, then that's a corrupt packet. Let's accept the packet anyway, since it's
                         * apparently a common bug in routers. Let's however suppress OPT support in this
                         * case, so that we force the rest of the logic into lowest DNS baseline support. Or
                         * to say this differently: if the DNS server doesn't even get the RR counts right,
                         * it's highly unlikely it gets EDNS right. */
                        log_debug("More resource records declared in packet than included, suppressing OPT.");
                        bad_opt = true;
                        break;
                }

                r = dns_packet_read_rr(p, &rr, &cache_flush, &start);
                if (r < 0)
                        return r;

                /* Try to reduce memory usage a bit */
                if (previous)
                        dns_resource_key_reduce(&rr->key, &previous->key);

                if (rr->key->type == DNS_TYPE_OPT) {
                        bool has_rfc6975;

                        if (p->opt || bad_opt) {
                                /* Multiple OPT RRs? if so, let's ignore all, because there's
                                 * something wrong with the server, and if one is valid we wouldn't
                                 * know which one. */
                                log_debug("Multiple OPT RRs detected, ignoring all.");
                                bad_opt = true;
                                continue;
                        }

                        if (!dns_name_is_root(dns_resource_key_name(rr->key))) {
                                /* If the OPT RR is not owned by the root domain, then it is bad,
                                 * let's ignore it. */
                                log_debug("OPT RR is not owned by root domain, ignoring.");
                                bad_opt = true;
                                continue;
                        }

                        if (i < DNS_PACKET_ANCOUNT(p) + DNS_PACKET_NSCOUNT(p)) {
                                /* OPT RR is in the wrong section? Some Belkin routers do this. This
                                 * is a hint the EDNS implementation is borked, like the Belkin one
                                 * is, hence ignore it. */
                                log_debug("OPT RR in wrong section, ignoring.");
                                bad_opt = true;
                                continue;
                        }

                        if (!opt_is_good(rr, &has_rfc6975)) {
                                log_debug("Malformed OPT RR, ignoring.");
                                bad_opt = true;
                                continue;
                        }

                        if (DNS_PACKET_QR(p)) {
                                /* Additional checks for responses */

                                if (!DNS_RESOURCE_RECORD_OPT_VERSION_SUPPORTED(rr))
                                        /* If this is a reply and we don't know the EDNS version
                                         * then something is weird... */
                                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                               "EDNS version newer that our request, bad server.");

                                if (has_rfc6975) {
                                        /* If the OPT RR contains RFC6975 algorithm data, then this
                                         * is indication that the server just copied the OPT it got
                                         * from us (which contained that data) back into the reply.
                                         * If so, then it doesn't properly support EDNS, as RFC6975
                                         * makes it very clear that the algorithm data should only
                                         * be contained in questions, never in replies. Crappy
                                         * Belkin routers copy the OPT data for example, hence let's
                                         * detect this so that we downgrade early. */
                                        log_debug("OPT RR contains RFC6975 data, ignoring.");
                                        bad_opt = true;
                                        continue;
                                }
                        }

                        p->opt = dns_resource_record_ref(rr);
                        p->opt_start = start;
                        assert(p->rindex >= start);
                        p->opt_size = p->rindex - start;
                } else {
                        DnsAnswerFlags flags = 0;

                        if (p->protocol == DNS_PROTOCOL_MDNS) {
                                flags |= DNS_ANSWER_REFUSE_TTL_NO_MATCH;
                                if (!cache_flush)
                                        flags |= DNS_ANSWER_SHARED_OWNER;
                        }

                        /* According to RFC 4795, section 2.9. only the RRs from the Answer section shall be
                         * cached. Hence mark only those RRs as cacheable by default, but not the ones from
                         * the Additional or Authority sections.
                         * This restriction does not apply to mDNS records (RFC 6762). */
                        if (i < DNS_PACKET_ANCOUNT(p))
                                flags |= DNS_ANSWER_CACHEABLE|DNS_ANSWER_SECTION_ANSWER;
                        else if (i < DNS_PACKET_ANCOUNT(p) + DNS_PACKET_NSCOUNT(p))
                                flags |= DNS_ANSWER_SECTION_AUTHORITY;
                        else {
                                flags |= DNS_ANSWER_SECTION_ADDITIONAL;
                                if (p->protocol == DNS_PROTOCOL_MDNS)
                                        flags |= DNS_ANSWER_CACHEABLE;
                        }

                        r = dns_answer_add(answer, rr, p->ifindex, flags, NULL);
                        if (r < 0)
                                return r;
                }

                /* Remember this RR, so that we can potentially merge its ->key object with the
                 * next RR. Note that we only do this if we actually decided to keep the RR around.
                 */
                DNS_RR_REPLACE(previous, dns_resource_record_ref(rr));
        }

        if (bad_opt) {
                p->opt = dns_resource_record_unref(p->opt);
                p->opt_start = p->opt_size = SIZE_MAX;
        }

        *ret_answer = TAKE_PTR(answer);

        return 0;
}

int dns_packet_extract(DnsPacket *p) {
        assert(p);

        if (p->extracted)
                return 0;

        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _unused_ _cleanup_(rewind_dns_packet) DnsPacketRewinder rewinder = REWINDER_INIT(p);
        int r;

        dns_packet_rewind(p, DNS_PACKET_HEADER_SIZE);

        r = dns_packet_extract_question(p, &question);
        if (r < 0)
                return r;

        r = dns_packet_extract_answer(p, &answer);
        if (r < 0)
                return r;

        if (p->rindex < p->size)  {
                log_debug("Trailing garbage in packet, suppressing OPT.");
                p->opt = dns_resource_record_unref(p->opt);
                p->opt_start = p->opt_size = SIZE_MAX;
        }

        p->question = TAKE_PTR(question);
        p->answer = TAKE_PTR(answer);
        p->extracted = true;

        /* no CANCEL, always rewind */
        return 0;
}

int dns_packet_is_reply_for(DnsPacket *p, const DnsResourceKey *key) {
        int r;

        assert(p);
        assert(key);

        /* Checks if the specified packet is a reply for the specified
         * key and the specified key is the only one in the question
         * section. */

        if (DNS_PACKET_QR(p) != 1)
                return 0;

        /* Let's unpack the packet, if that hasn't happened yet. */
        r = dns_packet_extract(p);
        if (r < 0)
                return r;

        if (!p->question)
                return 0;

        if (p->question->n_keys != 1)
                return 0;

        return dns_resource_key_equal(dns_question_first_key(p->question), key);
}

int dns_packet_patch_max_udp_size(DnsPacket *p, uint16_t max_udp_size) {
        assert(p);
        assert(max_udp_size >= DNS_PACKET_UNICAST_SIZE_MAX);

        if (p->opt_start == SIZE_MAX) /* No OPT section, nothing to patch */
                return 0;

        assert(p->opt_size != SIZE_MAX);
        assert(p->opt_size >= 5);

        unaligned_write_be16(DNS_PACKET_DATA(p) + p->opt_start + 3, max_udp_size);
        return 1;
}

static int patch_rr(DnsPacket *p, usec_t age) {
        _cleanup_(rewind_dns_packet) DnsPacketRewinder rewinder = REWINDER_INIT(p);
        size_t ttl_index;
        uint32_t ttl;
        uint16_t type, rdlength;
        int r;

        /* Patches the RR at the current rindex, subtracts the specified time from the TTL */

        r = dns_packet_read_name(p, NULL, true, NULL);
        if (r < 0)
                return r;

        r = dns_packet_read_uint16(p, &type, NULL);
        if (r < 0)
                return r;

        r = dns_packet_read_uint16(p, NULL, NULL);
        if (r < 0)
                return r;

        r = dns_packet_read_uint32(p, &ttl, &ttl_index);
        if (r < 0)
                return r;

        if (type != DNS_TYPE_OPT) { /* The TTL of the OPT field is not actually a TTL, skip it */
                ttl = LESS_BY(ttl * USEC_PER_SEC, age) / USEC_PER_SEC;
                unaligned_write_be32(DNS_PACKET_DATA(p) + ttl_index, ttl);
        }

        r = dns_packet_read_uint16(p, &rdlength, NULL);
        if (r < 0)
                return r;

        r = dns_packet_read(p, rdlength, NULL, NULL);
        if (r < 0)
                return r;

        CANCEL_REWINDER(rewinder);
        return 0;
}

int dns_packet_patch_ttls(DnsPacket *p, usec_t timestamp) {
        assert(p);
        assert(timestamp_is_set(timestamp));

        /* Adjusts all TTLs in the packet by subtracting the time difference between now and the specified timestamp */

        _unused_ _cleanup_(rewind_dns_packet) DnsPacketRewinder rewinder = REWINDER_INIT(p);
        unsigned n;
        usec_t k;
        int r;

        k = now(CLOCK_BOOTTIME);
        assert(k >= timestamp);
        k -= timestamp;

        dns_packet_rewind(p, DNS_PACKET_HEADER_SIZE);

        n = DNS_PACKET_QDCOUNT(p);
        for (unsigned i = 0; i < n; i++) {
                r = dns_packet_read_key(p, NULL, NULL, NULL);
                if (r < 0)
                        return r;
        }

        n = DNS_PACKET_RRCOUNT(p);
        for (unsigned i = 0; i < n; i++) {

                /* DNS servers suck, hence the RR count is in many servers off. If we reached the end
                 * prematurely, accept that, exit early */
                if (p->rindex == p->size)
                        break;

                r = patch_rr(p, k);
                if (r < 0)
                        return r;
        }

        return 0;
}

static void dns_packet_hash_func(const DnsPacket *s, struct siphash *state) {
        assert(s);

        siphash24_compress(&s->size, sizeof(s->size), state);
        siphash24_compress(DNS_PACKET_DATA((DnsPacket*) s), s->size, state);
}

static int dns_packet_compare_func(const DnsPacket *x, const DnsPacket *y) {
        int r;

        r = CMP(x->size, y->size);
        if (r != 0)
                return r;

        return memcmp(DNS_PACKET_DATA((DnsPacket*) x), DNS_PACKET_DATA((DnsPacket*) y), x->size);
}

DEFINE_HASH_OPS(dns_packet_hash_ops, DnsPacket, dns_packet_hash_func, dns_packet_compare_func);

bool dns_packet_equal(const DnsPacket *a, const DnsPacket *b) {
        return dns_packet_compare_func(a, b) == 0;
}

int dns_packet_has_nsid_request(DnsPacket *p) {
        bool has_nsid = false;
        const uint8_t *d;
        size_t l;

        assert(p);

        if (!p->opt)
                return false;

        d = p->opt->opt.data;
        l = p->opt->opt.data_size;

        while (l > 0) {
                uint16_t code, length;

                if (l < 4U)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "EDNS0 variable part has invalid size.");

                code = unaligned_read_be16(d);
                length = unaligned_read_be16(d + 2);

                if (l < 4U + length)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Truncated option in EDNS0 variable part.");

                if (code == 3) {
                        if (has_nsid)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "Duplicate NSID option in EDNS0 variable part.");

                        if (length != 0)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "Non-empty NSID option in DNS request.");

                        has_nsid = true;
                }

                d += 4U + length;
                l -= 4U + length;
        }

        return has_nsid;
}

size_t dns_packet_size_unfragmented(DnsPacket *p) {
        assert(p);

        if (p->fragsize == 0) /* Wasn't fragmented */
                return p->size;

        /* The fragment size (p->fragsize) covers the whole (fragmented) IP packet, while the regular packet
         * size (p->size) only covers the DNS part. Thus, subtract the UDP header from the largest fragment
         * size, in order to determine which size of DNS packet would have gone through without
         * fragmenting. */

        return LESS_BY(p->fragsize, udp_header_size(p->family));
}

static const char* const dns_rcode_table[_DNS_RCODE_MAX_DEFINED] = {
        [DNS_RCODE_SUCCESS]   = "SUCCESS",
        [DNS_RCODE_FORMERR]   = "FORMERR",
        [DNS_RCODE_SERVFAIL]  = "SERVFAIL",
        [DNS_RCODE_NXDOMAIN]  = "NXDOMAIN",
        [DNS_RCODE_NOTIMP]    = "NOTIMP",
        [DNS_RCODE_REFUSED]   = "REFUSED",
        [DNS_RCODE_YXDOMAIN]  = "YXDOMAIN",
        [DNS_RCODE_YXRRSET]   = "YRRSET",
        [DNS_RCODE_NXRRSET]   = "NXRRSET",
        [DNS_RCODE_NOTAUTH]   = "NOTAUTH",
        [DNS_RCODE_NOTZONE]   = "NOTZONE",
        [DNS_RCODE_BADVERS]   = "BADVERS",
        [DNS_RCODE_BADKEY]    = "BADKEY",
        [DNS_RCODE_BADTIME]   = "BADTIME",
        [DNS_RCODE_BADMODE]   = "BADMODE",
        [DNS_RCODE_BADNAME]   = "BADNAME",
        [DNS_RCODE_BADALG]    = "BADALG",
        [DNS_RCODE_BADTRUNC]  = "BADTRUNC",
        [DNS_RCODE_BADCOOKIE] = "BADCOOKIE",
};
DEFINE_STRING_TABLE_LOOKUP(dns_rcode, int);

const char *format_dns_rcode(int i, char buf[static DECIMAL_STR_MAX(int)]) {
        const char *p = dns_rcode_to_string(i);
        if (p)
                return p;

        return snprintf_ok(buf, DECIMAL_STR_MAX(int), "%i", i);
}

static const char* const dns_protocol_table[_DNS_PROTOCOL_MAX] = {
        [DNS_PROTOCOL_DNS]   = "dns",
        [DNS_PROTOCOL_MDNS]  = "mdns",
        [DNS_PROTOCOL_LLMNR] = "llmnr",
};
DEFINE_STRING_TABLE_LOOKUP(dns_protocol, DnsProtocol);
