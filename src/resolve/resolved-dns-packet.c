/* SPDX-License-Identifier: LGPL-2.1+ */

#if HAVE_GCRYPT
#include <gcrypt.h>
#endif

#include "alloc-util.h"
#include "dns-domain.h"
#include "memory-util.h"
#include "resolved-dns-packet.h"
#include "set.h"
#include "string-table.h"
#include "strv.h"
#include "unaligned.h"
#include "utf8.h"
#include "util.h"

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

#define INIT_REWINDER(rewinder, p) do { rewinder.packet = p; rewinder.saved_rindex = p->rindex; } while (0)
#define CANCEL_REWINDER(rewinder) do { rewinder.packet = NULL; } while (0)

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

        p->size = p->rindex = DNS_PACKET_HEADER_SIZE;
        p->allocated = a;
        p->max_size = max_size;
        p->protocol = protocol;
        p->opt_start = p->opt_size = (size_t) -1;
        p->n_ref = 1;

        *ret = p;

        return 0;
}

void dns_packet_set_flags(DnsPacket *p, bool dnssec_checking_disabled, bool truncated) {

        DnsPacketHeader *h;

        assert(p);

        h = DNS_PACKET_HEADER(p);

        switch(p->protocol) {
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

        if (DNS_PACKET_TC(p))
                return -EBADMSG;

        switch (p->protocol) {

        case DNS_PROTOCOL_LLMNR:
        case DNS_PROTOCOL_DNS:
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
                /* RFC 6762, Section 18 */
                if (DNS_PACKET_AA(p)    != 0 ||
                    DNS_PACKET_RD(p)    != 0 ||
                    DNS_PACKET_RA(p)    != 0 ||
                    DNS_PACKET_AD(p)    != 0 ||
                    DNS_PACKET_CD(p)    != 0 ||
                    DNS_PACKET_RCODE(p) != 0)
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
        Iterator i;
        char *s;
        void *n;

        assert(p);

        if (p->size <= sz)
                return;

        HASHMAP_FOREACH_KEY(n, s, p->names, i) {

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

        if (p->canonical_form && canonical_candidate) {
                size_t i;

                /* Generate in canonical form, as defined by DNSSEC
                 * RFC 4034, Section 6.2, i.e. all lower-case. */

                for (i = 0; i < l; i++)
                        w[i] = (uint8_t) ascii_tolower(d[i]);
        } else
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
                char label[DNS_LABEL_MAX];
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

                        r = hashmap_ensure_allocated(&p->names, &dns_name_hash_ops);
                        if (r < 0)
                                goto fail;

                        r = hashmap_put(p->names, s, SIZE_TO_PTR(n));
                        if (r < 0)
                                goto fail;

                        s = NULL;
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

        class = flags & DNS_ANSWER_CACHE_FLUSH ? k->class | MDNS_RR_CACHE_FLUSH : k->class;
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
        Iterator i;
        uint8_t window = 0;
        uint8_t entry = 0;
        uint8_t bitmaps[32] = {};
        unsigned n;
        size_t saved_size;
        int r;

        assert(p);

        saved_size = p->size;

        BITMAP_FOREACH(n, types, i) {
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
int dns_packet_append_opt(DnsPacket *p, uint16_t max_udp_size, bool edns0_do, int rcode, size_t *start) {
        size_t saved_size;
        int r;

        assert(p);
        /* we must never advertise supported packet size smaller than the legacy max */
        assert(max_udp_size >= DNS_PACKET_UNICAST_SIZE_MAX);
        assert(rcode >= 0);
        assert(rcode <= _DNS_RCODE_MAX);

        if (p->opt_start != (size_t) -1)
                return -EBUSY;

        assert(p->opt_size == (size_t) -1);

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

        /* RDLENGTH */
        if (edns0_do && !DNS_PACKET_QR(p)) {
                /* If DO is on and this is not a reply, also append RFC6975 Algorithm data */

                static const uint8_t rfc6975[] = {

                        0, 5, /* OPTION_CODE: DAU */
#if HAVE_GCRYPT && GCRYPT_VERSION_NUMBER >= 0x010600
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
#if HAVE_GCRYPT && GCRYPT_VERSION_NUMBER >= 0x010600
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

                r = dns_packet_append_uint16(p, sizeof(rfc6975), NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_blob(p, rfc6975, sizeof(rfc6975), NULL);
        } else
                r = dns_packet_append_uint16(p, 0, NULL);
        if (r < 0)
                goto fail;

        DNS_PACKET_HEADER(p)->arcount = htobe16(DNS_PACKET_ARCOUNT(p) + 1);

        p->opt_start = saved_size;
        p->opt_size = p->size - saved_size;

        if (start)
                *start = saved_size;

        return 0;

fail:
        dns_packet_truncate(p, saved_size);
        return r;
}

int dns_packet_truncate_opt(DnsPacket *p) {
        assert(p);

        if (p->opt_start == (size_t) -1) {
                assert(p->opt_size == (size_t) -1);
                return 0;
        }

        assert(p->opt_size != (size_t) -1);
        assert(DNS_PACKET_ARCOUNT(p) > 0);

        if (p->opt_start + p->opt_size != p->size)
                return -EBUSY;

        dns_packet_truncate(p, p->opt_start);
        DNS_PACKET_HEADER(p)->arcount = htobe16(DNS_PACKET_ARCOUNT(p) - 1);
        p->opt_start = p->opt_size = (size_t) -1;

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

        switch (rr->unparseable ? _DNS_TYPE_INVALID : rr->key->type) {

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

                /* RFC 2782 states "Unless and until permitted by future standards
                 * action, name compression is not to be used for this field." */
                r = dns_packet_append_name(p, rr->srv.name, false, false, NULL);
                break;

        case DNS_TYPE_PTR:
        case DNS_TYPE_NS:
        case DNS_TYPE_CNAME:
        case DNS_TYPE_DNAME:
                r = dns_packet_append_name(p, rr->ptr.name, true, false, NULL);
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
                } else {
                        DnsTxtItem *i;

                        LIST_FOREACH(items, i, rr->txt.items) {
                                r = dns_packet_append_raw_string(p, i->data, i->length, NULL);
                                if (r < 0)
                                        goto fail;
                        }
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
                r = dns_packet_append_name(p, rr->soa.mname, true, false, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_name(p, rr->soa.rname, true, false, NULL);
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

                r = dns_packet_append_name(p, rr->mx.exchange, true, false, NULL);
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
        case _DNS_TYPE_INVALID: /* unparseable */
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

int dns_packet_append_answer(DnsPacket *p, DnsAnswer *a) {
        DnsResourceRecord *rr;
        DnsAnswerFlags flags;
        int r;

        assert(p);

        DNS_ANSWER_FOREACH_FLAGS(rr, flags, a) {
                r = dns_packet_append_rr(p, rr, flags, NULL, NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

int dns_packet_read(DnsPacket *p, size_t sz, const void **ret, size_t *start) {
        assert(p);

        if (p->rindex + sz > p->size)
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
        _cleanup_(rewind_dns_packet) DnsPacketRewinder rewinder;
        const void *d;
        char *t;
        uint8_t c;
        int r;

        assert(p);
        INIT_REWINDER(rewinder, p);

        r = dns_packet_read_uint8(p, &c, NULL);
        if (r < 0)
                return r;

        r = dns_packet_read(p, c, &d, NULL);
        if (r < 0)
                return r;

        if (memchr(d, 0, c))
                return -EBADMSG;

        t = strndup(d, c);
        if (!t)
                return -ENOMEM;

        if (!utf8_is_valid(t)) {
                free(t);
                return -EBADMSG;
        }

        *ret = t;

        if (start)
                *start = rewinder.saved_rindex;
        CANCEL_REWINDER(rewinder);

        return 0;
}

int dns_packet_read_raw_string(DnsPacket *p, const void **ret, size_t *size, size_t *start) {
        _cleanup_(rewind_dns_packet) DnsPacketRewinder rewinder;
        uint8_t c;
        int r;

        assert(p);
        INIT_REWINDER(rewinder, p);

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
                char **_ret,
                bool allow_compression,
                size_t *start) {

        _cleanup_(rewind_dns_packet) DnsPacketRewinder rewinder;
        size_t after_rindex = 0, jump_barrier;
        _cleanup_free_ char *ret = NULL;
        size_t n = 0, allocated = 0;
        bool first = true;
        int r;

        assert(p);
        assert(_ret);
        INIT_REWINDER(rewinder, p);
        jump_barrier = p->rindex;

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

                        if (!GREEDY_REALLOC(ret, allocated, n + !first + DNS_LABEL_ESCAPED_MAX))
                                return -ENOMEM;

                        if (first)
                                first = false;
                        else
                                ret[n++] = '.';

                        r = dns_label_escape(label, c, ret + n, DNS_LABEL_ESCAPED_MAX);
                        if (r < 0)
                                return r;

                        n += r;
                        continue;
                } else if (allow_compression && (c & 0xc0) == 0xc0) {
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

        if (!GREEDY_REALLOC(ret, allocated, n + 1))
                return -ENOMEM;

        ret[n] = 0;

        if (after_rindex != 0)
                p->rindex= after_rindex;

        *_ret = TAKE_PTR(ret);

        if (start)
                *start = rewinder.saved_rindex;
        CANCEL_REWINDER(rewinder);

        return 0;
}

static int dns_packet_read_type_window(DnsPacket *p, Bitmap **types, size_t *start) {
        uint8_t window;
        uint8_t length;
        const uint8_t *bitmap;
        uint8_t bit = 0;
        unsigned i;
        bool found = false;
        _cleanup_(rewind_dns_packet) DnsPacketRewinder rewinder;
        int r;

        assert(p);
        assert(types);
        INIT_REWINDER(rewinder, p);

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

        for (i = 0; i < length; i++) {
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
        _cleanup_(rewind_dns_packet) DnsPacketRewinder rewinder;
        int r;

        INIT_REWINDER(rewinder, p);

        while (p->rindex < rewinder.saved_rindex + size) {
                r = dns_packet_read_type_window(p, types, NULL);
                if (r < 0)
                        return r;

                /* don't read past end of current RR */
                if (p->rindex > rewinder.saved_rindex + size)
                        return -EBADMSG;
        }

        if (p->rindex != rewinder.saved_rindex + size)
                return -EBADMSG;

        if (start)
                *start = rewinder.saved_rindex;
        CANCEL_REWINDER(rewinder);

        return 0;
}

int dns_packet_read_key(DnsPacket *p, DnsResourceKey **ret, bool *ret_cache_flush, size_t *start) {
        _cleanup_(rewind_dns_packet) DnsPacketRewinder rewinder;
        _cleanup_free_ char *name = NULL;
        bool cache_flush = false;
        uint16_t class, type;
        DnsResourceKey *key;
        int r;

        assert(p);
        assert(ret);
        INIT_REWINDER(rewinder, p);

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
                /* See RFC6762, Section 10.2 */

                if (type != DNS_TYPE_OPT && (class & MDNS_RR_CACHE_FLUSH)) {
                        class &= ~MDNS_RR_CACHE_FLUSH;
                        cache_flush = true;
                }
        }

        key = dns_resource_key_new_consume(class, type, name);
        if (!key)
                return -ENOMEM;

        name = NULL;
        *ret = key;

        if (ret_cache_flush)
                *ret_cache_flush = cache_flush;
        if (start)
                *start = rewinder.saved_rindex;
        CANCEL_REWINDER(rewinder);

        return 0;
}

static bool loc_size_ok(uint8_t size) {
        uint8_t m = size >> 4, e = size & 0xF;

        return m <= 9 && e <= 9 && (m > 0 || e == 0);
}

int dns_packet_read_rr(DnsPacket *p, DnsResourceRecord **ret, bool *ret_cache_flush, size_t *start) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(rewind_dns_packet) DnsPacketRewinder rewinder;
        size_t offset;
        uint16_t rdlength;
        bool cache_flush;
        int r;

        assert(p);
        assert(ret);

        INIT_REWINDER(rewinder, p);

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

        if (p->rindex + rdlength > p->size)
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
                r = dns_packet_read_name(p, &rr->srv.name, true, NULL);
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

                        while (p->rindex < offset + rdlength) {
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
                        rr->unparseable = true;
                        goto unparseable;
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

                if (rdlength + offset < p->rindex)
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

                if (rdlength + offset < p->rindex)
                        return -EBADMSG;

                r = dns_packet_read_memdup(p,
                                           rdlength + offset - p->rindex,
                                           &rr->caa.value, &rr->caa.value_size, NULL);

                break;

        case DNS_TYPE_OPT: /* we only care about the header of OPT for now. */
        case DNS_TYPE_OPENPGPKEY:
        default:
        unparseable:
                r = dns_packet_read_memdup(p, rdlength, &rr->generic.data, &rr->generic.data_size, NULL);

                break;
        }
        if (r < 0)
                return r;
        if (p->rindex != offset + rdlength)
                return -EBADMSG;

        *ret = TAKE_PTR(rr);

        if (ret_cache_flush)
                *ret_cache_flush = cache_flush;
        if (start)
                *start = rewinder.saved_rindex;
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
        unsigned n, i;
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
                                               * hash collisions, but the gains quickly drop of after 2. */
                if (r < 0)
                        return r;

                for (i = 0; i < n; i++) {
                        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
                        bool cache_flush;

                        r = dns_packet_read_key(p, &key, &cache_flush, NULL);
                        if (r < 0)
                                return r;

                        if (cache_flush)
                                return -EBADMSG;

                        if (!dns_type_is_valid_query(key->type))
                                return -EBADMSG;

                        r = set_put(keys, key);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                /* Already in the Question, let's skip */
                                continue;

                        r = dns_question_add_raw(question, key);
                        if (r < 0)
                                return r;
                }
        }

        *ret_question = TAKE_PTR(question);

        return 0;
}

static int dns_packet_extract_answer(DnsPacket *p, DnsAnswer **ret_answer) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        unsigned n, i;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *previous = NULL;
        bool bad_opt = false;
        int r;

        n = DNS_PACKET_RRCOUNT(p);
        if (n == 0)
                return 0;

        answer = dns_answer_new(n);
        if (!answer)
                return -ENOMEM;

        for (i = 0; i < n; i++) {
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
                bool cache_flush = false;

                r = dns_packet_read_rr(p, &rr, &cache_flush, NULL);
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

                                if (!DNS_RESOURCE_RECORD_OPT_VERSION_SUPPORTED(rr)) {
                                        /* If this is a reply and we don't know the EDNS version
                                         * then something is weird... */
                                        log_debug("EDNS version newer that our request, bad server.");
                                        return -EBADMSG;
                                }

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
                } else {
                        /* According to RFC 4795, section 2.9. only the RRs from the Answer section
                         * shall be cached. Hence mark only those RRs as cacheable by default, but
                         * not the ones from the Additional or Authority sections. */
                        DnsAnswerFlags flags =
                                (i < DNS_PACKET_ANCOUNT(p) ? DNS_ANSWER_CACHEABLE : 0) |
                                (p->protocol == DNS_PROTOCOL_MDNS && !cache_flush ? DNS_ANSWER_SHARED_OWNER : 0);

                        r = dns_answer_add(answer, rr, p->ifindex, flags);
                        if (r < 0)
                                return r;
                }

                /* Remember this RR, so that we potentically can merge it's ->key object with the
                 * next RR. Note that we only do this if we actually decided to keep the RR around.
                 */
                dns_resource_record_unref(previous);
                previous = dns_resource_record_ref(rr);
        }

        if (bad_opt)
                p->opt = dns_resource_record_unref(p->opt);

        *ret_answer = TAKE_PTR(answer);

        return 0;
}

int dns_packet_extract(DnsPacket *p) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(rewind_dns_packet) DnsPacketRewinder rewinder = {};
        int r;

        if (p->extracted)
                return 0;

        INIT_REWINDER(rewinder, p);
        dns_packet_rewind(p, DNS_PACKET_HEADER_SIZE);

        r = dns_packet_extract_question(p, &question);
        if (r < 0)
                return r;

        r = dns_packet_extract_answer(p, &answer);
        if (r < 0)
                return r;

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

        return dns_resource_key_equal(p->question->keys[0], key);
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

static const char* const dns_rcode_table[_DNS_RCODE_MAX_DEFINED] = {
        [DNS_RCODE_SUCCESS] = "SUCCESS",
        [DNS_RCODE_FORMERR] = "FORMERR",
        [DNS_RCODE_SERVFAIL] = "SERVFAIL",
        [DNS_RCODE_NXDOMAIN] = "NXDOMAIN",
        [DNS_RCODE_NOTIMP] = "NOTIMP",
        [DNS_RCODE_REFUSED] = "REFUSED",
        [DNS_RCODE_YXDOMAIN] = "YXDOMAIN",
        [DNS_RCODE_YXRRSET] = "YRRSET",
        [DNS_RCODE_NXRRSET] = "NXRRSET",
        [DNS_RCODE_NOTAUTH] = "NOTAUTH",
        [DNS_RCODE_NOTZONE] = "NOTZONE",
        [DNS_RCODE_BADVERS] = "BADVERS",
        [DNS_RCODE_BADKEY] = "BADKEY",
        [DNS_RCODE_BADTIME] = "BADTIME",
        [DNS_RCODE_BADMODE] = "BADMODE",
        [DNS_RCODE_BADNAME] = "BADNAME",
        [DNS_RCODE_BADALG] = "BADALG",
        [DNS_RCODE_BADTRUNC] = "BADTRUNC",
        [DNS_RCODE_BADCOOKIE] = "BADCOOKIE",
};
DEFINE_STRING_TABLE_LOOKUP(dns_rcode, int);

static const char* const dns_protocol_table[_DNS_PROTOCOL_MAX] = {
        [DNS_PROTOCOL_DNS] = "dns",
        [DNS_PROTOCOL_MDNS] = "mdns",
        [DNS_PROTOCOL_LLMNR] = "llmnr",
};
DEFINE_STRING_TABLE_LOOKUP(dns_protocol, DnsProtocol);
