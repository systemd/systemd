/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include "utf8.h"
#include "util.h"
#include "strv.h"
#include "unaligned.h"
#include "dns-domain.h"
#include "resolved-dns-packet.h"

int dns_packet_new(DnsPacket **ret, DnsProtocol protocol, size_t mtu) {
        DnsPacket *p;
        size_t a;

        assert(ret);

        if (mtu <= UDP_PACKET_HEADER_SIZE)
                a = DNS_PACKET_SIZE_START;
        else
                a = mtu - UDP_PACKET_HEADER_SIZE;

        if (a < DNS_PACKET_HEADER_SIZE)
                a = DNS_PACKET_HEADER_SIZE;

        /* round up to next page size */
        a = PAGE_ALIGN(ALIGN(sizeof(DnsPacket)) + a) - ALIGN(sizeof(DnsPacket));

        /* make sure we never allocate more than useful */
        if (a > DNS_PACKET_SIZE_MAX)
                a = DNS_PACKET_SIZE_MAX;

        p = malloc0(ALIGN(sizeof(DnsPacket)) + a);
        if (!p)
                return -ENOMEM;

        p->size = p->rindex = DNS_PACKET_HEADER_SIZE;
        p->allocated = a;
        p->protocol = protocol;
        p->n_ref = 1;

        *ret = p;

        return 0;
}

int dns_packet_new_query(DnsPacket **ret, DnsProtocol protocol, size_t mtu) {
        DnsPacket *p;
        DnsPacketHeader *h;
        int r;

        assert(ret);

        r = dns_packet_new(&p, protocol, mtu);
        if (r < 0)
                return r;

        h = DNS_PACKET_HEADER(p);

        if (protocol == DNS_PROTOCOL_LLMNR)
                h->flags = htobe16(DNS_PACKET_MAKE_FLAGS(0 /* qr */,
                                                         0 /* opcode */,
                                                         0 /* c */,
                                                         0 /* tc */,
                                                         0 /* t */,
                                                         0 /* ra */,
                                                         0 /* ad */,
                                                         0 /* cd */,
                                                         0 /* rcode */));
        else
                h->flags = htobe16(DNS_PACKET_MAKE_FLAGS(0 /* qr */,
                                                         0 /* opcode */,
                                                         0 /* aa */,
                                                         0 /* tc */,
                                                         1 /* rd (ask for recursion) */,
                                                         0 /* ra */,
                                                         0 /* ad */,
                                                         0 /* cd */,
                                                         0 /* rcode */));

        *ret = p;
        return 0;
}

DnsPacket *dns_packet_ref(DnsPacket *p) {

        if (!p)
                return NULL;

        assert(p->n_ref > 0);
        p->n_ref++;
        return p;
}

static void dns_packet_free(DnsPacket *p) {
        char *s;

        assert(p);

        dns_question_unref(p->question);
        dns_answer_unref(p->answer);

        while ((s = hashmap_steal_first_key(p->names)))
                free(s);
        hashmap_free(p->names);

        free(p->_data);
        free(p);
}

DnsPacket *dns_packet_unref(DnsPacket *p) {
        if (!p)
                return NULL;

        assert(p->n_ref > 0);

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

        default:
                break;
        }

        return 1;
}

static int dns_packet_extend(DnsPacket *p, size_t add, void **ret, size_t *start) {
        assert(p);

        if (p->size + add > p->allocated) {
                size_t a;

                a = PAGE_ALIGN((p->size + add) * 2);
                if (a > DNS_PACKET_SIZE_MAX)
                        a = DNS_PACKET_SIZE_MAX;

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

static void dns_packet_truncate(DnsPacket *p, size_t sz) {
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

        memcpy(q, d, l);
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
        void *d;
        size_t l;
        int r;

        assert(p);
        assert(s);

        l = strlen(s);
        if (l > 255)
                return -E2BIG;

        r = dns_packet_extend(p, 1 + l, &d, start);
        if (r < 0)
                return r;

        ((uint8_t*) d)[0] = (uint8_t) l;
        memcpy(((uint8_t*) d) + 1, s, l);

        return 0;
}

int dns_packet_append_label(DnsPacket *p, const char *d, size_t l, size_t *start) {
        void *w;
        int r;

        assert(p);
        assert(d);

        if (l > DNS_LABEL_MAX)
                return -E2BIG;

        r = dns_packet_extend(p, 1 + l, &w, start);
        if (r < 0)
                return r;

        ((uint8_t*) w)[0] = (uint8_t) l;
        memcpy(((uint8_t*) w) + 1, d, l);

        return 0;
}

int dns_packet_append_name(
                DnsPacket *p,
                const char *name,
                bool allow_compression,
                size_t *start) {

        size_t saved_size;
        int r;

        assert(p);
        assert(name);

        if (p->refuse_compression)
                allow_compression = false;

        saved_size = p->size;

        while (*name) {
                _cleanup_free_ char *s = NULL;
                char label[DNS_LABEL_MAX];
                size_t n = 0;
                int k;

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

                s = strdup(name);
                if (!s) {
                        r = -ENOMEM;
                        goto fail;
                }

                r = dns_label_unescape(&name, label, sizeof(label));
                if (r < 0)
                        goto fail;

                if (p->protocol == DNS_PROTOCOL_DNS)
                        k = dns_label_apply_idna(label, r, label, sizeof(label));
                else
                        k = dns_label_undo_idna(label, r, label, sizeof(label));
                if (k < 0) {
                        r = k;
                        goto fail;
                }
                if (k > 0)
                        r = k;

                r = dns_packet_append_label(p, label, r, &n);
                if (r < 0)
                        goto fail;

                if (allow_compression) {
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

int dns_packet_append_key(DnsPacket *p, const DnsResourceKey *k, size_t *start) {
        size_t saved_size;
        int r;

        assert(p);
        assert(k);

        saved_size = p->size;

        r = dns_packet_append_name(p, DNS_RESOURCE_KEY_NAME(k), true, NULL);
        if (r < 0)
                goto fail;

        r = dns_packet_append_uint16(p, k->type, NULL);
        if (r < 0)
                goto fail;

        r = dns_packet_append_uint16(p, k->class, NULL);
        if (r < 0)
                goto fail;

        if (start)
                *start = saved_size;

        return 0;

fail:
        dns_packet_truncate(p, saved_size);
        return r;
}

static int dns_packet_append_type_window(DnsPacket *p, uint8_t window, uint8_t length, uint8_t *types, size_t *start) {
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
        assert(types);

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

        r = dns_packet_append_type_window(p, window, entry / 8 + 1, bitmaps, NULL);
        if (r < 0)
                goto fail;

        if (start)
                *start = saved_size;

        return 0;
fail:
        dns_packet_truncate(p, saved_size);
        return r;
}

int dns_packet_append_rr(DnsPacket *p, const DnsResourceRecord *rr, size_t *start) {
        size_t saved_size, rdlength_offset, end, rdlength;
        int r;

        assert(p);
        assert(rr);

        saved_size = p->size;

        r = dns_packet_append_key(p, rr->key, NULL);
        if (r < 0)
                goto fail;

        r = dns_packet_append_uint32(p, rr->ttl, NULL);
        if (r < 0)
                goto fail;

        /* Initially we write 0 here */
        r = dns_packet_append_uint16(p, 0, &rdlength_offset);
        if (r < 0)
                goto fail;

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

                r = dns_packet_append_name(p, rr->srv.name, true, NULL);
                break;

        case DNS_TYPE_PTR:
        case DNS_TYPE_NS:
        case DNS_TYPE_CNAME:
        case DNS_TYPE_DNAME:
                r = dns_packet_append_name(p, rr->ptr.name, true, NULL);
                break;

        case DNS_TYPE_HINFO:
                r = dns_packet_append_string(p, rr->hinfo.cpu, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_string(p, rr->hinfo.os, NULL);
                break;

        case DNS_TYPE_SPF: /* exactly the same as TXT */
        case DNS_TYPE_TXT: {
                char **s;

                if (strv_isempty(rr->txt.strings)) {
                        /* RFC 6763, section 6.1 suggests to generate
                         * single empty string for an empty array. */

                        r = dns_packet_append_string(p, "", NULL);
                        if (r < 0)
                                goto fail;
                } else {
                        STRV_FOREACH(s, rr->txt.strings) {
                                r = dns_packet_append_string(p, *s, NULL);
                                if (r < 0)
                                        goto fail;
                        }
                }

                r = 0;
                break;
        }

        case DNS_TYPE_A:
                r = dns_packet_append_blob(p, &rr->a.in_addr, sizeof(struct in_addr), NULL);
                break;

        case DNS_TYPE_AAAA:
                r = dns_packet_append_blob(p, &rr->aaaa.in6_addr, sizeof(struct in6_addr), NULL);
                break;

        case DNS_TYPE_SOA:
                r = dns_packet_append_name(p, rr->soa.mname, true, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_name(p, rr->soa.rname, true, NULL);
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

                r = dns_packet_append_name(p, rr->mx.exchange, true, NULL);
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
                r = dns_packet_append_uint16(p, dnskey_to_flags(rr), NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_uint8(p, 3u, NULL);
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

                r = dns_packet_append_name(p, rr->rrsig.signer, false, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_append_blob(p, rr->rrsig.signature, rr->rrsig.signature_size, NULL);
                break;

        case DNS_TYPE_NSEC:
                r = dns_packet_append_name(p, rr->nsec.next_domain_name, false, NULL);
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
        case _DNS_TYPE_INVALID: /* unparseable */
        default:

                r = dns_packet_append_blob(p, rr->generic.data, rr->generic.size, NULL);
                break;
        }
        if (r < 0)
                goto fail;

        /* Let's calculate the actual data size and update the field */
        rdlength = p->size - rdlength_offset - sizeof(uint16_t);
        if (rdlength > 0xFFFF) {
                r = ENOSPC;
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

        return 0;

fail:
        dns_packet_truncate(p, saved_size);
        return r;
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
        size_t saved_rindex;
        const void *d;
        char *t;
        uint8_t c;
        int r;

        assert(p);

        saved_rindex = p->rindex;

        r = dns_packet_read_uint8(p, &c, NULL);
        if (r < 0)
                goto fail;

        r = dns_packet_read(p, c, &d, NULL);
        if (r < 0)
                goto fail;

        if (memchr(d, 0, c)) {
                r = -EBADMSG;
                goto fail;
        }

        t = strndup(d, c);
        if (!t) {
                r = -ENOMEM;
                goto fail;
        }

        if (!utf8_is_valid(t)) {
                free(t);
                r = -EBADMSG;
                goto fail;
        }

        *ret = t;

        if (start)
                *start = saved_rindex;

        return 0;

fail:
        dns_packet_rewind(p, saved_rindex);
        return r;
}

int dns_packet_read_name(
                DnsPacket *p,
                char **_ret,
                bool allow_compression,
                size_t *start) {

        size_t saved_rindex, after_rindex = 0, jump_barrier;
        _cleanup_free_ char *ret = NULL;
        size_t n = 0, allocated = 0;
        bool first = true;
        int r;

        assert(p);
        assert(_ret);

        if (p->refuse_compression)
                allow_compression = false;

        saved_rindex = p->rindex;
        jump_barrier = p->rindex;

        for (;;) {
                uint8_t c, d;

                r = dns_packet_read_uint8(p, &c, NULL);
                if (r < 0)
                        goto fail;

                if (c == 0)
                        /* End of name */
                        break;
                else if (c <= 63) {
                        _cleanup_free_ char *t = NULL;
                        const char *label;

                        /* Literal label */
                        r = dns_packet_read(p, c, (const void**) &label, NULL);
                        if (r < 0)
                                goto fail;

                        r = dns_label_escape(label, c, &t);
                        if (r < 0)
                                goto fail;

                        if (!GREEDY_REALLOC(ret, allocated, n + !first + strlen(t) + 1)) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        if (!first)
                                ret[n++] = '.';
                        else
                                first = false;

                        memcpy(ret + n, t, r);
                        n += r;
                        continue;
                } else if (allow_compression && (c & 0xc0) == 0xc0) {
                        uint16_t ptr;

                        /* Pointer */
                        r = dns_packet_read_uint8(p, &d, NULL);
                        if (r < 0)
                                goto fail;

                        ptr = (uint16_t) (c & ~0xc0) << 8 | (uint16_t) d;
                        if (ptr < DNS_PACKET_HEADER_SIZE || ptr >= jump_barrier) {
                                r = -EBADMSG;
                                goto fail;
                        }

                        if (after_rindex == 0)
                                after_rindex = p->rindex;

                        /* Jumps are limited to a "prior occurrence" (RFC-1035 4.1.4) */
                        jump_barrier = ptr;
                        p->rindex = ptr;
                } else {
                        r = -EBADMSG;
                        goto fail;
                }
        }

        if (!GREEDY_REALLOC(ret, allocated, n + 1)) {
                r = -ENOMEM;
                goto fail;
        }

        ret[n] = 0;

        if (after_rindex != 0)
                p->rindex= after_rindex;

        *_ret = ret;
        ret = NULL;

        if (start)
                *start = saved_rindex;

        return 0;

fail:
        dns_packet_rewind(p, saved_rindex);
        return r;
}

static int dns_packet_read_type_window(DnsPacket *p, Bitmap **types, size_t *start) {
        uint8_t window;
        uint8_t length;
        const uint8_t *bitmap;
        uint8_t bit = 0;
        unsigned i;
        bool found = false;
        size_t saved_rindex;
        int r;

        assert(p);
        assert(types);

        saved_rindex = p->rindex;

        r = bitmap_ensure_allocated(types);
        if (r < 0)
                goto fail;

        r = dns_packet_read_uint8(p, &window, NULL);
        if (r < 0)
                goto fail;

        r = dns_packet_read_uint8(p, &length, NULL);
        if (r < 0)
                goto fail;

        if (length == 0 || length > 32)
                return -EBADMSG;

        r = dns_packet_read(p, length, (const void **)&bitmap, NULL);
        if (r < 0)
                goto fail;

        for (i = 0; i < length; i++) {
                uint8_t bitmask = 1 << 7;

                if (!bitmap[i]) {
                        found = false;
                        bit += 8;
                        continue;
                }

                found = true;

                while (bitmask) {
                        if (bitmap[i] & bitmask) {
                                uint16_t n;

                                n = (uint16_t) window << 8 | (uint16_t) bit;

                                /* Ignore pseudo-types. see RFC4034 section 4.1.2 */
                                if (dns_type_is_pseudo(n))
                                        continue;

                                r = bitmap_set(*types, n);
                                if (r < 0)
                                        goto fail;
                        }

                        bit ++;
                        bitmask >>= 1;
                }
        }

        if (!found)
                return -EBADMSG;

        if (start)
                *start = saved_rindex;

        return 0;
fail:
        dns_packet_rewind(p, saved_rindex);
        return r;
}

static int dns_packet_read_type_windows(DnsPacket *p, Bitmap **types, size_t size, size_t *start) {
        size_t saved_rindex;
        int r;

        saved_rindex = p->rindex;

        while (p->rindex < saved_rindex + size) {
                r = dns_packet_read_type_window(p, types, NULL);
                if (r < 0)
                        goto fail;

                /* don't read past end of current RR */
                if (p->rindex > saved_rindex + size) {
                        r = -EBADMSG;
                        goto fail;
                }
        }

        if (p->rindex != saved_rindex + size) {
                r = -EBADMSG;
                goto fail;
        }

        if (start)
                *start = saved_rindex;

        return 0;
fail:
        dns_packet_rewind(p, saved_rindex);
        return r;
}

int dns_packet_read_key(DnsPacket *p, DnsResourceKey **ret, size_t *start) {
        _cleanup_free_ char *name = NULL;
        uint16_t class, type;
        DnsResourceKey *key;
        size_t saved_rindex;
        int r;

        assert(p);
        assert(ret);

        saved_rindex = p->rindex;

        r = dns_packet_read_name(p, &name, true, NULL);
        if (r < 0)
                goto fail;

        r = dns_packet_read_uint16(p, &type, NULL);
        if (r < 0)
                goto fail;

        r = dns_packet_read_uint16(p, &class, NULL);
        if (r < 0)
                goto fail;

        key = dns_resource_key_new_consume(class, type, name);
        if (!key) {
                r = -ENOMEM;
                goto fail;
        }

        name = NULL;
        *ret = key;

        if (start)
                *start = saved_rindex;

        return 0;
fail:
        dns_packet_rewind(p, saved_rindex);
        return r;
}

static bool loc_size_ok(uint8_t size) {
        uint8_t m = size >> 4, e = size & 0xF;

        return m <= 9 && e <= 9 && (m > 0 || e == 0);
}

static int dnskey_parse_flags(DnsResourceRecord *rr, uint16_t flags) {
        assert(rr);

        if (flags & ~(DNSKEY_FLAG_SEP | DNSKEY_FLAG_ZONE_KEY))
                return -EBADMSG;

        rr->dnskey.zone_key_flag = flags & DNSKEY_FLAG_ZONE_KEY;
        rr->dnskey.sep_flag = flags & DNSKEY_FLAG_SEP;
        return 0;
}

int dns_packet_read_rr(DnsPacket *p, DnsResourceRecord **ret, size_t *start) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        size_t saved_rindex, offset;
        uint16_t rdlength;
        int r;

        assert(p);
        assert(ret);

        saved_rindex = p->rindex;

        r = dns_packet_read_key(p, &key, NULL);
        if (r < 0)
                goto fail;

        if (key->class == DNS_CLASS_ANY ||
            key->type == DNS_TYPE_ANY) {
                r = -EBADMSG;
                goto fail;
        }

        rr = dns_resource_record_new(key);
        if (!rr) {
                r = -ENOMEM;
                goto fail;
        }

        r = dns_packet_read_uint32(p, &rr->ttl, NULL);
        if (r < 0)
                goto fail;

        r = dns_packet_read_uint16(p, &rdlength, NULL);
        if (r < 0)
                goto fail;

        if (p->rindex + rdlength > p->size) {
                r = -EBADMSG;
                goto fail;
        }

        offset = p->rindex;

        switch (rr->key->type) {

        case DNS_TYPE_SRV:
                r = dns_packet_read_uint16(p, &rr->srv.priority, NULL);
                if (r < 0)
                        goto fail;
                r = dns_packet_read_uint16(p, &rr->srv.weight, NULL);
                if (r < 0)
                        goto fail;
                r = dns_packet_read_uint16(p, &rr->srv.port, NULL);
                if (r < 0)
                        goto fail;
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
                        goto fail;

                r = dns_packet_read_string(p, &rr->hinfo.os, NULL);
                break;

        case DNS_TYPE_SPF: /* exactly the same as TXT */
        case DNS_TYPE_TXT:
                if (rdlength <= 0) {
                        /* RFC 6763, section 6.1 suggests to treat
                         * empty TXT RRs as equivalent to a TXT record
                         * with a single empty string. */

                        r = strv_extend(&rr->txt.strings, "");
                        if (r < 0)
                                goto fail;
                } else {
                        while (p->rindex < offset + rdlength) {
                                char *s;

                                r = dns_packet_read_string(p, &s, NULL);
                                if (r < 0)
                                        goto fail;

                                r = strv_consume(&rr->txt.strings, s);
                                if (r < 0)
                                        goto fail;
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
                        goto fail;

                r = dns_packet_read_name(p, &rr->soa.rname, true, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_uint32(p, &rr->soa.serial, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_uint32(p, &rr->soa.refresh, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_uint32(p, &rr->soa.retry, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_uint32(p, &rr->soa.expire, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_uint32(p, &rr->soa.minimum, NULL);
                break;

        case DNS_TYPE_MX:
                r = dns_packet_read_uint16(p, &rr->mx.priority, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_name(p, &rr->mx.exchange, true, NULL);
                break;

        case DNS_TYPE_LOC: {
                uint8_t t;
                size_t pos;

                r = dns_packet_read_uint8(p, &t, &pos);
                if (r < 0)
                        goto fail;

                if (t == 0) {
                        rr->loc.version = t;

                        r = dns_packet_read_uint8(p, &rr->loc.size, NULL);
                        if (r < 0)
                                goto fail;

                        if (!loc_size_ok(rr->loc.size)) {
                                r = -EBADMSG;
                                goto fail;
                        }

                        r = dns_packet_read_uint8(p, &rr->loc.horiz_pre, NULL);
                        if (r < 0)
                                goto fail;

                        if (!loc_size_ok(rr->loc.horiz_pre)) {
                                r = -EBADMSG;
                                goto fail;
                        }

                        r = dns_packet_read_uint8(p, &rr->loc.vert_pre, NULL);
                        if (r < 0)
                                goto fail;

                        if (!loc_size_ok(rr->loc.vert_pre)) {
                                r = -EBADMSG;
                                goto fail;
                        }

                        r = dns_packet_read_uint32(p, &rr->loc.latitude, NULL);
                        if (r < 0)
                                goto fail;

                        r = dns_packet_read_uint32(p, &rr->loc.longitude, NULL);
                        if (r < 0)
                                goto fail;

                        r = dns_packet_read_uint32(p, &rr->loc.altitude, NULL);
                        if (r < 0)
                                goto fail;

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
                        goto fail;

                r = dns_packet_read_uint8(p, &rr->ds.algorithm, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_uint8(p, &rr->ds.digest_type, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_memdup(p, rdlength - 4,
                                           &rr->ds.digest, &rr->ds.digest_size,
                                           NULL);
                if (r < 0)
                        goto fail;

                if (rr->ds.digest_size <= 0) {
                        /* the accepted size depends on the algorithm, but for now
                           just ensure that the value is greater than zero */
                        r = -EBADMSG;
                        goto fail;
                }

                break;
        case DNS_TYPE_SSHFP:
                r = dns_packet_read_uint8(p, &rr->sshfp.algorithm, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_uint8(p, &rr->sshfp.fptype, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_memdup(p, rdlength - 2,
                                           &rr->sshfp.fingerprint, &rr->sshfp.fingerprint_size,
                                           NULL);

                if (rr->sshfp.fingerprint_size <= 0) {
                        /* the accepted size depends on the algorithm, but for now
                           just ensure that the value is greater than zero */
                        r = -EBADMSG;
                        goto fail;
                }

                break;

        case DNS_TYPE_DNSKEY: {
                uint16_t flags;
                uint8_t proto;

                r = dns_packet_read_uint16(p, &flags, NULL);
                if (r < 0)
                        goto fail;

                r = dnskey_parse_flags(rr, flags);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_uint8(p, &proto, NULL);
                if (r < 0)
                        goto fail;

                /* protocol is required to be always 3 */
                if (proto != 3) {
                        r = -EBADMSG;
                        goto fail;
                }

                r = dns_packet_read_uint8(p, &rr->dnskey.algorithm, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_memdup(p, rdlength - 4,
                                           &rr->dnskey.key, &rr->dnskey.key_size,
                                           NULL);

                if (rr->dnskey.key_size <= 0) {
                        /* the accepted size depends on the algorithm, but for now
                           just ensure that the value is greater than zero */
                        r = -EBADMSG;
                        goto fail;
                }

                break;
        }

        case DNS_TYPE_RRSIG:
                r = dns_packet_read_uint16(p, &rr->rrsig.type_covered, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_uint8(p, &rr->rrsig.algorithm, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_uint8(p, &rr->rrsig.labels, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_uint32(p, &rr->rrsig.original_ttl, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_uint32(p, &rr->rrsig.expiration, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_uint32(p, &rr->rrsig.inception, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_uint16(p, &rr->rrsig.key_tag, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_name(p, &rr->rrsig.signer, false, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_memdup(p, offset + rdlength - p->rindex,
                                           &rr->rrsig.signature, &rr->rrsig.signature_size,
                                           NULL);

                if (rr->rrsig.signature_size <= 0) {
                        /* the accepted size depends on the algorithm, but for now
                           just ensure that the value is greater than zero */
                        r = -EBADMSG;
                        goto fail;
                }

                break;

        case DNS_TYPE_NSEC:
                r = dns_packet_read_name(p, &rr->nsec.next_domain_name, false, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_type_windows(p, &rr->nsec.types, offset + rdlength - p->rindex, NULL);
                if (r < 0)
                        goto fail;

                /* The types bitmap must contain at least the NSEC record itself, so an empty bitmap means
                   something went wrong */
                if (bitmap_isclear(rr->nsec.types)) {
                        r = -EBADMSG;
                        goto fail;
                }

                break;

        case DNS_TYPE_NSEC3: {
                uint8_t size;

                r = dns_packet_read_uint8(p, &rr->nsec3.algorithm, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_uint8(p, &rr->nsec3.flags, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_uint16(p, &rr->nsec3.iterations, NULL);
                if (r < 0)
                        goto fail;

                /* this may be zero */
                r = dns_packet_read_uint8(p, &size, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_memdup(p, size, &rr->nsec3.salt, &rr->nsec3.salt_size, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_uint8(p, &size, NULL);
                if (r < 0)
                        goto fail;

                if (size <= 0) {
                        r = -EBADMSG;
                        goto fail;
                }

                r = dns_packet_read_memdup(p, size, &rr->nsec3.next_hashed_name, &rr->nsec3.next_hashed_name_size, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_type_windows(p, &rr->nsec3.types, offset + rdlength - p->rindex, NULL);
                if (r < 0)
                        goto fail;

                /* empty non-terminals can have NSEC3 records, so empty bitmaps are allowed */

                break;
        }
        default:
        unparseable:
                r = dns_packet_read_memdup(p, rdlength, &rr->generic.data, &rr->generic.size, NULL);
                if (r < 0)
                        goto fail;
                break;
        }
        if (r < 0)
                goto fail;
        if (p->rindex != offset + rdlength) {
                r = -EBADMSG;
                goto fail;
        }

        *ret = rr;
        rr = NULL;

        if (start)
                *start = saved_rindex;

        return 0;
fail:
        dns_packet_rewind(p, saved_rindex);
        return r;
}

int dns_packet_extract(DnsPacket *p) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        size_t saved_rindex;
        unsigned n, i;
        int r;

        if (p->extracted)
                return 0;

        saved_rindex = p->rindex;
        dns_packet_rewind(p, DNS_PACKET_HEADER_SIZE);

        n = DNS_PACKET_QDCOUNT(p);
        if (n > 0) {
                question = dns_question_new(n);
                if (!question) {
                        r = -ENOMEM;
                        goto finish;
                }

                for (i = 0; i < n; i++) {
                        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

                        r = dns_packet_read_key(p, &key, NULL);
                        if (r < 0)
                                goto finish;

                        r = dns_question_add(question, key);
                        if (r < 0)
                                goto finish;
                }
        }

        n = DNS_PACKET_RRCOUNT(p);
        if (n > 0) {
                answer = dns_answer_new(n);
                if (!answer) {
                        r = -ENOMEM;
                        goto finish;
                }

                for (i = 0; i < n; i++) {
                        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

                        r = dns_packet_read_rr(p, &rr, NULL);
                        if (r < 0)
                                goto finish;

                        r = dns_answer_add(answer, rr, p->ifindex);
                        if (r < 0)
                                goto finish;
                }
        }

        p->question = question;
        question = NULL;

        p->answer = answer;
        answer = NULL;

        p->extracted = true;

        r = 0;

finish:
        p->rindex = saved_rindex;
        return r;
}

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
};
DEFINE_STRING_TABLE_LOOKUP(dns_rcode, int);

static const char* const dns_protocol_table[_DNS_PROTOCOL_MAX] = {
        [DNS_PROTOCOL_DNS] = "dns",
        [DNS_PROTOCOL_MDNS] = "mdns",
        [DNS_PROTOCOL_LLMNR] = "llmnr",
};
DEFINE_STRING_TABLE_LOOKUP(dns_protocol, DnsProtocol);

static const char* const dnssec_algorithm_table[_DNSSEC_ALGORITHM_MAX_DEFINED] = {
        [DNSSEC_ALGORITHM_RSAMD5]             = "RSAMD5",
        [DNSSEC_ALGORITHM_DH]                 = "DH",
        [DNSSEC_ALGORITHM_DSA]                = "DSA",
        [DNSSEC_ALGORITHM_ECC]                = "ECC",
        [DNSSEC_ALGORITHM_RSASHA1]            = "RSASHA1",
        [DNSSEC_ALGORITHM_DSA_NSEC3_SHA1]     = "DSA-NSEC3-SHA1",
        [DNSSEC_ALGORITHM_RSASHA1_NSEC3_SHA1] = "RSASHA1-NSEC3-SHA1",
        [DNSSEC_ALGORITHM_INDIRECT]           = "INDIRECT",
        [DNSSEC_ALGORITHM_PRIVATEDNS]         = "PRIVATEDNS",
        [DNSSEC_ALGORITHM_PRIVATEOID]         = "PRIVATEOID",
};
DEFINE_STRING_TABLE_LOOKUP(dnssec_algorithm, int);
