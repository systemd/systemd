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

#include "resolved-dns-domain.h"
#include "resolved-dns-packet.h"

int dns_packet_new(DnsPacket **ret, size_t mtu) {
        DnsPacket *p;
        size_t a;

        assert(ret);

        if (mtu <= 0)
                a = DNS_PACKET_SIZE_START;
        else
                a = mtu;

        if (a < DNS_PACKET_HEADER_SIZE)
                a = DNS_PACKET_HEADER_SIZE;

        p = malloc0(ALIGN(sizeof(DnsPacket)) + a);
        if (!p)
                return -ENOMEM;

        p->size = p->rindex = DNS_PACKET_HEADER_SIZE;
        p->allocated = a;
        p->n_ref = 1;

        *ret = p;

        return 0;
}

int dns_packet_new_query(DnsPacket **ret, size_t mtu) {
        DnsPacket *p;
        DnsPacketHeader *h;
        int r;

        assert(ret);

        r = dns_packet_new(&p, mtu);
        if (r < 0)
                return r;

        h = DNS_PACKET_HEADER(p);
        h->flags = htobe16(DNS_PACKET_MAKE_FLAGS(0, 0, 0, 0, 1, 0, 0, 0, 0));

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

        while ((s = hashmap_steal_first_key(p->names)))
                free(s);
        hashmap_free(p->names);

        free(p->data);
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

        return 0;
}

int dns_packet_validate_reply(DnsPacket *p) {
        DnsPacketHeader *h;
        int r;

        assert(p);

        r = dns_packet_validate(p);
        if (r < 0)
                return r;

        h = DNS_PACKET_HEADER(p);

        /* Check QR field */
        if ((be16toh(h->flags) & 1) == 0)
                return -EBADMSG;

        /* Check opcode field */
        if (((be16toh(h->flags) >> 1) & 15) != 0)
                return -EBADMSG;

        return 0;
}

static int dns_packet_extend(DnsPacket *p, size_t add, void **ret, size_t *start) {
        assert(p);

        if (p->size + add > p->allocated)
                return -ENOMEM;

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

        HASHMAP_FOREACH_KEY(s, n, p->names, i) {

                if (PTR_TO_SIZE(n) < sz)
                        continue;

                hashmap_remove(p->names, s);
                free(s);
        }

        p->size = sz;
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

        ((uint8_t*) d)[0] = (uint8_t) (v >> 8);
        ((uint8_t*) d)[1] = (uint8_t) (v & 255);

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

int dns_packet_append_name(DnsPacket *p, const char *name, size_t *start) {
        size_t saved_size;
        int r;

        assert(p);
        assert(name);

        saved_size = p->size;

        while (*name) {
                _cleanup_free_ char *s = NULL;
                char label[DNS_LABEL_MAX];
                size_t n;

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

                r = dns_packet_append_label(p, label, r, &n);
                if (r < 0)
                        goto fail;

                r = hashmap_ensure_allocated(&p->names, dns_name_hash_func, dns_name_compare_func);
                if (r < 0)
                        goto fail;

                r = hashmap_put(p->names, s, SIZE_TO_PTR(n));
                if (r < 0)
                        goto fail;

                s = NULL;
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

        r = dns_packet_append_name(p, k->name, NULL);
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

static void dns_packet_rewind(DnsPacket *p, size_t idx) {
        assert(p);
        assert(idx <= p->size);
        assert(idx >= DNS_PACKET_HEADER_SIZE);

        p->rindex = idx;
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

        *ret = (((uint16_t) ((uint8_t*) d)[0]) << 8) |
                ((uint16_t) ((uint8_t*) d)[1]);
        return 0;
}

int dns_packet_read_uint32(DnsPacket *p, uint32_t *ret, size_t *start) {
        const void *d;
        int r;

        assert(p);

        r = dns_packet_read(p, sizeof(uint32_t), &d, start);
        if (r < 0)
                return r;

        *ret = (((uint32_t) ((uint8_t*) d)[0]) << 24) |
               (((uint32_t) ((uint8_t*) d)[1]) << 16) |
               (((uint32_t) ((uint8_t*) d)[2]) << 8) |
                ((uint32_t) ((uint8_t*) d)[3]);

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

int dns_packet_read_name(DnsPacket *p, char **_ret, size_t *start) {
        size_t saved_rindex, after_rindex = 0;
        _cleanup_free_ char *ret = NULL;
        size_t n = 0, allocated = 0;
        bool first = true;
        int r;

        assert(p);
        assert(_ret);

        saved_rindex = p->rindex;

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

                        memcpy(ret + n, t, c);
                        n += r;
                        continue;
                } else if ((c & 0xc0) == 0xc0) {
                        uint16_t ptr;

                        /* Pointer */
                        r = dns_packet_read_uint8(p, &d, NULL);
                        if (r < 0)
                                goto fail;

                        ptr = (uint16_t) (c & ~0xc0) << 8 | (uint16_t) d;
                        if (ptr < DNS_PACKET_HEADER_SIZE || ptr >= saved_rindex) {
                                r = -EBADMSG;
                                goto fail;
                        }

                        if (after_rindex == 0)
                                after_rindex = p->rindex;

                        p->rindex = ptr;
                } else
                        goto fail;
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

int dns_packet_read_key(DnsPacket *p, DnsResourceKey *ret, size_t *start) {
        _cleanup_(dns_resource_key_free) DnsResourceKey k = {};
        size_t saved_rindex;
        int r;

        assert(p);
        assert(ret);

        saved_rindex = p->rindex;

        r = dns_packet_read_name(p, &k.name, NULL);
        if (r < 0)
                goto fail;

        r = dns_packet_read_uint16(p, &k.type, NULL);
        if (r < 0)
                goto fail;

        r = dns_packet_read_uint16(p, &k.class, NULL);
        if (r < 0)
                goto fail;

        *ret = k;
        zero(k);

        if (start)
                *start = saved_rindex;

        return 0;
fail:
        dns_packet_rewind(p, saved_rindex);
        return r;
}

int dns_packet_read_rr(DnsPacket *p, DnsResourceRecord **ret, size_t *start) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr;
        size_t saved_rindex, offset;
        uint16_t rdlength;
        const void *d;
        int r;

        assert(p);
        assert(ret);

        rr = dns_resource_record_new();
        if (!rr)
                return -ENOMEM;

        saved_rindex = p->rindex;

        r = dns_packet_read_key(p, &rr->key, NULL);
        if (r < 0)
                goto fail;

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

        switch (rr->key.type) {

        case DNS_TYPE_PTR:
        case DNS_TYPE_NS:
        case DNS_TYPE_CNAME:
                r = dns_packet_read_name(p, &rr->ptr.name, NULL);
                break;

        case DNS_TYPE_HINFO:
                r = dns_packet_read_string(p, &rr->hinfo.cpu, NULL);
                if (r < 0)
                        goto fail;

                r = dns_packet_read_string(p, &rr->hinfo.os, NULL);
                break;

        case DNS_TYPE_A:
                r = dns_packet_read(p, sizeof(struct in_addr), &d, NULL);
                if (r < 0)
                        goto fail;

                memcpy(&rr->a.in_addr, d, sizeof(struct in_addr));
                break;

        case DNS_TYPE_AAAA:
                r = dns_packet_read(p, sizeof(struct in6_addr), &d, NULL);
                if (r < 0)
                        goto fail;

                memcpy(&rr->aaaa.in6_addr, d, sizeof(struct in6_addr));
                break;

        default:
                r = dns_packet_read(p, rdlength, &d, NULL);
                if (r < 0)
                        goto fail;

                rr->generic.data = memdup(d, rdlength);
                if (!rr->generic.data) {
                        r = -ENOMEM;
                        goto fail;
                }

                rr->generic.size = rdlength;
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

int dns_packet_skip_question(DnsPacket *p) {
        int r;

        unsigned i, n;
        assert(p);

        n = be16toh(DNS_PACKET_HEADER(p)->qdcount);
        for (i = 0; i < n; i++) {
                _cleanup_(dns_resource_key_free) DnsResourceKey key = {};

                r = dns_packet_read_key(p, &key, NULL);
                if (r < 0)
                        return r;
        }

        return 0;
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
