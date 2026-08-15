/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "hashmap.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "json-util.h"
#include "tlv-util.h"
#include "unaligned.h"

#define TLV_MAX_ENTRIES 4096u

TLVFlag tlv_flags_verify(TLVFlag flags) {
        assert(IN_SET(flags & _TLV_TAG_MASK, TLV_TAG_U8, TLV_TAG_U16, TLV_TAG_U32));
        assert(IN_SET(flags & _TLV_LENGTH_MASK, TLV_LENGTH_U8, TLV_LENGTH_U16, TLV_LENGTH_U32));

        /* TLV_PAD and TLV_END are for DHCPv4 options, hence here we assume TLV_TAG_U8 is set. */
        assert(!FLAGS_SET(flags, TLV_PAD) || FLAGS_SET(flags, TLV_TAG_U8));
        assert(!FLAGS_SET(flags, TLV_END) || FLAGS_SET(flags, TLV_TAG_U8));

        /* When we requested to append the END tag, then we should understand the END tag on parse. */
        assert(!FLAGS_SET(flags, TLV_APPEND_END) || FLAGS_SET(flags, TLV_END));

        return flags;
}

void tlv_done(TLV *tlv) {
        assert(tlv);

        tlv->entries = hashmap_free(tlv->entries);
        tlv->n_entries = 0;
}

static TLV* tlv_free(TLV *tlv) {
        if (!tlv)
                return NULL;

        tlv_done(tlv);
        return mfree(tlv);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(TLV, tlv, tlv_free);

TLV* tlv_new(TLVFlag flags) {
        TLV *tlv = new(TLV, 1);
        if (!tlv)
                return NULL;

        *tlv = TLV_INIT(flags);
        return tlv;
}

bool tlv_isempty(const TLV *tlv) {
        return !tlv || hashmap_isempty(tlv->entries);
}

struct iovec_wrapper* tlv_get_all(const TLV *tlv, uint32_t tag) {
        assert(tlv);
        return hashmap_get(tlv->entries, UINT32_TO_PTR(tag));
}

int tlv_get_full(const TLV *tlv, uint32_t tag, size_t length, struct iovec *ret) {
        assert(tlv);

        /* Do not free the result iovec, the data is still owned by TLV (or the original input data when
         * TLV_TEMPORARY is set). */

        struct iovec_wrapper *iovw = tlv_get_all(tlv, tag);
        if (iovw_isempty(iovw))
                return -ENODATA;

        /* When multiple entries exist, use the first one matching the length. */
        FOREACH_ARRAY(iov, iovw->iovec, iovw->count) {
                if (length != SIZE_MAX && iov->iov_len != length)
                        continue;

                if (ret)
                        *ret = *iov;
                return 0;
        }

        return -ENODATA;
}

int tlv_get_alloc(const TLV *tlv, uint32_t tag, struct iovec *ret) {
        assert(tlv);

        /* Free the result iovec. */

        struct iovec_wrapper *iovw = tlv_get_all(tlv, tag);
        if (iovw_isempty(iovw))
                return -ENODATA;

        if (!ret)
                return 0;

        if (FLAGS_SET(tlv->flags, TLV_MERGE))
                return iovw_concat(iovw, ret);

        /* When TLV_MERGE is unset, provides the first entry. */
        if (!iovec_memdup(&iovw->iovec[0], ret))
                return -ENOMEM;

        return 0;
}

void tlv_remove(TLV *tlv, uint32_t tag) {
        assert(tlv);

        struct iovec_wrapper *iovw = hashmap_remove(tlv->entries, UINT32_TO_PTR(tag));
        if (!iovw)
                return;

        assert(tlv->n_entries >= iovw->count);
        tlv->n_entries -= iovw->count;

        if (FLAGS_SET(tlv->flags, TLV_TEMPORARY))
                iovw_free(iovw);
        else
                iovw_free_free(iovw);
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                tlv_hash_ops,
                void,
                trivial_hash_func,
                trivial_compare_func,
                struct iovec_wrapper,
                iovw_free);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                tlv_hash_ops_free,
                void,
                trivial_hash_func,
                trivial_compare_func,
                struct iovec_wrapper,
                iovw_free_free);

static int tlv_append_impl(TLV *tlv, uint32_t tag, size_t length, const void *data) {
        int r;

        assert(tlv);
        assert(length == 0 || data);

        if (tlv->n_entries >= TLV_MAX_ENTRIES)
                return -E2BIG;

        if (FLAGS_SET(tlv->flags, TLV_TEMPORARY)) {
                struct iovec_wrapper *e = tlv_get_all(tlv, tag);
                if (e) {
                        r = iovw_put_full(e, /* accept_zero= */ true, (void*) data, length);
                        if (r < 0)
                                return r;
                } else {
                        _cleanup_(iovw_freep) struct iovec_wrapper *v = new0(struct iovec_wrapper, 1);
                        if (!v)
                                return -ENOMEM;

                        r = iovw_put_full(v, /* accept_zero= */ true, (void*) data, length);
                        if (r < 0)
                                return r;

                        r = hashmap_ensure_put(&tlv->entries, &tlv_hash_ops, UINT32_TO_PTR(tag), v);
                        if (r < 0)
                                return r;

                        TAKE_PTR(v);
                }
        } else {
                struct iovec_wrapper *e = tlv_get_all(tlv, tag);
                if (e) {
                        r = iovw_extend_full(e, /* accept_zero= */ true, data, length);
                        if (r < 0)
                                return r;
                } else {
                        _cleanup_(iovw_free_freep) struct iovec_wrapper *v = new0(struct iovec_wrapper, 1);
                        if (!v)
                                return -ENOMEM;

                        r = iovw_extend_full(v, /* accept_zero= */ true, data, length);
                        if (r < 0)
                                return r;

                        r = hashmap_ensure_put(&tlv->entries, &tlv_hash_ops_free, UINT32_TO_PTR(tag), v);
                        if (r < 0)
                                return r;

                        TAKE_PTR(v);
                }
        }

        tlv->n_entries++;
        return 0;
}

int tlv_append(TLV *tlv, uint32_t tag, size_t length, const void *data) {
        int r;

        assert(tlv);
        assert(length == 0 || data);

        switch (tlv->flags & _TLV_TAG_MASK) {
        case TLV_TAG_U8:
                if (tag > UINT8_MAX)
                        return -EINVAL;
                break;
        case TLV_TAG_U16:
                if (tag > UINT16_MAX)
                        return -EINVAL;
                break;
        case TLV_TAG_U32:
                break;
        default:
                assert_not_reached();
        }

        if ((FLAGS_SET(tlv->flags, TLV_PAD) && tag == TLV_TAG_PAD) ||
            (FLAGS_SET(tlv->flags, TLV_END) && tag == TLV_TAG_END))
                return -EINVAL;

        size_t max_length;
        switch (tlv->flags & _TLV_LENGTH_MASK) {
        case TLV_LENGTH_U8:
                max_length = UINT8_MAX;
                break;
        case TLV_LENGTH_U16:
                max_length = UINT16_MAX;
                break;
        case TLV_LENGTH_U32:
                max_length = UINT32_MAX;
                break;
        default:
                assert_not_reached();
        }

        if (FLAGS_SET(tlv->flags, TLV_MERGE)) {
                /* If TLV_MERGE is set and the length is larger than the allowed maximum, then split the data
                 * and store them in multiple entries.
                 *
                 * Note, if tlv_append_impl() fails below, we do not rollback the entries, hence the caller
                 * of this function needs to discard the entire data in that case. */
                const uint8_t *p = data;
                while (length > max_length) {
                        r = tlv_append_impl(tlv, tag, max_length, p);
                        if (r < 0)
                                return r;

                        p += max_length;
                        length -= max_length;
                }

                return tlv_append_impl(tlv, tag, length, p);
        }

        /* Otherwise, refuse too long data. */
        if (length > max_length)
                return -EINVAL;

        return tlv_append_impl(tlv, tag, length, data);
}

int tlv_append_iov(TLV *tlv, uint32_t tag, const struct iovec *iov) {
        assert(tlv);
        assert(iovec_is_valid(iov));

        return tlv_append(tlv, tag, iov ? iov->iov_len : 0, iov ? iov->iov_base : NULL);
}

int tlv_append_tlv(TLV *tlv, const TLV *source) {
        int r;

        assert(tlv);

        /* Note, this does not rollback entries on failure, hence the caller of this function needs to
         * discard the entire data in that case. */

        if (!source)
                return 0;

        if (source == tlv)
                return -EINVAL;

        void *tagp;
        struct iovec_wrapper *iovw;
        HASHMAP_FOREACH_KEY(iovw, tagp, source->entries) {
                uint32_t tag = PTR_TO_UINT32(tagp);

                FOREACH_ARRAY(iov, iovw->iovec, iovw->count) {
                        r = tlv_append(tlv, tag, iov->iov_len, iov->iov_base);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

int tlv_parse(TLV *tlv, const struct iovec *iov) {
        int r;

        assert(tlv);
        assert(iovec_is_valid(iov));

        /* Note, this does not rollback entries on failure, hence the caller of this function needs to
         * discard the entire data in that case. */

        if (!iovec_is_set(iov))
                return 0;

        for (struct iovec i = *iov; iovec_is_set(&i); ) {
                uint32_t tag;
                switch (tlv->flags & _TLV_TAG_MASK) {
                case TLV_TAG_U8:
                        if (i.iov_len < sizeof(uint8_t))
                                return -EBADMSG;
                        tag = *(uint8_t*) i.iov_base;
                        iovec_inc(&i, sizeof(uint8_t));
                        break;
                case TLV_TAG_U16:
                        if (i.iov_len < sizeof(uint16_t))
                                return -EBADMSG;
                        tag = unaligned_read_be16(i.iov_base);
                        iovec_inc(&i, sizeof(uint16_t));
                        break;
                case TLV_TAG_U32:
                        if (i.iov_len < sizeof(uint32_t))
                                return -EBADMSG;
                        tag = unaligned_read_be32(i.iov_base);
                        iovec_inc(&i, sizeof(uint32_t));
                        break;
                default:
                        assert_not_reached();
                }

                if (FLAGS_SET(tlv->flags, TLV_PAD) && tag == TLV_TAG_PAD)
                        continue;
                if (FLAGS_SET(tlv->flags, TLV_END) && tag == TLV_TAG_END)
                        break;

                size_t len;
                switch (tlv->flags & _TLV_LENGTH_MASK) {
                case TLV_LENGTH_U8:
                        if (i.iov_len < sizeof(uint8_t))
                                return -EBADMSG;
                        len = *(uint8_t*) i.iov_base;
                        iovec_inc(&i, sizeof(uint8_t));
                        break;
                case TLV_LENGTH_U16:
                        if (i.iov_len < sizeof(uint16_t))
                                return -EBADMSG;
                        len = unaligned_read_be16(i.iov_base);
                        iovec_inc(&i, sizeof(uint16_t));
                        break;
                case TLV_LENGTH_U32:
                        if (i.iov_len < sizeof(uint32_t))
                                return -EBADMSG;
                        len = unaligned_read_be32(i.iov_base);
                        iovec_inc(&i, sizeof(uint32_t));
                        break;
                default:
                        assert_not_reached();
                }

                if (i.iov_len < len)
                        return -EBADMSG;

                r = tlv_append_impl(tlv, tag, len, i.iov_base);
                if (r < 0)
                        return r;

                iovec_inc(&i, len);
        }

        return 0;
}

size_t tlv_size(const TLV *tlv) {
        assert(tlv);

        size_t header_sz;
        switch (tlv->flags & _TLV_TAG_MASK) {
        case TLV_TAG_U8:
                header_sz = sizeof(uint8_t);
                break;
        case TLV_TAG_U16:
                header_sz = sizeof(uint16_t);
                break;
        case TLV_TAG_U32:
                header_sz = sizeof(uint32_t);
                break;
        default:
                assert_not_reached();
        }

        switch (tlv->flags & _TLV_LENGTH_MASK) {
        case TLV_LENGTH_U8:
                header_sz += sizeof(uint8_t);
                break;
        case TLV_LENGTH_U16:
                header_sz += sizeof(uint16_t);
                break;
        case TLV_LENGTH_U32:
                header_sz += sizeof(uint32_t);
                break;
        default:
                assert_not_reached();
        }

        size_t sz = FLAGS_SET(tlv->flags, TLV_APPEND_END);

        struct iovec_wrapper *iovw;
        HASHMAP_FOREACH(iovw, tlv->entries) {
                if (size_multiply_overflow(header_sz, iovw->count))
                        return SIZE_MAX;

                sz = size_add(sz, size_add(header_sz * iovw->count, iovw_size(iovw)));
        }

        return sz;
}

int tlv_build(const TLV *tlv, struct iovec *ret) {
        int r;

        assert(tlv);
        assert(ret);

        size_t sz = tlv_size(tlv);
        if (sz == SIZE_MAX)
                return -ENOBUFS;

        _cleanup_free_ uint8_t *buf = new(uint8_t, sz);
        if (!buf)
                return -ENOMEM;

        /* Sort by tags, for reproducibility. */
        _cleanup_free_ void **sorted = NULL;
        size_t n;
        r = hashmap_dump_keys_sorted(tlv->entries, &sorted, &n);
        if (r < 0)
                return r;

        uint8_t *p = buf;
        FOREACH_ARRAY(tagp, sorted, n) {
                uint32_t tag = PTR_TO_UINT32(*tagp);
                struct iovec_wrapper *iovw = ASSERT_PTR(tlv_get_all(tlv, tag));

                if ((FLAGS_SET(tlv->flags, TLV_PAD) && tag == TLV_TAG_PAD) ||
                    (FLAGS_SET(tlv->flags, TLV_END) && tag == TLV_TAG_END))
                        return -EINVAL;

                FOREACH_ARRAY(iov, iovw->iovec, iovw->count) {
                        switch (tlv->flags & _TLV_TAG_MASK) {
                        case TLV_TAG_U8:
                                if (tag > UINT8_MAX)
                                        return -EINVAL;
                                *p++ = tag;
                                break;
                        case TLV_TAG_U16:
                                if (tag > UINT16_MAX)
                                        return -EINVAL;
                                unaligned_write_be16(p, tag);
                                p += sizeof(uint16_t);
                                break;
                        case TLV_TAG_U32:
                                unaligned_write_be32(p, tag);
                                p += sizeof(uint32_t);
                                break;
                        default:
                                assert_not_reached();
                        }

                        switch (tlv->flags & _TLV_LENGTH_MASK) {
                        case TLV_LENGTH_U8:
                                if (iov->iov_len > UINT8_MAX)
                                        return -EINVAL;
                                *p++ = iov->iov_len;
                                break;
                        case TLV_LENGTH_U16:
                                if (iov->iov_len > UINT16_MAX)
                                        return -EINVAL;
                                unaligned_write_be16(p, iov->iov_len);
                                p += sizeof(uint16_t);
                                break;
                        case TLV_LENGTH_U32:
                                if (iov->iov_len > UINT32_MAX)
                                        return -EINVAL;
                                unaligned_write_be32(p, iov->iov_len);
                                p += sizeof(uint32_t);
                                break;
                        default:
                                assert_not_reached();
                        }

                        p = mempcpy_safe(p, iov->iov_base, iov->iov_len);
                }
        }

        if (FLAGS_SET(tlv->flags, TLV_APPEND_END))
                *p++ = TLV_TAG_END;

        assert(sz == (size_t) (p - buf));

        *ret = IOVEC_MAKE(TAKE_PTR(buf), sz);
        return 0;
}

int tlv_build_json(const TLV *tlv, sd_json_variant **ret) {
        int r;

        assert(tlv);
        assert(ret);

        /* Sort by tags, for reproducibility. */
        _cleanup_free_ void **sorted = NULL;
        size_t n;
        r = hashmap_dump_keys_sorted(tlv->entries, &sorted, &n);
        if (r < 0)
                return r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        FOREACH_ARRAY(tagp, sorted, n) {
                uint32_t tag = PTR_TO_UINT32(*tagp);
                struct iovec_wrapper *iovw = ASSERT_PTR(tlv_get_all(tlv, tag));

                FOREACH_ARRAY(iov, iovw->iovec, iovw->count) {
                        r = sd_json_variant_append_arraybo(
                                        &v,
                                        SD_JSON_BUILD_PAIR_UNSIGNED("tag", tag),
                                        JSON_BUILD_PAIR_IOVEC_HEX("data", iov));
                        if (r < 0)
                                return r;
                }
        }

        *ret = TAKE_PTR(v);
        return 0;
}

typedef struct TLVParam {
        uint32_t tag;
        struct iovec data;
} TLVParam;

static void tlv_param_done(TLVParam *p) {
        iovec_done(&p->data);
}

int tlv_parse_json(TLV *tlv, sd_json_variant *v) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "tag",  _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint32,   offsetof(TLVParam, tag),  SD_JSON_MANDATORY },
                { "data", SD_JSON_VARIANT_STRING,        json_dispatch_unhex_iovec, offsetof(TLVParam, data), SD_JSON_MANDATORY },
                {},
        };

        int r;

        assert(tlv);
        assert(v);

        sd_json_variant *e;
        JSON_VARIANT_ARRAY_FOREACH(e, v) {
                _cleanup_(tlv_param_done) TLVParam p = {};
                r = sd_json_dispatch(e, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
                if (r < 0)
                        return r;

                r = tlv_append(tlv, p.tag, p.data.iov_len, p.data.iov_base);
                if (r < 0)
                        return r;
        }

        return 0;
}
