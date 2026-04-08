/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "dhcp-option.h"
#include "hashmap.h"
#include "iovec-util.h"
#include "json-util.h"
#include "memory-util.h"

#define DHCP_MAX_OPTIONS 4096u

static sd_dhcp_option* dhcp_option_free(sd_dhcp_option *o) {
        if (!o)
                return NULL;

        if (!o->option_prev)
                /* If this is the head one, remove all subsequent options. */
                LIST_CLEAR(option, o->option_next, sd_dhcp_option_unref);
        else
                /* Otherwise, remove this option from the list. */
                LIST_REMOVE(option, o->option_prev, o);

        return mfree(o);
}

int sd_dhcp_option_new(uint8_t option, const void *data, size_t length, sd_dhcp_option **ret) {
        assert_return(ret, -EINVAL);
        assert_return(length == 0 || data, -EINVAL);

        if (IN_SET(option, SD_DHCP_OPTION_PAD, SD_DHCP_OPTION_END))
                return -EINVAL;

        if (length > UINT8_MAX)
                return -EINVAL;

        sd_dhcp_option *p = malloc(MAX(sizeof(sd_dhcp_option), offsetof(sd_dhcp_option, data) + length));
        if (!p)
                return -ENOMEM;

        *p = (sd_dhcp_option) {
                .n_ref = 1,
                .option = option,
                .length = length,
        };

        memcpy_safe(p->data, data, length);

        *ret = TAKE_PTR(p);
        return 0;
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp_option, sd_dhcp_option, dhcp_option_free);
DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                dhcp_option_hash_ops,
                void,
                trivial_hash_func,
                trivial_compare_func,
                sd_dhcp_option,
                sd_dhcp_option_unref);

static int dhcp_options_append_impl(Hashmap **options, uint8_t code, uint8_t length, const void *data) {
        int r;

        assert(options);

        if (IN_SET(code, SD_DHCP_OPTION_PAD, SD_DHCP_OPTION_END))
                return -EINVAL;

        _cleanup_(sd_dhcp_option_unrefp) sd_dhcp_option *o = NULL;
        r = sd_dhcp_option_new(code, data, length, &o);
        if (r < 0)
                return r;

        sd_dhcp_option *e = hashmap_get(*options, UINT_TO_PTR(o->option));
        if (e) {
                LIST_APPEND(option, e->option_next, TAKE_PTR(o));
                return 0;
        }

        r = hashmap_ensure_put(options, &dhcp_option_hash_ops, UINT_TO_PTR(o->option), o);
        if (r < 0)
                return r;

        TAKE_PTR(o);
        return 0;
}

int dhcp_options_append(Hashmap **options, uint8_t code, size_t length, const void *data) {
        int r;

        assert(options);
        assert(data || length == 0);

        /* Safety check. Assume not so many options. */
        if (hashmap_size(*options) + DIV_ROUND_UP(length, UINT8_MAX) >= DHCP_MAX_OPTIONS)
                return -E2BIG;

        const uint8_t *p = data;
        while (length > UINT8_MAX) {
                /* If the data is too long, then split it into small pieces. See RFC 3396. */
                r = dhcp_options_append_impl(options, code, UINT8_MAX, p);
                if (r < 0)
                        return r;

                p += UINT8_MAX;
                length -= UINT8_MAX;
        }

        return dhcp_options_append_impl(options, code, length, p);
}

int dhcp_options_append_many(Hashmap **options, Hashmap *src) {
        int r;

        assert(options);

        sd_dhcp_option *o;
        HASHMAP_FOREACH(o, src)
                LIST_FOREACH(option, i, o) {
                        r = dhcp_options_append(options, i->option, i->length, i->data);
                        if (r < 0)
                                return r;
                }

        return 0;
}

int dhcp_options_parse(Hashmap **options, const struct iovec *iov) {
        int r;

        assert(options);
        assert(iov);

        for (struct iovec i = *iov; iovec_is_set(&i);) {
                /* option code */
                uint8_t code = *(uint8_t*) i.iov_base;
                iovec_inc(&i, 1);

                /* PAD and END do not have the length field. */
                if (code == SD_DHCP_OPTION_PAD)
                        continue;
                if (code == SD_DHCP_OPTION_END)
                        break;

                if (!iovec_is_set(&i))
                        return -EBADMSG;

                /* option length */
                uint8_t len = *(uint8_t*) i.iov_base;
                iovec_inc(&i, 1);
                if (len > i.iov_len)
                        return -EBADMSG;

                r = dhcp_options_append(options, code, len, i.iov_base);
                if (r < 0)
                        return r;

                iovec_inc(&i, len);
        }

        return 0;
}

size_t dhcp_options_size(Hashmap *options) {
        sd_dhcp_option *o;
        size_t sz = 1; /* 1 is for SD_DHCP_OPTION_END */
        HASHMAP_FOREACH(o, options)
                LIST_FOREACH(option, i, o)
                        sz += 2 + i->length;

        return sz;
}

int dhcp_options_build(Hashmap *options, struct iovec *ret) {
        int r;

        assert(ret);

        size_t sz = dhcp_options_size(options);
        _cleanup_free_ uint8_t *buf = new(uint8_t, sz);
        if (!buf)
                return -ENOMEM;

        /* Sort options by their option code, for reproducibility. */
        _cleanup_free_ sd_dhcp_option **sorted = NULL;
        size_t n;
        r = hashmap_dump_sorted(options, (void***) &sorted, &n);
        if (r < 0)
                return r;

        uint8_t *p = buf;
        FOREACH_ARRAY(o, sorted, n)
                LIST_FOREACH(option, i, *o)
                        p = mempcpy(p, i->tlv, 2 + i->length);

        *p++ = SD_DHCP_OPTION_END;

        *ret = IOVEC_MAKE(TAKE_PTR(buf), sz);
        return 0;
}

int dhcp_options_build_json(Hashmap *options, sd_json_variant **ret) {
        int r;

        assert(ret);

        /* Sort options by their option code, for reproducibility. */
        _cleanup_free_ sd_dhcp_option **sorted = NULL;
        size_t n;
        r = hashmap_dump_sorted(options, (void***) &sorted, &n);
        if (r < 0)
                return r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        FOREACH_ARRAY(o, sorted, n)
                LIST_FOREACH(option, i, *o) {
                        r = sd_json_variant_append_arraybo(
                                        &v,
                                        SD_JSON_BUILD_PAIR_UNSIGNED("option", i->option),
                                        JSON_BUILD_PAIR_HEX_NON_EMPTY("data", i->data, i->length));
                        if (r < 0)
                                return r;
                }

        *ret = TAKE_PTR(v);
        return 0;
}

typedef struct OptionParam {
        uint8_t option;
        struct iovec data;
} OptionParam;

static void option_param_done(OptionParam *p) {
        iovec_done(&p->data);
}

int dhcp_options_parse_json(sd_json_variant *v, Hashmap **ret) {
        int r;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "option",  _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint8,    offsetof(OptionParam, option), SD_JSON_MANDATORY },
                { "data",    SD_JSON_VARIANT_STRING,        json_dispatch_unhex_iovec, offsetof(OptionParam, data),   0                 },
                {},
        };

        assert(v);
        assert(ret);

        _cleanup_hashmap_free_ Hashmap *options = NULL;
        sd_json_variant *e;
        JSON_VARIANT_ARRAY_FOREACH(e, v) {
                _cleanup_(option_param_done) OptionParam p = {};
                r = sd_json_dispatch(e, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
                if (r < 0)
                        return r;

                if (!iovec_is_valid(&p.data) || p.data.iov_len > UINT8_MAX)
                        return -EINVAL;

                r = dhcp_options_append(&options, p.option, p.data.iov_len, p.data.iov_base);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(options);
        return 0;
}
