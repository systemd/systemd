/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-dhcp-protocol.h"

#include "hashmap.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "random-util.h"
#include "tests.h"
#include "tlv-util.h"

TEST(tlv_constant) {
        ASSERT_EQ(TLV_TAG_PAD, (uint32_t) SD_DHCP_OPTION_PAD);
        ASSERT_EQ(TLV_TAG_END, (uint32_t) SD_DHCP_OPTION_END);
}

TEST(tlv) {
        _cleanup_(tlv_done) TLV tlv = TLV_INIT(TLV_DHCP4);

        _cleanup_(iovec_done) struct iovec data0 = {}, data1 = {}, data2a = {}, data2b = {}, data3 = {}, data4 = {};
        ASSERT_OK(random_bytes_allocate_iovec(0, &data0));
        ASSERT_OK(random_bytes_allocate_iovec(111, &data1));
        ASSERT_OK(random_bytes_allocate_iovec(123, &data2a));
        ASSERT_OK(random_bytes_allocate_iovec(321, &data2b));
        ASSERT_OK(random_bytes_allocate_iovec(333, &data3));
        ASSERT_OK(random_bytes_allocate_iovec(444, &data4));

        /* tlv_append() */
        ASSERT_OK(tlv_append(&tlv, 10, data0.iov_len, data0.iov_base));
        ASSERT_OK(tlv_append(&tlv, 11, data1.iov_len, data1.iov_base));
        ASSERT_OK(tlv_append(&tlv, 22, data2a.iov_len, data2a.iov_base));
        ASSERT_OK(tlv_append(&tlv, 22, data2b.iov_len, data2b.iov_base));
        ASSERT_OK(tlv_append(&tlv, 33, data3.iov_len, data3.iov_base));
        ASSERT_OK(tlv_append(&tlv, 44, data4.iov_len, data4.iov_base));
        ASSERT_ERROR(tlv_append(&tlv, 0x00, data4.iov_len, data4.iov_base), EINVAL);
        ASSERT_ERROR(tlv_append(&tlv, 0xFF, data4.iov_len, data4.iov_base), EINVAL);
        ASSERT_EQ(hashmap_size(tlv.entries), 5u);

        /* tlv_remove() */
        tlv_remove(&tlv, 44);
        ASSERT_EQ(hashmap_size(tlv.entries), 4u);
        tlv_remove(&tlv, 55);
        ASSERT_EQ(hashmap_size(tlv.entries), 4u);

        /* tlv_append_tlv() */
        _cleanup_(tlv_done) TLV tlv_copy = TLV_INIT(TLV_DHCP4);
        ASSERT_ERROR(tlv_append_tlv(&tlv_copy, &tlv_copy), EINVAL);
        ASSERT_OK(tlv_append_tlv(&tlv_copy, NULL));
        ASSERT_OK(tlv_append_tlv(&tlv_copy, &tlv));
        ASSERT_EQ(hashmap_size(tlv_copy.entries), hashmap_size(tlv.entries));

        /* tlv_isempty() */
        ASSERT_TRUE(tlv_isempty(NULL));
        ASSERT_TRUE(tlv_isempty(&TLV_INIT(TLV_DHCP4)));
        ASSERT_FALSE(tlv_isempty(&tlv));

        /* tlv_contains() */
        ASSERT_TRUE(tlv_contains(&tlv, 10));
        ASSERT_TRUE(tlv_contains(&tlv, 11));
        ASSERT_TRUE(tlv_contains(&tlv, 22));
        ASSERT_TRUE(tlv_contains(&tlv, 33));
        ASSERT_FALSE(tlv_contains(&tlv, 44));

        /* tlv_get_all() */
        struct iovec_wrapper *iovw;

        iovw = ASSERT_NOT_NULL(tlv_get_all(&tlv, 10));
        ASSERT_EQ(iovw->count, 1u);
        ASSERT_TRUE(iovec_equal(&iovw->iovec[0], &data0));

        iovw = ASSERT_NOT_NULL(tlv_get_all(&tlv, 11));
        ASSERT_EQ(iovw->count, 1u);
        ASSERT_TRUE(iovec_equal(&iovw->iovec[0], &data1));

        iovw = ASSERT_NOT_NULL(tlv_get_all(&tlv, 22));
        ASSERT_EQ(iovw->count, 3u);
        ASSERT_TRUE(iovec_equal(&iovw->iovec[0], &data2a));
        ASSERT_TRUE(iovec_equal(&iovw->iovec[1], &IOVEC_MAKE(data2b.iov_base, UINT8_MAX)));
        ASSERT_TRUE(iovec_equal(&iovw->iovec[2], &IOVEC_SHIFT(&data2b, UINT8_MAX)));

        iovw = ASSERT_NOT_NULL(tlv_get_all(&tlv, 33));
        ASSERT_EQ(iovw->count, 2u);
        ASSERT_TRUE(iovec_equal(&iovw->iovec[0], &IOVEC_MAKE(data3.iov_base, UINT8_MAX)));
        ASSERT_TRUE(iovec_equal(&iovw->iovec[1], &IOVEC_SHIFT(&data3, UINT8_MAX)));

        ASSERT_NULL(tlv_get_all(&tlv, 44));

        /* tlv_get_full() */
        struct iovec iov;

        ASSERT_OK(tlv_get(&tlv, 10, &iov));
        ASSERT_TRUE(iovec_equal(&iov, &data0));
        ASSERT_OK(tlv_get_full(&tlv, 10, data0.iov_len, &iov));
        ASSERT_TRUE(iovec_equal(&iov, &data0));
        ASSERT_ERROR(tlv_get_full(&tlv, 10, 123, &iov), ENODATA);

        ASSERT_OK(tlv_get(&tlv, 11, &iov));
        ASSERT_TRUE(iovec_equal(&iov, &data1));
        ASSERT_OK(tlv_get_full(&tlv, 11, data1.iov_len, &iov));
        ASSERT_TRUE(iovec_equal(&iov, &data1));
        ASSERT_ERROR(tlv_get_full(&tlv, 11, 123, &iov), ENODATA);

        ASSERT_OK(tlv_get(&tlv, 22, &iov));
        ASSERT_TRUE(iovec_equal(&iov, &data2a));
        ASSERT_OK(tlv_get_full(&tlv, 22, data2a.iov_len, &iov));
        ASSERT_TRUE(iovec_equal(&iov, &data2a));
        ASSERT_ERROR(tlv_get_full(&tlv, 22, data2b.iov_len, &iov), ENODATA);
        ASSERT_OK(tlv_get_full(&tlv, 22, UINT8_MAX, &iov));
        ASSERT_TRUE(iovec_equal(&iov, &IOVEC_MAKE(data2b.iov_base, UINT8_MAX)));
        ASSERT_OK(tlv_get_full(&tlv, 22, data2b.iov_len - UINT8_MAX, &iov));
        ASSERT_TRUE(iovec_equal(&iov, &IOVEC_SHIFT(&data2b, UINT8_MAX)));

        ASSERT_OK(tlv_get(&tlv, 33, &iov));
        ASSERT_TRUE(iovec_equal(&iov, &IOVEC_MAKE(data3.iov_base, UINT8_MAX)));
        ASSERT_ERROR(tlv_get_full(&tlv, 33, data3.iov_len, &iov), ENODATA);
        ASSERT_OK(tlv_get_full(&tlv, 33, UINT8_MAX, &iov));
        ASSERT_TRUE(iovec_equal(&iov, &IOVEC_MAKE(data3.iov_base, UINT8_MAX)));
        ASSERT_OK(tlv_get_full(&tlv, 33, data3.iov_len - UINT8_MAX, &iov));
        ASSERT_TRUE(iovec_equal(&iov, &IOVEC_SHIFT(&data3, UINT8_MAX)));

        ASSERT_ERROR(tlv_get(&tlv, 44, NULL), ENODATA);

        /* tlv_get_alloc() */
        _cleanup_(iovec_done) struct iovec v = {};

        ASSERT_OK(tlv_get_alloc(&tlv, 10, &v));
        ASSERT_TRUE(iovec_equal(&v, &data0));
        iovec_done(&v);

        ASSERT_OK(tlv_get_alloc(&tlv, 11, &v));
        ASSERT_TRUE(iovec_equal(&v, &data1));
        iovec_done(&v);

        ASSERT_OK(tlv_get_alloc(&tlv, 22, &v));
        ASSERT_EQ(v.iov_len, data2a.iov_len + data2b.iov_len);
        ASSERT_EQ(memcmp(v.iov_base, data2a.iov_base, data2a.iov_len), 0);
        ASSERT_EQ(memcmp((uint8_t*) v.iov_base + data2a.iov_len, data2b.iov_base, data2b.iov_len), 0);
        iovec_done(&v);

        ASSERT_OK(tlv_get_alloc(&tlv, 33, &v));
        ASSERT_TRUE(iovec_equal(&v, &data3));
        iovec_done(&v);

        ASSERT_ERROR(tlv_get_alloc(&tlv, 44, NULL), ENODATA);

        /* tlv_size() */
        size_t sz = tlv_size(&tlv);
        /* The tlv contains the 7 entries with a 2-byte header:
         * tag 10: 1 entry, tag 11: 1 entry, tag 22: 3 entries, tag 33: 2 entries = 7 entries total. */
        ASSERT_EQ(sz, 7 * 2 + data0.iov_len + data1.iov_len + data2a.iov_len + data2b.iov_len + data3.iov_len + 1);

        /* tlv_build() */
        ASSERT_OK(tlv_build(&tlv, &v));
        ASSERT_EQ(v.iov_len, sz);
        uint8_t *p = v.iov_base;
        ASSERT_EQ(*p++, 10u);
        ASSERT_EQ(*p++, data0.iov_len);

        ASSERT_EQ(*p++, 11u);
        ASSERT_EQ(*p++, data1.iov_len);
        ASSERT_EQ(memcmp(p, data1.iov_base, data1.iov_len), 0);
        p += data1.iov_len;

        ASSERT_EQ(*p++, 22u);
        ASSERT_EQ(*p++, data2a.iov_len);
        ASSERT_EQ(memcmp(p, data2a.iov_base, data2a.iov_len), 0);
        p += data2a.iov_len;

        ASSERT_EQ(*p++, 22u);
        ASSERT_EQ(*p++, UINT8_MAX);
        ASSERT_EQ(memcmp(p, data2b.iov_base, UINT8_MAX), 0);
        p += UINT8_MAX;

        ASSERT_EQ(*p++, 22u);
        ASSERT_EQ(*p++, data2b.iov_len - UINT8_MAX);
        ASSERT_EQ(memcmp(p, (uint8_t*) data2b.iov_base + UINT8_MAX, data2b.iov_len - UINT8_MAX), 0);
        p += data2b.iov_len - UINT8_MAX;

        ASSERT_EQ(*p++, 33u);
        ASSERT_EQ(*p++, UINT8_MAX);
        ASSERT_EQ(memcmp(p, data3.iov_base, UINT8_MAX), 0);
        p += UINT8_MAX;

        ASSERT_EQ(*p++, 33u);
        ASSERT_EQ(*p++, data3.iov_len - UINT8_MAX);
        ASSERT_EQ(memcmp(p, (uint8_t*) data3.iov_base + UINT8_MAX, data3.iov_len - UINT8_MAX), 0);
        p += data3.iov_len - UINT8_MAX;

        ASSERT_EQ(*p, 255u);

        /* tlv_new() and tlv_parse() */
        _cleanup_(tlv_unrefp) TLV *tlv2 = ASSERT_NOT_NULL(tlv_new(TLV_DHCP4 | TLV_TEMPORARY));
        ASSERT_OK(tlv_parse(tlv2, &v));
        ASSERT_EQ(hashmap_size(tlv.entries), hashmap_size(tlv2->entries));
        void *tagp;
        HASHMAP_FOREACH_KEY(iovw, tagp, tlv.entries) {
                struct iovec_wrapper *iovw2 = ASSERT_PTR(hashmap_get(tlv2->entries, tagp));
                ASSERT_TRUE(iovw_equal(iovw, iovw2));
        }

        /* tlv_build() again, and check the reproducibility. */
        _cleanup_(iovec_done) struct iovec v2 = {};
        ASSERT_OK(tlv_build(tlv2, &v2));
        ASSERT_TRUE(iovec_equal(&v, &v2));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
