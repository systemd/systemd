/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_infiniband.h>
#include <net/ethernet.h>
#include <net/if_arp.h>

#include "dhcp-identifier.h"
#include "netif-util.h"
#include "network-common.h"
#include "siphash24.h"
#include "string-table.h"
#include "unaligned.h"

#define HASH_KEY       SD_ID128_MAKE(80,11,8c,c2,fe,4a,03,ee,3e,d6,0c,6f,36,39,14,09)
#define APPLICATION_ID SD_ID128_MAKE(a5,0a,d1,12,bf,60,45,77,a2,fb,74,1a,b1,95,5b,03)
#define USEC_2000       ((usec_t) 946684800000000) /* 2000-01-01 00:00:00 UTC */

static const char * const duid_type_table[_DUID_TYPE_MAX] = {
        [DUID_TYPE_LLT]  = "DUID-LLT",
        [DUID_TYPE_EN]   = "DUID-EN/Vendor",
        [DUID_TYPE_LL]   = "DUID-LL",
        [DUID_TYPE_UUID] = "UUID",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(duid_type, DUIDType);

int dhcp_identifier_set_duid_llt(
                const struct hw_addr_data *hw_addr,
                uint16_t arp_type,
                usec_t t,
                struct duid *ret_duid,
                size_t *ret_len) {

        uint16_t time_from_2000y;

        assert(hw_addr);
        assert(ret_duid);
        assert(ret_len);

        if (hw_addr->length == 0)
                return -EOPNOTSUPP;

        if (arp_type == ARPHRD_ETHER)
                assert_return(hw_addr->length == ETH_ALEN, -EINVAL);
        else if (arp_type == ARPHRD_INFINIBAND)
                assert_return(hw_addr->length == INFINIBAND_ALEN, -EINVAL);
        else
                return -EOPNOTSUPP;

        if (t < USEC_2000)
                time_from_2000y = 0;
        else
                time_from_2000y = (uint16_t) (((t - USEC_2000) / USEC_PER_SEC) & 0xffffffff);

        unaligned_write_be16(&ret_duid->type, DUID_TYPE_LLT);
        unaligned_write_be16(&ret_duid->llt.htype, arp_type);
        unaligned_write_be32(&ret_duid->llt.time, time_from_2000y);
        memcpy(ret_duid->llt.haddr, hw_addr->bytes, hw_addr->length);

        *ret_len = offsetof(struct duid, llt.haddr) + hw_addr->length;

        return 0;
}

int dhcp_identifier_set_duid_ll(
                const struct hw_addr_data *hw_addr,
                uint16_t arp_type,
                struct duid *ret_duid,
                size_t *ret_len) {

        assert(hw_addr);
        assert(ret_duid);
        assert(ret_len);

        if (hw_addr->length == 0)
                return -EOPNOTSUPP;

        if (arp_type == ARPHRD_ETHER)
                assert_return(hw_addr->length == ETH_ALEN, -EINVAL);
        else if (arp_type == ARPHRD_INFINIBAND)
                assert_return(hw_addr->length == INFINIBAND_ALEN, -EINVAL);
        else
                return -EOPNOTSUPP;

        unaligned_write_be16(&ret_duid->type, DUID_TYPE_LL);
        unaligned_write_be16(&ret_duid->ll.htype, arp_type);
        memcpy(ret_duid->ll.haddr, hw_addr->bytes, hw_addr->length);

        *ret_len = offsetof(struct duid, ll.haddr) + hw_addr->length;

        return 0;
}

int dhcp_identifier_set_duid_en(struct duid *ret_duid, size_t *ret_len) {
        sd_id128_t machine_id;
        bool test_mode;
        uint64_t hash;
        int r;

        assert(ret_duid);
        assert(ret_len);

        test_mode = network_test_mode_enabled();

        if (!test_mode) {
                r = sd_id128_get_machine(&machine_id);
                if (r < 0)
                        return r;
        } else
                /* For tests, especially for fuzzers, reproducibility is important.
                 * Hence, use a static and constant machine ID.
                 * See 9216fddc5a8ac2742e6cfa7660f95c20ca4f2193. */
                machine_id = SD_ID128_MAKE(01, 02, 03, 04, 05, 06, 07, 08, 09, 0a, 0b, 0c, 0d, 0e, 0f, 10);

        unaligned_write_be16(&ret_duid->type, DUID_TYPE_EN);
        unaligned_write_be32(&ret_duid->en.pen, SYSTEMD_PEN);

        /* a bit of snake-oil perhaps, but no need to expose the machine-id
         * directly; duid->en.id might not be aligned, so we need to copy */
        hash = htole64(siphash24(&machine_id, sizeof(machine_id), HASH_KEY.bytes));
        memcpy(ret_duid->en.id, &hash, sizeof(hash));

        *ret_len = offsetof(struct duid, en.id) + sizeof(hash);

        if (test_mode)
                assert_se(memcmp(ret_duid, (const uint8_t[]) { 0x00, 0x02, 0x00, 0x00, 0xab, 0x11, 0x61, 0x77, 0x40, 0xde, 0x13, 0x42, 0xc3, 0xa2 }, *ret_len) == 0);

        return 0;
}

int dhcp_identifier_set_duid_uuid(struct duid *ret_duid, size_t *ret_len) {
        sd_id128_t machine_id;
        int r;

        assert(ret_duid);
        assert(ret_len);

        r = sd_id128_get_machine_app_specific(APPLICATION_ID, &machine_id);
        if (r < 0)
                return r;

        unaligned_write_be16(&ret_duid->type, DUID_TYPE_UUID);
        memcpy(&ret_duid->uuid.uuid, &machine_id, sizeof(machine_id));

        *ret_len = offsetof(struct duid, uuid.uuid) + sizeof(machine_id);

        return 0;
}

int dhcp_identifier_set_duid_raw(
                DUIDType duid_type,
                const uint8_t *buf,
                size_t buf_len,
                struct duid *ret_duid,
                size_t *ret_len) {

        assert(buf || buf_len == 0);
        assert(ret_duid);
        assert(ret_len);

        if (duid_type < 0 || duid_type > UINT16_MAX)
                return -EINVAL;

        if (buf_len > MAX_DUID_DATA_LEN)
                return -EINVAL;

        unaligned_write_be16(&ret_duid->type, duid_type);
        memcpy_safe(ret_duid->raw.data, buf, buf_len);

        *ret_len = offsetof(struct duid, raw.data) + buf_len;
        return 0;
}

int dhcp_identifier_set_iaid(
                sd_device *dev,
                const struct hw_addr_data *hw_addr,
                bool legacy_unstable_byteorder,
                void *ret) {

        const char *name = NULL;
        uint32_t id32;
        uint64_t id;

        assert(hw_addr);
        assert(ret);

        if (dev)
                name = net_get_persistent_name(dev);
        if (name)
                id = siphash24(name, strlen(name), HASH_KEY.bytes);
        else
                /* fall back to MAC address if no predictable name available */
                id = siphash24(hw_addr->bytes, hw_addr->length, HASH_KEY.bytes);

        id32 = (id & 0xffffffff) ^ (id >> 32);

        if (legacy_unstable_byteorder)
                /* for historical reasons (a bug), the bits were swapped and thus
                 * the result was endianness dependent. Preserve that behavior. */
                id32 = bswap_32(id32);
        else
                /* the fixed behavior returns a stable byte order. Since LE is expected
                 * to be more common, swap the bytes on LE to give the same as legacy
                 * behavior. */
                id32 = be32toh(id32);

        unaligned_write_ne32(ret, id32);
        return 0;
}
