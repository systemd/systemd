/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_infiniband.h>
#include <net/ethernet.h>
#include <net/if_arp.h>

#include "dhcp-duid-internal.h"
#include "hexdecoct.h"
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

int sd_dhcp_duid_clear(sd_dhcp_duid *duid) {
        assert_return(duid, -EINVAL);

        *duid = (sd_dhcp_duid) {};
        return 0;
}

int sd_dhcp_duid_is_set(const sd_dhcp_duid *duid) {
        if (!duid)
                return false;

        return duid_size_is_valid(duid->size);
}

int sd_dhcp_duid_get(const sd_dhcp_duid *duid, uint16_t *ret_type, const void **ret_data, size_t *ret_size) {
        assert_return(sd_dhcp_duid_is_set(duid), -EINVAL);
        assert_return(ret_type, -EINVAL);
        assert_return(ret_data, -EINVAL);
        assert_return(ret_size, -EINVAL);

        *ret_type = be16toh(duid->duid.type);
        *ret_data = duid->duid.data;
        *ret_size = duid->size - offsetof(struct duid, data);
        return 0;
}

int sd_dhcp_duid_get_raw(const sd_dhcp_duid *duid, const void **ret_data, size_t *ret_size) {
        assert_return(sd_dhcp_duid_is_set(duid), -EINVAL);
        assert_return(ret_data, -EINVAL);
        assert_return(ret_size, -EINVAL);

        /* Unlike sd_dhcp_duid_get(), this returns whole DUID including its type. */

        *ret_data = duid->raw;
        *ret_size = duid->size;
        return 0;
}

int sd_dhcp_duid_set(
                sd_dhcp_duid *duid,
                uint16_t duid_type,
                const void *data,
                size_t data_size) {

        assert_return(duid, -EINVAL);
        assert_return(data, -EINVAL);
        assert_return(duid_data_size_is_valid(data_size), -EINVAL);

        unaligned_write_be16(&duid->duid.type, duid_type);
        memcpy(duid->duid.data, data, data_size);

        duid->size = offsetof(struct duid, data) + data_size;
        return 0;
}

int sd_dhcp_duid_set_raw(
                sd_dhcp_duid *duid,
                const void *data,
                size_t data_size) {

        assert_return(duid, -EINVAL);
        assert_return(data, -EINVAL);
        assert_return(duid_size_is_valid(data_size), -EINVAL);

        /* Unlike sd_dhcp_duid_set(), this takes whole DUID including its type. */

        memcpy(duid->raw, data, data_size);

        duid->size = data_size;
        return 0;
}

int sd_dhcp_duid_set_llt(
                sd_dhcp_duid *duid,
                const void *hw_addr,
                size_t hw_addr_size,
                uint16_t arp_type,
                uint64_t usec) {

        uint16_t time_from_2000y;

        assert_return(duid, -EINVAL);
        assert_return(hw_addr, -EINVAL);

        if (arp_type == ARPHRD_ETHER)
                assert_return(hw_addr_size == ETH_ALEN, -EINVAL);
        else if (arp_type == ARPHRD_INFINIBAND)
                assert_return(hw_addr_size == INFINIBAND_ALEN, -EINVAL);
        else
                return -EOPNOTSUPP;

        time_from_2000y = (uint16_t) ((usec_sub_unsigned(usec, USEC_2000) / USEC_PER_SEC) & 0xffffffff);

        unaligned_write_be16(&duid->duid.type, SD_DUID_TYPE_LLT);
        unaligned_write_be16(&duid->duid.llt.htype, arp_type);
        unaligned_write_be32(&duid->duid.llt.time, time_from_2000y);
        memcpy(duid->duid.llt.haddr, hw_addr, hw_addr_size);

        duid->size = offsetof(struct duid, llt.haddr) + hw_addr_size;
        return 0;
}

int sd_dhcp_duid_set_ll(
                sd_dhcp_duid *duid,
                const void *hw_addr,
                size_t hw_addr_size,
                uint16_t arp_type) {

        assert_return(duid, -EINVAL);
        assert_return(hw_addr, -EINVAL);

        if (arp_type == ARPHRD_ETHER)
                assert_return(hw_addr_size == ETH_ALEN, -EINVAL);
        else if (arp_type == ARPHRD_INFINIBAND)
                assert_return(hw_addr_size == INFINIBAND_ALEN, -EINVAL);
        else
                return -EOPNOTSUPP;

        unaligned_write_be16(&duid->duid.type, SD_DUID_TYPE_LL);
        unaligned_write_be16(&duid->duid.ll.htype, arp_type);
        memcpy(duid->duid.ll.haddr, hw_addr, hw_addr_size);

        duid->size = offsetof(struct duid, ll.haddr) + hw_addr_size;
        return 0;
}

int sd_dhcp_duid_set_en(sd_dhcp_duid *duid) {
        sd_id128_t machine_id;
        bool test_mode;
        uint64_t hash;
        int r;

        assert_return(duid, -EINVAL);

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

        unaligned_write_be16(&duid->duid.type, SD_DUID_TYPE_EN);
        unaligned_write_be32(&duid->duid.en.pen, SYSTEMD_PEN);

        /* a bit of snake-oil perhaps, but no need to expose the machine-id
         * directly; duid->en.id might not be aligned, so we need to copy */
        hash = htole64(siphash24(&machine_id, sizeof(machine_id), HASH_KEY.bytes));
        memcpy(duid->duid.en.id, &hash, sizeof(hash));

        duid->size = offsetof(struct duid, en.id) + sizeof(hash);

        if (test_mode)
                assert_se(memcmp(&duid->duid, (const uint8_t[]) { 0x00, 0x02, 0x00, 0x00, 0xab, 0x11, 0x61, 0x77, 0x40, 0xde, 0x13, 0x42, 0xc3, 0xa2 }, duid->size) == 0);

        return 0;
}

int sd_dhcp_duid_set_uuid(sd_dhcp_duid *duid) {
        sd_id128_t machine_id;
        int r;

        assert_return(duid, -EINVAL);

        r = sd_id128_get_machine_app_specific(APPLICATION_ID, &machine_id);
        if (r < 0)
                return r;

        unaligned_write_be16(&duid->duid.type, SD_DUID_TYPE_UUID);
        memcpy(&duid->duid.uuid.uuid, &machine_id, sizeof(machine_id));

        duid->size = offsetof(struct duid, uuid.uuid) + sizeof(machine_id);
        return 0;
}

int dhcp_duid_to_string_internal(uint16_t type, const void *data, size_t data_size, char **ret) {
        _cleanup_free_ char *p = NULL, *x = NULL;
        const char *t;

        assert(data);
        assert(duid_data_size_is_valid(data_size));
        assert(ret);

        x = hexmem(data, data_size);
        if (!x)
                return -ENOMEM;

        t = duid_type_to_string(type);
        if (!t)
                return asprintf(ret, "%04x:%s", htobe16(type), x);

        p = strjoin(t, ":", x);
        if (!p)
                return -ENOMEM;

        *ret = TAKE_PTR(p);
        return 0;
}

int sd_dhcp_duid_to_string(const sd_dhcp_duid *duid, char **ret) {
        uint16_t type;
        const void *data;
        size_t data_size;
        int r;

        assert_return(sd_dhcp_duid_is_set(duid), -EINVAL);
        assert_return(ret, -EINVAL);

        r = sd_dhcp_duid_get(duid, &type, &data, &data_size);
        if (r < 0)
                return r;

        return dhcp_duid_to_string_internal(type, data, data_size, ret);
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
