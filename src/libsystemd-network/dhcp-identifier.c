/* SPDX-License-Identifier: LGPL-2.1+ */

#include <linux/if_infiniband.h>
#include <net/if_arp.h>

#include "sd-device.h"
#include "sd-id128.h"

#include "dhcp-identifier.h"
#include "dhcp6-protocol.h"
#include "network-internal.h"
#include "siphash24.h"
#include "sparse-endian.h"
#include "stdio-util.h"
#include "udev-util.h"
#include "virt.h"

#define SYSTEMD_PEN    43793
#define HASH_KEY       SD_ID128_MAKE(80,11,8c,c2,fe,4a,03,ee,3e,d6,0c,6f,36,39,14,09)
#define APPLICATION_ID SD_ID128_MAKE(a5,0a,d1,12,bf,60,45,77,a2,fb,74,1a,b1,95,5b,03)
#define USEC_2000       ((usec_t) 946684800000000) /* 2000-01-01 00:00:00 UTC */

int dhcp_validate_duid_len(uint16_t duid_type, size_t duid_len, bool strict) {
        struct duid d;

        assert_cc(sizeof(d.raw) >= MAX_DUID_LEN);
        if (duid_len > MAX_DUID_LEN)
                return -EINVAL;

        if (!strict) {
                /* Strict validation is not requested. We only ensure that the
                 * DUID is not too long. */
                return 0;
        }

        switch (duid_type) {
        case DUID_TYPE_LLT:
                if (duid_len <= sizeof(d.llt))
                        return -EINVAL;
                break;
        case DUID_TYPE_EN:
                if (duid_len != sizeof(d.en))
                        return -EINVAL;
                break;
        case DUID_TYPE_LL:
                if (duid_len <= sizeof(d.ll))
                        return -EINVAL;
                break;
        case DUID_TYPE_UUID:
                if (duid_len != sizeof(d.uuid))
                        return -EINVAL;
                break;
        default:
                /* accept unknown type in order to be forward compatible */
                break;
        }
        return 0;
}

int dhcp_identifier_set_duid_llt(struct duid *duid, usec_t t, const uint8_t *addr, size_t addr_len, uint16_t arp_type, size_t *len) {
        uint16_t time_from_2000y;

        assert(duid);
        assert(len);
        assert(addr);

        if (arp_type == ARPHRD_ETHER)
                assert_return(addr_len == ETH_ALEN, -EINVAL);
        else if (arp_type == ARPHRD_INFINIBAND)
                assert_return(addr_len == INFINIBAND_ALEN, -EINVAL);
        else
                return -EINVAL;

        if (t < USEC_2000)
                time_from_2000y = 0;
        else
                time_from_2000y = (uint16_t) (((t - USEC_2000) / USEC_PER_SEC) & 0xffffffff);

        unaligned_write_be16(&duid->type, DUID_TYPE_LLT);
        unaligned_write_be16(&duid->llt.htype, arp_type);
        unaligned_write_be32(&duid->llt.time, time_from_2000y);
        memcpy(duid->llt.haddr, addr, addr_len);

        *len = sizeof(duid->type) + sizeof(duid->llt.htype) + sizeof(duid->llt.time) + addr_len;

        return 0;
}

int dhcp_identifier_set_duid_ll(struct duid *duid, const uint8_t *addr, size_t addr_len, uint16_t arp_type, size_t *len) {
        assert(duid);
        assert(len);
        assert(addr);

        if (arp_type == ARPHRD_ETHER)
                assert_return(addr_len == ETH_ALEN, -EINVAL);
        else if (arp_type == ARPHRD_INFINIBAND)
                assert_return(addr_len == INFINIBAND_ALEN, -EINVAL);
        else
                return -EINVAL;

        unaligned_write_be16(&duid->type, DUID_TYPE_LL);
        unaligned_write_be16(&duid->ll.htype, arp_type);
        memcpy(duid->ll.haddr, addr, addr_len);

        *len = sizeof(duid->type) + sizeof(duid->ll.htype) + addr_len;

        return 0;
}

int dhcp_identifier_set_duid_en(struct duid *duid, size_t *len) {
        sd_id128_t machine_id;
        uint64_t hash;
        int r;

        assert(duid);
        assert(len);

        r = sd_id128_get_machine(&machine_id);
        if (r < 0) {
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
                machine_id = SD_ID128_MAKE(01, 02, 03, 04, 05, 06, 07, 08, 09, 0a, 0b, 0c, 0d, 0e, 0f, 10);
#else
                return r;
#endif
        }

        unaligned_write_be16(&duid->type, DUID_TYPE_EN);
        unaligned_write_be32(&duid->en.pen, SYSTEMD_PEN);

        *len = sizeof(duid->type) + sizeof(duid->en);

        /* a bit of snake-oil perhaps, but no need to expose the machine-id
         * directly; duid->en.id might not be aligned, so we need to copy */
        hash = htole64(siphash24(&machine_id, sizeof(machine_id), HASH_KEY.bytes));
        memcpy(duid->en.id, &hash, sizeof(duid->en.id));

        return 0;
}

int dhcp_identifier_set_duid_uuid(struct duid *duid, size_t *len) {
        sd_id128_t machine_id;
        int r;

        assert(duid);
        assert(len);

        r = sd_id128_get_machine_app_specific(APPLICATION_ID, &machine_id);
        if (r < 0)
                return r;

        unaligned_write_be16(&duid->type, DUID_TYPE_UUID);
        memcpy(&duid->raw.data, &machine_id, sizeof(machine_id));

        *len = sizeof(duid->type) + sizeof(machine_id);

        return 0;
}

int dhcp_identifier_set_iaid(
                int ifindex,
                const uint8_t *mac,
                size_t mac_len,
                bool legacy_unstable_byteorder,
                void *_id) {
        /* name is a pointer to memory in the sd_device struct, so must
         * have the same scope */
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        const char *name = NULL;
        uint64_t id;
        uint32_t id32;

        if (detect_container() <= 0) {
                /* not in a container, udev will be around */
                char ifindex_str[1 + DECIMAL_STR_MAX(int)];
                int r;

                xsprintf(ifindex_str, "n%d", ifindex);
                if (sd_device_new_from_device_id(&device, ifindex_str) >= 0) {
                        r = sd_device_get_is_initialized(device);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                /* not yet ready */
                                return -EBUSY;

                        r = device_is_renaming(device);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                /* device is under renaming */
                                return -EBUSY;

                        name = net_get_name_persistent(device);
                }
        }

        if (name)
                id = siphash24(name, strlen(name), HASH_KEY.bytes);
        else
                /* fall back to MAC address if no predictable name available */
                id = siphash24(mac, mac_len, HASH_KEY.bytes);

        id32 = (id & 0xffffffff) ^ (id >> 32);

        if (legacy_unstable_byteorder)
                /* for historical reasons (a bug), the bits were swapped and thus
                 * the result was endianness dependent. Preserve that behavior. */
                id32 = __bswap_32(id32);
        else
                /* the fixed behavior returns a stable byte order. Since LE is expected
                 * to be more common, swap the bytes on LE to give the same as legacy
                 * behavior. */
                id32 = be32toh(id32);

        unaligned_write_ne32(_id, id32);
        return 0;
}
