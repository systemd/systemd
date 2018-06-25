/* SPDX-License-Identifier: LGPL-2.1+ */

#include "libudev.h"
#include "sd-id128.h"

#include "dhcp-identifier.h"
#include "dhcp6-protocol.h"
#include "network-internal.h"
#include "siphash24.h"
#include "sparse-endian.h"
#include "udev-util.h"
#include "virt.h"

#define SYSTEMD_PEN    43793
#define HASH_KEY       SD_ID128_MAKE(80,11,8c,c2,fe,4a,03,ee,3e,d6,0c,6f,36,39,14,09)
#define APPLICATION_ID SD_ID128_MAKE(a5,0a,d1,12,bf,60,45,77,a2,fb,74,1a,b1,95,5b,03)

int dhcp_validate_duid_len(uint16_t duid_type, size_t duid_len) {
        struct duid d;

        assert_cc(sizeof(d.raw) >= MAX_DUID_LEN);
        if (duid_len > MAX_DUID_LEN)
                return -EINVAL;

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

int dhcp_identifier_set_duid_en(struct duid *duid, size_t *len) {
        sd_id128_t machine_id;
        uint64_t hash;
        int r;

        assert(duid);
        assert(len);

        r = sd_id128_get_machine(&machine_id);
        if (r < 0)
                return r;

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

int dhcp_identifier_set_iaid(int ifindex, uint8_t *mac, size_t mac_len, void *_id) {
        /* name is a pointer to memory in the udev_device struct, so must
           have the same scope */
        _cleanup_(udev_device_unrefp) struct udev_device *device = NULL;
        const char *name = NULL;
        uint64_t id;

        if (detect_container() <= 0) {
                /* not in a container, udev will be around */
                _cleanup_(udev_unrefp) struct udev *udev;
                char ifindex_str[2 + DECIMAL_STR_MAX(int)];

                udev = udev_new();
                if (!udev)
                        return -ENOMEM;

                sprintf(ifindex_str, "n%d", ifindex);
                device = udev_device_new_from_device_id(udev, ifindex_str);
                if (device) {
                        if (udev_device_get_is_initialized(device) <= 0)
                                /* not yet ready */
                                return -EBUSY;

                        name = net_get_name(device);
                }
        }

        if (name)
                id = siphash24(name, strlen(name), HASH_KEY.bytes);
        else
                /* fall back to MAC address if no predictable name available */
                id = siphash24(mac, mac_len, HASH_KEY.bytes);

        id = htole64(id);

        /* fold into 32 bits */
        unaligned_write_be32(_id, (id & 0xffffffff) ^ (id >> 32));

        return 0;
}
