/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_arp.h>

#include "arphrd-util.h"
#include "device-util.h"
#include "log-link.h"
#include "memory-util.h"
#include "netif-util.h"
#include "siphash24.h"
#include "sparse-endian.h"
#include "strv.h"

int net_get_type_string(sd_device *device, uint16_t iftype, char **ret) {
        const char *t;
        char *p;

        if (device &&
            sd_device_get_devtype(device, &t) >= 0 &&
            !isempty(t)) {
                p = strdup(t);
                if (!p)
                        return -ENOMEM;

                *ret = p;
                return 0;
        }

        t = arphrd_to_name(iftype);
        if (!t)
                return -ENOENT;

        p = strdup(t);
        if (!p)
                return -ENOMEM;

        *ret = ascii_strlower(p);
        return 0;
}

const char *net_get_persistent_name(sd_device *device) {
        const char *name, *field;

        assert(device);

        /* fetch some persistent data unique (on this machine) to this device */
        FOREACH_STRING(field, "ID_NET_NAME_ONBOARD", "ID_NET_NAME_SLOT", "ID_NET_NAME_PATH", "ID_NET_NAME_MAC")
                if (sd_device_get_property_value(device, field, &name) >= 0)
                        return name;

        return NULL;
}

/* Used when generating hardware address by udev, and IPv4LL seed by networkd. */
#define HASH_KEY SD_ID128_MAKE(d3,1e,48,fa,90,fe,4b,4c,9d,af,d5,d7,a1,b1,2e,8a)

int net_get_unique_predictable_data(sd_device *device, bool use_sysname, uint64_t *ret) {
        const char *name;

        assert(device);
        assert(ret);

        /* net_get_persistent_name() will return one of the device names based on stable information about
         * the device. If this is not available, we fall back to using the actual device name. */
        name = net_get_persistent_name(device);
        if (!name && use_sysname)
                (void) sd_device_get_sysname(device, &name);
        if (!name)
                return log_device_debug_errno(device, SYNTHETIC_ERRNO(ENODATA),
                                              "No stable identifying information found");

        log_device_debug(device, "Using \"%s\" as stable identifying information", name);

        return net_get_unique_predictable_data_from_name(name, &HASH_KEY, ret);
}

int net_get_unique_predictable_data_from_name(
                const char *name,
                const sd_id128_t *key,
                uint64_t *ret) {

        size_t l, sz;
        uint8_t *v;
        int r;

        assert(name);
        assert(key);
        assert(ret);

        l = strlen(name);
        sz = sizeof(sd_id128_t) + l;
        v = newa(uint8_t, sz);

        /* Fetch some persistent data unique to this machine */
        r = sd_id128_get_machine((sd_id128_t*) v);
        if (r < 0)
                 return r;

        memcpy(v + sizeof(sd_id128_t), name, l);

        /* Let's hash the machine ID plus the device name. We use
         * a fixed, but originally randomly created hash key here. */
        *ret = htole64(siphash24(v, sz, key->bytes));
        return 0;
}

typedef struct Link {
        const char *ifname;
} Link;

int net_verify_hardware_address(
                const char *ifname,
                bool warn_invalid,
                uint16_t iftype,
                const struct hw_addr_data *ib_hw_addr, /* current or parent HW address */
                struct hw_addr_data *new_hw_addr) {

        Link link = { .ifname = ifname };

        assert(new_hw_addr);

        if (new_hw_addr->length == 0)
                return 0;

        if (new_hw_addr->length != arphrd_to_hw_addr_len(iftype)) {
                if (warn_invalid)
                        log_link_warning(&link,
                                         "Specified MAC address with invalid length (%zu, expected %zu), refusing.",
                                         new_hw_addr->length, arphrd_to_hw_addr_len(iftype));
                return -EINVAL;
        }

        switch (iftype) {
        case ARPHRD_ETHER:
                /* see eth_random_addr() in the kernel */

                if (ether_addr_is_null(&new_hw_addr->ether)) {
                        if (warn_invalid)
                                log_link_warning(&link, "Specified MAC address is null, refusing.");
                        return -EINVAL;
                }

                if (ether_addr_is_broadcast(&new_hw_addr->ether)) {
                        if (warn_invalid)
                                log_link_warning(&link, "Specified MAC address is broadcast, refusing.");
                        return -EINVAL;
                }

                if (ether_addr_is_multicast(&new_hw_addr->ether)) {
                        if (warn_invalid)
                                log_link_warning(&link, "Specified MAC address has multicast bit set, clearing the bit.");

                        new_hw_addr->bytes[0] &= 0xfe;
                }

                if (!ether_addr_is_local(&new_hw_addr->ether)) {
                        if (warn_invalid)
                                log_link_warning(&link, "Specified MAC address has not local assignment bit set, setting the bit.");

                        new_hw_addr->bytes[0] |= 0x02;
                }

                break;

        case ARPHRD_INFINIBAND:
                /* see ipoib_check_lladdr() in the kernel */

                assert(ib_hw_addr);
                assert(ib_hw_addr->length == INFINIBAND_ALEN);

                if (warn_invalid &&
                    (!memeqzero(new_hw_addr->bytes, INFINIBAND_ALEN - 8) ||
                     memcmp(new_hw_addr->bytes, ib_hw_addr->bytes, INFINIBAND_ALEN - 8) != 0))
                        log_link_warning(&link, "Only the last 8 bytes of the InifniBand MAC address can be changed, ignoring the first 12 bytes.");

                if (memeqzero(new_hw_addr->bytes + INFINIBAND_ALEN - 8, 8)) {
                        if (warn_invalid)
                                log_link_warning(&link, "The last 8 bytes of the InfiniBand MAC address cannot be null, refusing.");
                        return -EINVAL;
                }

                memcpy(new_hw_addr->bytes, ib_hw_addr->bytes, INFINIBAND_ALEN - 8);
                break;

        default:
                if (warn_invalid)
                        log_link_warning(&link, "Unsupported interface type %s%u to set MAC address, refusing.",
                                         strna(arphrd_to_name(iftype)), iftype);
                return -EINVAL;
        }

        return 0;
}
