/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if.h>
#include <linux/if_arp.h>

#include "arphrd-util.h"
#include "device-util.h"
#include "hexdecoct.h"
#include "log-link.h"
#include "memory-util.h"
#include "netif-naming-scheme.h"
#include "netif-util.h"
#include "siphash24.h"
#include "sparse-endian.h"
#include "strv.h"

#define SHORTEN_IFNAME_HASH_KEY SD_ID128_MAKE(e1,90,a4,04,a8,ef,4b,51,8c,cc,c3,3a,9f,11,fc,a2)

bool netif_has_carrier(uint8_t operstate, unsigned flags) {
        /* see Documentation/networking/operstates.txt in the kernel sources */

        if (operstate == IF_OPER_UP)
                return true;

        if (operstate != IF_OPER_UNKNOWN)
                return false;

        /* operstate may not be implemented, so fall back to flags */
        return FLAGS_SET(flags, IFF_LOWER_UP | IFF_RUNNING) &&
                !FLAGS_SET(flags, IFF_DORMANT);
}

int net_get_type_string(sd_device *device, uint16_t iftype, char **ret) {
        const char *t;
        char *p;

        if (device &&
            sd_device_get_devtype(device, &t) >= 0 &&
            !isempty(t))
                return strdup_to(ret, t);

        t = arphrd_to_name(iftype);
        if (!t)
                return -ENOENT;

        p = strdup(t);
        if (!p)
                return -ENOMEM;

        *ret = ascii_strlower(p);
        return 0;
}

const char* net_get_persistent_name(sd_device *device) {
        assert(device);

        /* fetch some persistent data unique (on this machine) to this device */
        FOREACH_STRING(field, "ID_NET_NAME_ONBOARD", "ID_NET_NAME_SLOT", "ID_NET_NAME_PATH", "ID_NET_NAME_MAC") {
                const char *name;

                if (sd_device_get_property_value(device, field, &name) >= 0)
                        return name;
        }

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
                bool is_static,
                uint16_t iftype,
                const struct hw_addr_data *ib_hw_addr, /* current or parent HW address */
                struct hw_addr_data *new_hw_addr) {

        Link link = { .ifname = ifname };

        assert(new_hw_addr);

        if (new_hw_addr->length == 0)
                return 0;

        if (new_hw_addr->length != arphrd_to_hw_addr_len(iftype)) {
                if (is_static)
                        log_link_warning(&link,
                                         "Specified MAC address with invalid length (%zu, expected %zu), refusing.",
                                         new_hw_addr->length, arphrd_to_hw_addr_len(iftype));
                return -EINVAL;
        }

        switch (iftype) {
        case ARPHRD_ETHER:
                /* see eth_random_addr() in the kernel */

                if (ether_addr_is_null(&new_hw_addr->ether)) {
                        if (is_static)
                                log_link_warning(&link, "Specified MAC address is null, refusing.");
                        return -EINVAL;
                }

                if (ether_addr_is_broadcast(&new_hw_addr->ether)) {
                        if (is_static)
                                log_link_warning(&link, "Specified MAC address is broadcast, refusing.");
                        return -EINVAL;
                }

                if (ether_addr_is_multicast(&new_hw_addr->ether)) {
                        if (is_static)
                                log_link_warning(&link, "Specified MAC address has the multicast bit set, clearing the bit.");

                        new_hw_addr->bytes[0] &= 0xfe;
                }

                if (!is_static && !ether_addr_is_local(&new_hw_addr->ether))
                        /* Adjust local assignment bit when the MAC address is generated randomly. */
                        new_hw_addr->bytes[0] |= 0x02;

                break;

        case ARPHRD_INFINIBAND:
                /* see ipoib_check_lladdr() in the kernel */

                assert(ib_hw_addr);
                assert(ib_hw_addr->length == INFINIBAND_ALEN);

                if (is_static &&
                    (!memeqzero(new_hw_addr->bytes, INFINIBAND_ALEN - 8) ||
                     memcmp(new_hw_addr->bytes, ib_hw_addr->bytes, INFINIBAND_ALEN - 8) != 0))
                        log_link_warning(&link, "Only the last 8 bytes of the InifniBand MAC address can be changed, ignoring the first 12 bytes.");

                if (memeqzero(new_hw_addr->bytes + INFINIBAND_ALEN - 8, 8)) {
                        if (is_static)
                                log_link_warning(&link, "The last 8 bytes of the InfiniBand MAC address cannot be null, refusing.");
                        return -EINVAL;
                }

                memcpy(new_hw_addr->bytes, ib_hw_addr->bytes, INFINIBAND_ALEN - 8);
                break;

        default:
                if (is_static)
                        log_link_warning(&link, "Unsupported interface type %s%u to set MAC address, refusing.",
                                         strna(arphrd_to_name(iftype)), iftype);
                return -EINVAL;
        }

        return 0;
}

int net_generate_mac(
                const char *machine_name,
                struct ether_addr *mac,
                sd_id128_t hash_key,
                uint64_t idx) {

        uint64_t result;
        size_t l, sz;
        uint8_t *v, *i;
        int r;

        l = strlen(machine_name);
        sz = sizeof(sd_id128_t) + l;
        if (idx > 0)
                sz += sizeof(idx);

        v = newa(uint8_t, sz);

        /* fetch some persistent data unique to the host */
        r = sd_id128_get_machine((sd_id128_t*) v);
        if (r < 0)
                return r;

        /* combine with some data unique (on this host) to this
         * container instance */
        i = mempcpy(v + sizeof(sd_id128_t), machine_name, l);
        if (idx > 0) {
                idx = htole64(idx);
                memcpy(i, &idx, sizeof(idx));
        }

        /* Let's hash the host machine ID plus the container name. We
         * use a fixed, but originally randomly created hash key here. */
        result = htole64(siphash24(v, sz, hash_key.bytes));

        assert_cc(ETH_ALEN <= sizeof(result));
        memcpy(mac->ether_addr_octet, &result, ETH_ALEN);

        ether_addr_mark_random(mac);

        return 0;
}

int net_shorten_ifname(char *ifname, bool check_naming_scheme) {
        char new_ifname[IFNAMSIZ];

        assert(ifname);

        if (strlen(ifname) < IFNAMSIZ) /* Name is short enough */
                return 0;

        if (!check_naming_scheme || naming_scheme_has(NAMING_NSPAWN_LONG_HASH)) {
                uint64_t h;

                /* Calculate 64-bit hash value */
                h = siphash24(ifname, strlen(ifname), SHORTEN_IFNAME_HASH_KEY.bytes);

                /* Set the final four bytes (i.e. 32-bit) to the lower 24bit of the hash, encoded in url-safe base64 */
                memcpy(new_ifname, ifname, IFNAMSIZ - 5);
                new_ifname[IFNAMSIZ - 5] = urlsafe_base64char(h >> 18);
                new_ifname[IFNAMSIZ - 4] = urlsafe_base64char(h >> 12);
                new_ifname[IFNAMSIZ - 3] = urlsafe_base64char(h >> 6);
                new_ifname[IFNAMSIZ - 2] = urlsafe_base64char(h);
        } else
                /* On old nspawn versions we just truncated the name, provide compatibility */
                memcpy(new_ifname, ifname, IFNAMSIZ-1);

        new_ifname[IFNAMSIZ - 1] = 0;

        /* Log the incident to make it more discoverable */
        log_warning("Network interface name '%s' has been changed to '%s' to fit length constraints.", ifname, new_ifname);

        strcpy(ifname, new_ifname);
        return 1;
}
