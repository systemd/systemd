/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-id128.h"

#include "arphrd-list.h"
#include "device-util.h"
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

const char *net_get_name_persistent(sd_device *device) {
        const char *name, *field;

        assert(device);

        /* fetch some persistent data unique (on this machine) to this device */
        FOREACH_STRING(field, "ID_NET_NAME_ONBOARD", "ID_NET_NAME_SLOT", "ID_NET_NAME_PATH", "ID_NET_NAME_MAC")
                if (sd_device_get_property_value(device, field, &name) >= 0)
                        return name;

        return NULL;
}

#define HASH_KEY_1 SD_ID128_MAKE(d3,1e,48,fa,90,fe,4b,4c,9d,af,d5,d7,a1,b1,2e,8a)
#define HASH_KEY_2 SD_ID128_MAKE(70,7d,6d,59,9b,0c,43,62,9c,47,58,aa,52,1d,aa,73)
#define HASH_KEY_3 SD_ID128_MAKE(08,2c,39,8f,18,b8,4d,c3,94,95,ce,c9,02,61,c2,a7)
#define HASH_KEY_4 SD_ID128_MAKE(34,71,b2,57,ac,d4,48,66,89,16,42,4a,f6,c4,05,d4)

static int net_get_unique_predictable_data_impl(sd_device *device, bool use_sysname, const sd_id128_t *key, uint64_t *ret) {
        const char *name;
        size_t l, sz;
        uint8_t *v;
        int r;

        assert(device);
        assert(key);
        assert(ret);

        /* net_get_name_persistent() will return one of the device names based on stable information about
         * the device. If this is not available, we fall back to using the actual device name. */
        name = net_get_name_persistent(device);
        if (!name && use_sysname)
                (void) sd_device_get_sysname(device, &name);
        if (!name)
                return log_device_debug_errno(device, SYNTHETIC_ERRNO(ENODATA),
                                              "No stable identifying information found");

        log_device_debug(device, "Using \"%s\" as stable identifying information", name);
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

int net_get_unique_predictable_data(sd_device *device, bool use_sysname, uint64_t *ret) {
        return net_get_unique_predictable_data_impl(device, use_sysname, &HASH_KEY_1, ret);
}

int net_get_unique_predictable_bytes(sd_device *device, bool use_sysname, size_t len, uint8_t *ret) {
        const sd_id128_t *keys[4] = { &HASH_KEY_1, &HASH_KEY_2, &HASH_KEY_3, &HASH_KEY_4, };
        uint64_t x[4];
        size_t n;
        int r;

        assert(ret);
        assert(len <= 4 * sizeof(uint64_t));

        n = DIV_ROUND_UP(len, sizeof(uint64_t));

        for (size_t i = 0; i < n; i++) {
                r = net_get_unique_predictable_data_impl(device, use_sysname, keys[i], x + i);
                if (r < 0)
                        return r;
        }

        for (size_t i = 0; i < n; i++) {
                memcpy(ret + i * sizeof(uint64_t), x + i, MIN(len, sizeof(uint64_t)));
                len = LESS_BY(len, sizeof(uint64_t));
        }

        return 0;
}
