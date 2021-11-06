/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-id128.h"

#include "arphrd-util.h"
#include "device-util.h"
#include "netif-util.h"
#include "siphash24.h"
#include "sparse-endian.h"
#include "strv.h"

int link_get_type_string(sd_device *device, unsigned short iftype, char **ret) {
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

#define HASH_KEY SD_ID128_MAKE(d3,1e,48,fa,90,fe,4b,4c,9d,af,d5,d7,a1,b1,2e,8a)

int net_get_unique_predictable_data(sd_device *device, bool use_sysname, uint64_t *ret) {
        size_t l, sz = 0;
        const char *name;
        int r;
        uint8_t *v;

        assert(device);

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
        *ret = htole64(siphash24(v, sz, HASH_KEY.bytes));
        return 0;
}
