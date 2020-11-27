/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-id128.h"

#include "alloc-util.h"
#include "arphrd-list.h"
#include "device-util.h"
#include "fd-util.h"
#include "network-util.h"
#include "siphash24.h"
#include "sparse-endian.h"
#include "string-table.h"
#include "strv.h"

bool network_is_online(void) {
        _cleanup_free_ char *carrier_state = NULL, *addr_state = NULL;
        int r;

        r = sd_network_get_carrier_state(&carrier_state);
        if (r < 0) /* if we don't know anything, we consider the system online */
                return true;

        r = sd_network_get_address_state(&addr_state);
        if (r < 0) /* if we don't know anything, we consider the system online */
                return true;

        if (STR_IN_SET(carrier_state, "degraded-carrier", "carrier") &&
            STR_IN_SET(addr_state, "routable", "degraded"))
                return true;

        return false;
}

static const char* const link_operstate_table[_LINK_OPERSTATE_MAX] = {
        [LINK_OPERSTATE_MISSING]          = "missing",
        [LINK_OPERSTATE_OFF]              = "off",
        [LINK_OPERSTATE_NO_CARRIER]       = "no-carrier",
        [LINK_OPERSTATE_DORMANT]          = "dormant",
        [LINK_OPERSTATE_DEGRADED_CARRIER] = "degraded-carrier",
        [LINK_OPERSTATE_CARRIER]          = "carrier",
        [LINK_OPERSTATE_DEGRADED]         = "degraded",
        [LINK_OPERSTATE_ENSLAVED]         = "enslaved",
        [LINK_OPERSTATE_ROUTABLE]         = "routable",
};

DEFINE_STRING_TABLE_LOOKUP(link_operstate, LinkOperationalState);

static const char* const link_carrier_state_table[_LINK_CARRIER_STATE_MAX] = {
        [LINK_CARRIER_STATE_OFF]              = "off",
        [LINK_CARRIER_STATE_NO_CARRIER]       = "no-carrier",
        [LINK_CARRIER_STATE_DORMANT]          = "dormant",
        [LINK_CARRIER_STATE_DEGRADED_CARRIER] = "degraded-carrier",
        [LINK_CARRIER_STATE_CARRIER]          = "carrier",
        [LINK_CARRIER_STATE_ENSLAVED]         = "enslaved",
};

DEFINE_STRING_TABLE_LOOKUP(link_carrier_state, LinkCarrierState);

static const char* const link_address_state_table[_LINK_ADDRESS_STATE_MAX] = {
        [LINK_ADDRESS_STATE_OFF]      = "off",
        [LINK_ADDRESS_STATE_DEGRADED] = "degraded",
        [LINK_ADDRESS_STATE_ROUTABLE] = "routable",
};

DEFINE_STRING_TABLE_LOOKUP(link_address_state, LinkAddressState);

int parse_operational_state_range(const char *str, LinkOperationalStateRange *out) {
        LinkOperationalStateRange range = { _LINK_OPERSTATE_INVALID, _LINK_OPERSTATE_INVALID };
        _cleanup_free_ const char *min = NULL;
        const char *p;

        assert(str);
        assert(out);

        p = strchr(str, ':');
        if (p) {
                min = strndup(str, p - str);

                if (!isempty(p + 1)) {
                        range.max = link_operstate_from_string(p + 1);
                        if (range.max < 0)
                                return -EINVAL;
                }
        } else
                min = strdup(str);

        if (!min)
                return -ENOMEM;

        if (!isempty(min)) {
                range.min = link_operstate_from_string(min);
                if (range.min < 0)
                        return -EINVAL;
        }

        /* Fail on empty strings. */
        if (range.min == _LINK_OPERSTATE_INVALID && range.max == _LINK_OPERSTATE_INVALID)
                return -EINVAL;

        if (range.min == _LINK_OPERSTATE_INVALID)
                range.min = LINK_OPERSTATE_MISSING;
        if (range.max == _LINK_OPERSTATE_INVALID)
                range.max = LINK_OPERSTATE_ROUTABLE;

        if (range.min > range.max)
                return -EINVAL;

        *out = range;

        return 0;
}

char *link_get_type_string(sd_device *device, unsigned short iftype) {
        const char *t;
        char *p;

        if (device &&
            sd_device_get_devtype(device, &t) >= 0 &&
            !isempty(t))
                return strdup(t);

        t = arphrd_to_name(iftype);
        if (!t)
                return NULL;

        p = strdup(t);
        if (!p)
                return NULL;

        return ascii_strlower(p);
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

int net_get_unique_predictable_data(sd_device *device, bool use_sysname, uint64_t *result) {
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
        *result = htole64(siphash24(v, sz, HASH_KEY.bytes));
        return 0;
}
