/* SPDX-License-Identifier: LGPL-2.1+ */

#include "bus-message-util.h"

int bus_message_read_family(sd_bus_message *message, sd_bus_error *error, int *ret) {
        int family, r;

        assert(message);
        assert(ret);

        assert_cc(sizeof(int) == sizeof(int32_t));

        r = sd_bus_message_read(message, "i", &family);
        if (r < 0)
                return r;

        if (!IN_SET(family, AF_INET, AF_INET6))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unknown address family %i", family);

        *ret = family;
        return 0;
}

int bus_message_read_in_addr_auto(sd_bus_message *message, sd_bus_error *error, int *ret_family, union in_addr_union *ret_addr) {
        int family, r;
        const void *d;
        size_t sz;

        assert(message);

        r = sd_bus_message_read(message, "i", &family);
        if (r < 0)
                return r;

        r = sd_bus_message_read_array(message, 'y', &d, &sz);
        if (r < 0)
                return r;

        if (!IN_SET(family, AF_INET, AF_INET6))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unknown address family %i", family);

        if (sz != FAMILY_ADDRESS_SIZE(family))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid address size");

        if (ret_family)
                *ret_family = family;
        if (ret_addr)
                memcpy(ret_addr, d, sz);
        return 0;
}
