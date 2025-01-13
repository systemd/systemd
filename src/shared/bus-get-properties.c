/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-get-properties.h"
#include "bus-message-util.h"
#include "rlimit-util.h"
#include "stdio-util.h"
#include "string-util.h"

int bus_property_get_bool(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        int b = *(bool*) userdata;

        return sd_bus_message_append_basic(reply, 'b', &b);
}

int bus_property_set_bool(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *value,
                void *userdata,
                sd_bus_error *error) {

        int b, r;

        r = sd_bus_message_read(value, "b", &b);
        if (r < 0)
                return r;

        *(bool*) userdata = b;
        return 0;
}

int bus_property_get_tristate(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        /* Defaults to false. */

        int b = (*(int*) userdata) > 0;

        return sd_bus_message_append_basic(reply, 'b', &b);
}

int bus_property_get_id128(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        sd_id128_t *id = userdata;

        if (sd_id128_is_null(*id)) /* Add an empty array if the ID is zero */
                return sd_bus_message_append(reply, "ay", 0);
        else
                return sd_bus_message_append_array(reply, 'y', id->bytes, 16);
}

#if __SIZEOF_SIZE_T__ != 8
int bus_property_get_size(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        uint64_t sz = *(size_t*) userdata;

        return sd_bus_message_append_basic(reply, 't', &sz);
}
#endif

#if __SIZEOF_LONG__ != 8
int bus_property_get_long(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        int64_t l = *(long*) userdata;

        return sd_bus_message_append_basic(reply, 'x', &l);
}

int bus_property_get_ulong(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        uint64_t ul = *(unsigned long*) userdata;

        return sd_bus_message_append_basic(reply, 't', &ul);
}
#endif

int bus_property_get_rlimit(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        const char *is_soft;
        struct rlimit *rl;
        uint64_t u;
        rlim_t x;

        assert(bus);
        assert(reply);
        assert(userdata);

        is_soft = endswith(property, "Soft");

        rl = *(struct rlimit**) userdata;
        if (rl)
                x = is_soft ? rl->rlim_cur : rl->rlim_max;
        else {
                struct rlimit buf = {};
                const char *s, *p;
                int z;

                /* Chop off "Soft" suffix */
                s = is_soft ? strndupa_safe(property, is_soft - property) : property;

                /* Skip over any prefix, such as "Default" */
                assert_se(p = strstrafter(s, "Limit"));

                z = rlimit_from_string(p);
                assert(z >= 0);

                (void) getrlimit(z, &buf);
                x = is_soft ? buf.rlim_cur : buf.rlim_max;
        }

        /* rlim_t might have different sizes, let's map RLIMIT_INFINITY to UINT64_MAX, so that it is the same on all
         * archs */
        u = x == RLIM_INFINITY ? UINT64_MAX : (uint64_t) x;

        return sd_bus_message_append(reply, "t", u);
}

int bus_property_get_string_set(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Set **s = ASSERT_PTR(userdata);

        assert(bus);
        assert(property);
        assert(reply);

        return bus_message_append_string_set(reply, *s);
}
