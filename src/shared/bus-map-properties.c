/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-map-properties.h"
#include "alloc-util.h"
#include "bus-util.h"
#include "strv.h"
#include "bus-message.h"
#include "bus-message-util.h"

int bus_map_id128(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        sd_id128_t *p = userdata;
        int r;

        assert(m);

        r = bus_message_read_id128(m, p);
        if (r < 0)
                return bus_log_parse_error_debug(r);

        return 0;
}

int bus_map_strv_sort(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        char ***p = ASSERT_PTR(userdata);
        int r;

        assert(m);

        r = sd_bus_message_read_strv_extend(m, p);
        if (r < 0)
                return bus_log_parse_error_debug(r);

        strv_sort(*p);
        return 0;
}

int bus_map_job_id(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        uint32_t *p = ASSERT_PTR(userdata);

        assert(m);

        return sd_bus_message_read(m, "(uo)", p, /* path = */ NULL);
}

static int map_basic(sd_bus_message *m, unsigned flags, void *userdata) {
        char type;
        int r;

        assert(m);
        assert(userdata);

        r = sd_bus_message_peek_type(m, &type, NULL);
        if (r < 0)
                return bus_log_parse_error_debug(r);

        switch (type) {

        case SD_BUS_TYPE_STRING:
        case SD_BUS_TYPE_OBJECT_PATH: {
                const char **p = userdata, *s;

                r = sd_bus_message_read_basic(m, type, &s);
                if (r < 0)
                        return bus_log_parse_error_debug(r);

                s = empty_to_null(s);

                if (FLAGS_SET(flags, BUS_MAP_STRDUP))
                        return free_and_strdup((char**) p, s);

                *p = s;
                return 0;
        }

        case SD_BUS_TYPE_ARRAY: {
                char ***p = userdata;

                r = sd_bus_message_read_strv_extend(m, p);
                if (r < 0)
                        return bus_log_parse_error_debug(r);

                return 0;
        }

        case SD_BUS_TYPE_BOOLEAN: {
                int b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return bus_log_parse_error_debug(r);

                if (flags & BUS_MAP_BOOLEAN_AS_BOOL)
                        *(bool*) userdata = b;
                else
                        *(int*) userdata = b;

                return 0;
        }

        case SD_BUS_TYPE_INT32:
        case SD_BUS_TYPE_UINT32: {
                uint32_t *p = userdata;

                r = sd_bus_message_read_basic(m, type, p);
                if (r < 0)
                        return bus_log_parse_error_debug(r);

                return 0;
        }

        case SD_BUS_TYPE_INT64:
        case SD_BUS_TYPE_UINT64: {
                uint64_t *p = userdata;

                r = sd_bus_message_read_basic(m, type, p);
                if (r < 0)
                        return bus_log_parse_error_debug(r);

                return 0;
        }

        case SD_BUS_TYPE_DOUBLE: {
                double *p = userdata;

                r = sd_bus_message_read_basic(m, type, p);
                if (r < 0)
                        return bus_log_parse_error_debug(r);

                return 0;
        }

        default:
                return -EOPNOTSUPP;
        }
}

int bus_message_map_all_properties(
                sd_bus_message *m,
                const struct bus_properties_map *map,
                unsigned flags,
                sd_bus_error *error,
                void *userdata) {

        int r;

        assert(m);
        assert(map);

        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "{sv}");
        if (r < 0)
                return bus_log_parse_error_debug(r);

        while ((r = sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY, "sv")) > 0) {
                const struct bus_properties_map *prop;
                const char *member;
                const char *contents;
                void *v;
                unsigned i;

                r = sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &member);
                if (r < 0)
                        return bus_log_parse_error_debug(r);

                for (i = 0, prop = NULL; map[i].member; i++)
                        if (streq(map[i].member, member)) {
                                prop = &map[i];
                                break;
                        }

                if (prop) {
                        r = sd_bus_message_peek_type(m, NULL, &contents);
                        if (r < 0)
                                return bus_log_parse_error_debug(r);

                        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, contents);
                        if (r < 0)
                                return bus_log_parse_error_debug(r);

                        v = (uint8_t *)userdata + prop->offset;
                        if (map[i].set)
                                r = prop->set(sd_bus_message_get_bus(m), member, m, error, v);
                        else
                                r = map_basic(m, flags, v);
                        if (r < 0)
                                return bus_log_parse_error_debug(r);

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return bus_log_parse_error_debug(r);
                } else {
                        r = sd_bus_message_skip(m, "v");
                        if (r < 0)
                                return bus_log_parse_error_debug(r);
                }

                r = sd_bus_message_exit_container(m);
                if (r < 0)
                        return bus_log_parse_error_debug(r);
        }
        if (r < 0)
                return bus_log_parse_error_debug(r);

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return bus_log_parse_error_debug(r);

        return r;
}

int bus_map_all_properties(
                sd_bus *bus,
                const char *destination,
                const char *path,
                const struct bus_properties_map *map,
                unsigned flags,
                sd_bus_error *error,
                sd_bus_message **reply,
                void *userdata) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        assert(bus);
        assert(destination);
        assert(path);
        assert(map);
        assert(reply || (flags & BUS_MAP_STRDUP));

        r = sd_bus_call_method(
                        bus,
                        destination,
                        path,
                        "org.freedesktop.DBus.Properties",
                        "GetAll",
                        error,
                        &m,
                        "s", "");
        if (r < 0)
                return r;

        r = bus_message_map_all_properties(m, map, flags, error, userdata);
        if (r < 0)
                return r;

        if (reply)
                *reply = sd_bus_message_ref(m);

        return r;
}
