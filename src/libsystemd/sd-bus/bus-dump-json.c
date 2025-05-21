/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "json-util.h"
#include "string-util.h"
#include "time-util.h"

static int json_transform_one(sd_bus_message *m, sd_json_variant **ret);

static int json_transform_array_or_struct(sd_bus_message *m, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        int r;

        assert(m);
        assert(ret);

        r = sd_json_variant_new_array(&array, NULL, 0);
        if (r < 0)
                return r;

        for (;;) {
                r = sd_bus_message_at_end(m, false);
                if (r < 0)
                        return r;
                if (r > 0)
                        break;

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                r = json_transform_one(m, &v);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(&array, v);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(array);
        return 0;
}

static int json_transform_variant(sd_bus_message *m, const char *contents, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *value = NULL;
        int r;

        assert(m);
        assert(contents);
        assert(ret);

        r = json_transform_one(m, &value);
        if (r < 0)
                return r;

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR("type", SD_JSON_BUILD_STRING(contents)),
                        SD_JSON_BUILD_PAIR("data", SD_JSON_BUILD_VARIANT(value)));
}

static int json_transform_dict_array(sd_bus_message *m, sd_json_variant **ret) {
        sd_json_variant **elements = NULL;
        size_t n_elements = 0;
        int r;

        assert(m);
        assert(ret);

        CLEANUP_ARRAY(elements, n_elements, sd_json_variant_unref_many);

        for (;;) {
                const char *contents;
                char type;

                r = sd_bus_message_at_end(m, false);
                if (r < 0)
                        return r;
                if (r > 0)
                        break;

                r = sd_bus_message_peek_type(m, &type, &contents);
                if (r < 0)
                        return r;

                assert(type == 'e');

                if (!GREEDY_REALLOC(elements, n_elements + 2))
                        return -ENOMEM;

                r = sd_bus_message_enter_container(m, type, contents);
                if (r < 0)
                        return r;

                r = json_transform_one(m, elements + n_elements);
                if (r < 0)
                        return r;

                n_elements++;

                r = json_transform_one(m, elements + n_elements);
                if (r < 0)
                        return r;

                n_elements++;

                r = sd_bus_message_exit_container(m);
                if (r < 0)
                        return r;
        }

        return sd_json_variant_new_object(ret, elements, n_elements);
}

static int json_transform_one(sd_bus_message *m, sd_json_variant **ret) {
        const char *contents;
        char type;
        int r;

        assert(m);
        assert(ret);

        r = sd_bus_message_peek_type(m, &type, &contents);
        if (r < 0)
                return r;

        switch (type) {

        case SD_BUS_TYPE_BYTE: {
                uint8_t b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return r;

                return sd_json_variant_new_unsigned(ret, b);
        }

        case SD_BUS_TYPE_BOOLEAN: {
                int b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return r;

                return sd_json_variant_new_boolean(ret, b);
        }

        case SD_BUS_TYPE_INT16: {
                int16_t b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return r;

                return sd_json_variant_new_integer(ret, b);
        }

        case SD_BUS_TYPE_UINT16: {
                uint16_t b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return r;

                return sd_json_variant_new_unsigned(ret, b);
        }

        case SD_BUS_TYPE_INT32: {
                int32_t b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return r;

                return sd_json_variant_new_integer(ret, b);
        }

        case SD_BUS_TYPE_UINT32: {
                uint32_t b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return r;

                return sd_json_variant_new_unsigned(ret, b);
        }

        case SD_BUS_TYPE_INT64: {
                int64_t b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return r;

                return sd_json_variant_new_integer(ret, b);
        }

        case SD_BUS_TYPE_UINT64: {
                uint64_t b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return r;

                return sd_json_variant_new_unsigned(ret, b);
        }

        case SD_BUS_TYPE_DOUBLE: {
                double d;

                r = sd_bus_message_read_basic(m, type, &d);
                if (r < 0)
                        return r;

                return sd_json_variant_new_real(ret, d);
        }

        case SD_BUS_TYPE_STRING:
        case SD_BUS_TYPE_OBJECT_PATH:
        case SD_BUS_TYPE_SIGNATURE: {
                const char *s;

                r = sd_bus_message_read_basic(m, type, &s);
                if (r < 0)
                        return r;

                return sd_json_variant_new_string(ret, s);
        }

        case SD_BUS_TYPE_UNIX_FD: {
                int fd;

                r = sd_bus_message_read_basic(m, type, &fd);
                if (r < 0)
                        return r;

                return json_variant_new_fd_info(ret, fd);
        }

        case SD_BUS_TYPE_ARRAY:
        case SD_BUS_TYPE_VARIANT:
        case SD_BUS_TYPE_STRUCT: {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                r = sd_bus_message_enter_container(m, type, contents);
                if (r < 0)
                        return r;

                if (type == SD_BUS_TYPE_VARIANT)
                        r = json_transform_variant(m, contents, &v);
                else if (type == SD_BUS_TYPE_ARRAY && contents[0] == '{')
                        r = json_transform_dict_array(m, &v);
                else
                        r = json_transform_array_or_struct(m, &v);
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(m);
                if (r < 0)
                        return r;

                *ret = TAKE_PTR(v);
                return 0;
        }

        default:
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "sd-bus: an invalid message type (signature=%s, type=%c, contents=%s).",
                                       sd_bus_message_get_signature(m, /* complete = */ false), type, strna(contents));
        }
}

static int json_transform_message(sd_bus_message *m, const char *type, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(m);
        assert(type);
        assert(ret);

        r = json_transform_array_or_struct(m, &v);
        if (r < 0)
                return r;

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR("type", SD_JSON_BUILD_STRING(type)),
                        SD_JSON_BUILD_PAIR("data", SD_JSON_BUILD_VARIANT(v)));
}

_public_ int sd_bus_message_dump_json(sd_bus_message *m, uint64_t flags, sd_json_variant **ret) {
        int r;

        assert_return(m, -EINVAL);
        assert_return((flags & ~_SD_BUS_MESSAGE_DUMP_KNOWN_FLAGS) == 0, -EINVAL);
        assert_return(ret, -EINVAL);

        r = sd_bus_message_rewind(m, !FLAGS_SET(flags, SD_BUS_MESSAGE_DUMP_SUBTREE_ONLY));
        if (r < 0)
                return r;

        const char *type = sd_bus_message_get_signature(m, !FLAGS_SET(flags, SD_BUS_MESSAGE_DUMP_SUBTREE_ONLY));
        if (!type)
                return -EINVAL;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        if (FLAGS_SET(flags, SD_BUS_MESSAGE_DUMP_SUBTREE_ONLY))
                r = json_transform_variant(m, type, &v);
        else
                r = json_transform_message(m, type, &v);
        if (r < 0)
                return r;

        if (!FLAGS_SET(flags, SD_BUS_MESSAGE_DUMP_WITH_HEADER)) {
                *ret = TAKE_PTR(v);
                return 0;
        }

        usec_t ts = m->realtime;
        if (ts == 0)
                ts = now(CLOCK_REALTIME);

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR("type", SD_JSON_BUILD_STRING(bus_message_type_to_string(m->header->type))),
                        SD_JSON_BUILD_PAIR("endian", SD_JSON_BUILD_STRING(CHAR_TO_STR(m->header->endian))),
                        SD_JSON_BUILD_PAIR("flags", SD_JSON_BUILD_INTEGER(m->header->flags)),
                        SD_JSON_BUILD_PAIR("version", SD_JSON_BUILD_INTEGER(m->header->version)),
                        SD_JSON_BUILD_PAIR("cookie", SD_JSON_BUILD_INTEGER(BUS_MESSAGE_COOKIE(m))),
                        SD_JSON_BUILD_PAIR_CONDITION(m->reply_cookie != 0, "reply_cookie", SD_JSON_BUILD_INTEGER(m->reply_cookie)),
                        SD_JSON_BUILD_PAIR("timestamp-realtime", SD_JSON_BUILD_UNSIGNED(ts)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!m->sender, "sender", SD_JSON_BUILD_STRING(m->sender)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!m->destination, "destination", SD_JSON_BUILD_STRING(m->destination)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!m->path, "path", SD_JSON_BUILD_STRING(m->path)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!m->interface, "interface", SD_JSON_BUILD_STRING(m->interface)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!m->member, "member", SD_JSON_BUILD_STRING(m->member)),
                        SD_JSON_BUILD_PAIR_CONDITION(m->monotonic != 0, "monotonic", SD_JSON_BUILD_INTEGER(m->monotonic)),
                        SD_JSON_BUILD_PAIR_CONDITION(m->realtime != 0, "realtime", SD_JSON_BUILD_INTEGER(m->realtime)),
                        SD_JSON_BUILD_PAIR_CONDITION(m->seqnum != 0, "seqnum", SD_JSON_BUILD_INTEGER(m->seqnum)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!m->error.name, "error_name", SD_JSON_BUILD_STRING(m->error.name)),
                        SD_JSON_BUILD_PAIR("payload", SD_JSON_BUILD_VARIANT(v)));
}
