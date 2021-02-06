/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-message.h"
#include "bus-util.h"
#include "json-transform.h"

static int json_transform_one(sd_bus_message *m, JsonVariant **ret);

static int json_transform_array_or_struct(sd_bus_message *m, JsonVariant **ret) {
        size_t n_elements = 0, n_allocated = 0;
        JsonVariant **elements = NULL;
        int r;

        assert(m);
        assert(ret);

        for (;;) {
                r = sd_bus_message_at_end(m, false);
                if (r < 0) {
                        bus_log_parse_error(r);
                        goto finish;
                }
                if (r > 0)
                        break;

                if (!GREEDY_REALLOC(elements, n_allocated, n_elements + 1)) {
                        r = log_oom();
                        goto finish;
                }

                r = json_transform_one(m, elements + n_elements);
                if (r < 0)
                        goto finish;

                n_elements++;
        }

        r = json_variant_new_array(ret, elements, n_elements);

finish:
        json_variant_unref_many(elements, n_elements);
        free(elements);

        return r;
}

int json_transform_variant(sd_bus_message *m, const char *contents, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *value = NULL;
        int r;

        assert(m);
        assert(contents);
        assert(ret);

        r = json_transform_one(m, &value);
        if (r < 0)
                return r;

        r = json_build(ret, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("type", JSON_BUILD_STRING(contents)),
                                              JSON_BUILD_PAIR("data", JSON_BUILD_VARIANT(value))));
        if (r < 0)
                return log_oom();

        return r;
}

static int json_transform_dict_array(sd_bus_message *m, JsonVariant **ret) {
        size_t n_elements = 0, n_allocated = 0;
        JsonVariant **elements = NULL;
        int r;

        assert(m);
        assert(ret);

        for (;;) {
                const char *contents;
                char type;

                r = sd_bus_message_at_end(m, false);
                if (r < 0) {
                        bus_log_parse_error(r);
                        goto finish;
                }
                if (r > 0)
                        break;

                r = sd_bus_message_peek_type(m, &type, &contents);
                if (r < 0)
                        return r;

                assert(type == 'e');

                if (!GREEDY_REALLOC(elements, n_allocated, n_elements + 2)) {
                        r = log_oom();
                        goto finish;
                }

                r = sd_bus_message_enter_container(m, type, contents);
                if (r < 0) {
                        bus_log_parse_error(r);
                        goto finish;
                }

                r = json_transform_one(m, elements + n_elements);
                if (r < 0)
                        goto finish;

                n_elements++;

                r = json_transform_one(m, elements + n_elements);
                if (r < 0)
                        goto finish;

                n_elements++;

                r = sd_bus_message_exit_container(m);
                if (r < 0) {
                        bus_log_parse_error(r);
                        goto finish;
                }
        }

        r = json_variant_new_object(ret, elements, n_elements);

finish:
        json_variant_unref_many(elements, n_elements);
        free(elements);

        return r;
}

static int json_transform_one(sd_bus_message *m, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        const char *contents;
        char type;
        int r;

        assert(m);
        assert(ret);

        r = sd_bus_message_peek_type(m, &type, &contents);
        if (r < 0)
                return bus_log_parse_error(r);

        switch (type) {

        case SD_BUS_TYPE_BYTE: {
                uint8_t b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = json_variant_new_unsigned(&v, b);
                if (r < 0)
                        return log_error_errno(r, "Failed to transform byte: %m");

                break;
        }

        case SD_BUS_TYPE_BOOLEAN: {
                int b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = json_variant_new_boolean(&v, b);
                if (r < 0)
                        return log_error_errno(r, "Failed to transform boolean: %m");

                break;
        }

        case SD_BUS_TYPE_INT16: {
                int16_t b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = json_variant_new_integer(&v, b);
                if (r < 0)
                        return log_error_errno(r, "Failed to transform int16: %m");

                break;
        }

        case SD_BUS_TYPE_UINT16: {
                uint16_t b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = json_variant_new_unsigned(&v, b);
                if (r < 0)
                        return log_error_errno(r, "Failed to transform uint16: %m");

                break;
        }

        case SD_BUS_TYPE_INT32: {
                int32_t b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = json_variant_new_integer(&v, b);
                if (r < 0)
                        return log_error_errno(r, "Failed to transform int32: %m");

                break;
        }

        case SD_BUS_TYPE_UINT32: {
                uint32_t b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = json_variant_new_unsigned(&v, b);
                if (r < 0)
                        return log_error_errno(r, "Failed to transform uint32: %m");

                break;
        }

        case SD_BUS_TYPE_INT64: {
                int64_t b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = json_variant_new_integer(&v, b);
                if (r < 0)
                        return log_error_errno(r, "Failed to transform int64: %m");

                break;
        }

        case SD_BUS_TYPE_UINT64: {
                uint64_t b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = json_variant_new_unsigned(&v, b);
                if (r < 0)
                        return log_error_errno(r, "Failed to transform uint64: %m");

                break;
        }

        case SD_BUS_TYPE_DOUBLE: {
                double d;

                r = sd_bus_message_read_basic(m, type, &d);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = json_variant_new_real(&v, d);
                if (r < 0)
                        return log_error_errno(r, "Failed to transform double: %m");

                break;
        }

        case SD_BUS_TYPE_STRING:
        case SD_BUS_TYPE_OBJECT_PATH:
        case SD_BUS_TYPE_SIGNATURE: {
                const char *s;

                r = sd_bus_message_read_basic(m, type, &s);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = json_variant_new_string(&v, s);
                if (r < 0)
                        return log_error_errno(r, "Failed to transform double: %m");

                break;
        }

        case SD_BUS_TYPE_UNIX_FD:
                r = sd_bus_message_read_basic(m, type, NULL);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = json_variant_new_null(&v);
                if (r < 0)
                        return log_error_errno(r, "Failed to transform fd: %m");

                break;

        case SD_BUS_TYPE_ARRAY:
        case SD_BUS_TYPE_VARIANT:
        case SD_BUS_TYPE_STRUCT:
                r = sd_bus_message_enter_container(m, type, contents);
                if (r < 0)
                        return bus_log_parse_error(r);

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
                        return bus_log_parse_error(r);

                break;

        default:
                assert_not_reached("Unexpected element type");
        }

        *ret = TAKE_PTR(v);
        return 0;
}

int json_transform_message(sd_bus_message *m, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        const char *type;
        int r;

        assert(m);
        assert(ret);

        assert_se(type = sd_bus_message_get_signature(m, false));

        r = json_transform_array_or_struct(m, &v);
        if (r < 0)
                return r;

        r = json_build(ret, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("type",  JSON_BUILD_STRING(type)),
                                              JSON_BUILD_PAIR("data", JSON_BUILD_VARIANT(v))));
        if (r < 0)
                return log_oom();

        return 0;
}
