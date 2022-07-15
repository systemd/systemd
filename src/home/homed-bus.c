/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "homed-bus.h"
#include "strv.h"

int bus_message_read_secret(sd_bus_message *m, UserRecord **ret, sd_bus_error *error) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL, *full = NULL;
        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        unsigned line = 0, column = 0;
        const char *json;
        int r;

        assert(ret);

        r = sd_bus_message_read(m, "s", &json);
        if (r < 0)
                return r;

        r = json_parse(json, JSON_PARSE_SENSITIVE, &v, &line, &column);
        if (r < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Failed to parse JSON secret record at %u:%u: %m", line, column);

        r = json_build(&full, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("secret", JSON_BUILD_VARIANT(v))));
        if (r < 0)
                return r;

        hr = user_record_new();
        if (!hr)
                return -ENOMEM;

        r = user_record_load(hr, full, USER_RECORD_REQUIRE_SECRET|USER_RECORD_PERMISSIVE);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(hr);
        return 0;
}

int bus_message_read_home_record(sd_bus_message *m, UserRecordLoadFlags flags, UserRecord **ret, sd_bus_error *error) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        unsigned line = 0, column = 0;
        const char *json;
        int r;

        assert(ret);

        r = sd_bus_message_read(m, "s", &json);
        if (r < 0)
                return r;

        r = json_parse(json, JSON_PARSE_SENSITIVE, &v, &line, &column);
        if (r < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Failed to parse JSON identity record at %u:%u: %m", line, column);

        hr = user_record_new();
        if (!hr)
                return -ENOMEM;

        r = user_record_load(hr, v, flags);
        if (r < 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "JSON data is not a valid identity record");

        *ret = TAKE_PTR(hr);
        return 0;
}
