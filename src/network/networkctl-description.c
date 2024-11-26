/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "glob-util.h"
#include "json-util.h"
#include "networkctl.h"
#include "networkctl-description.h"
#include "networkctl-util.h"
#include "stdio-util.h"
#include "strv.h"

static int get_description(sd_bus *bus, sd_json_variant **ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *text;
        int r;

        assert(bus);
        assert(ret);

        r = bus_call_method(bus, bus_network_mgr, "Describe", &error, &reply, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to get description: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "s", &text);
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_json_parse(text, 0, ret, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to parse JSON: %m");

        return 0;
}

static int dump_manager_description(sd_bus *bus) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(bus);

        r = get_description(bus, &v);
        if (r < 0)
                return r;

        sd_json_variant_dump(v, arg_json_format_flags, NULL, NULL);
        return 0;
}

static int dump_link_description(sd_bus *bus, char * const *patterns) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ bool *matched_patterns = NULL;
        sd_json_variant *i;
        size_t c = 0;
        int r;

        assert(bus);
        assert(patterns);

        r = get_description(bus, &v);
        if (r < 0)
                return r;

        matched_patterns = new0(bool, strv_length(patterns));
        if (!matched_patterns)
                return log_oom();

        JSON_VARIANT_ARRAY_FOREACH(i, sd_json_variant_by_key(v, "Interfaces")) {
                char ifindex_str[DECIMAL_STR_MAX(int64_t)];
                const char *name;
                int64_t index;
                size_t pos;

                name = sd_json_variant_string(sd_json_variant_by_key(i, "Name"));
                index = sd_json_variant_integer(sd_json_variant_by_key(i, "Index"));
                xsprintf(ifindex_str, "%" PRIi64, index);

                if (!strv_fnmatch_full(patterns, ifindex_str, 0, &pos) &&
                    !strv_fnmatch_full(patterns, name, 0, &pos)) {
                        bool match = false;
                        sd_json_variant *a;

                        JSON_VARIANT_ARRAY_FOREACH(a, sd_json_variant_by_key(i, "AlternativeNames"))
                                if (strv_fnmatch_full(patterns, sd_json_variant_string(a), 0, &pos)) {
                                        match = true;
                                        break;
                                }

                        if (!match)
                                continue;
                }

                matched_patterns[pos] = true;
                sd_json_variant_dump(i, arg_json_format_flags, NULL, NULL);
                c++;
        }

        /* Look if we matched all our arguments that are not globs. It is OK for a glob to match
         * nothing, but not for an exact argument. */
        for (size_t pos = 0; pos < strv_length(patterns); pos++) {
                if (matched_patterns[pos])
                        continue;

                if (string_is_glob(patterns[pos]))
                        log_debug("Pattern \"%s\" doesn't match any interface, ignoring.",
                                  patterns[pos]);
                else
                        return log_error_errno(SYNTHETIC_ERRNO(ENODEV),
                                               "Interface \"%s\" not found.", patterns[pos]);
        }

        if (c == 0)
                log_warning("No interfaces matched.");

        return 0;
}

int dump_description(int argc, char *argv[]) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        if (!sd_json_format_enabled(arg_json_format_flags))
                return 0;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        if (arg_all || argc <= 1)
                r = dump_manager_description(bus);
        else
                r = dump_link_description(bus, strv_skip(argv, 1));
        if (r < 0)
                return r;

        return 1; /* done */
}
