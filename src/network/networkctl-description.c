/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink.h"

#include "alloc-util.h"
#include "glob-util.h"
#include "json-util.h"
#include "log.h"
#include "networkctl.h"
#include "networkctl-description.h"
#include "networkctl-util.h"
#include "stdio-util.h"
#include "strv.h"
#include "varlink-util.h"

static int dump_manager_description(sd_varlink *vl) {
        sd_json_variant *v;
        int r;

        assert(vl);

        r = varlink_call_and_log(vl, "io.systemd.Network.Describe", /* parameters= */ NULL, &v);
        if (r < 0)
                return r;

        r = sd_json_variant_dump(v, arg_json_format_flags, /* f= */ NULL, /* prefix= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to dump json object: %m");
        return 0;
}

static int dump_link_description(sd_varlink *vl, char * const *patterns) {
        _cleanup_free_ bool *matched_patterns = NULL;
        sd_json_variant *i, *v;
        size_t c = 0;
        int r;

        assert(vl);
        assert(patterns);

        r = varlink_call_and_log(vl, "io.systemd.Network.Describe", /* parameters= */ NULL, &v);
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
        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *vl = NULL;
        int r;

        if (!sd_json_format_enabled(arg_json_format_flags))
                return 0;

        r = varlink_connect_networkd(&vl);
        if (r < 0)
                return r;

        if (arg_all || argc <= 1)
                r = dump_manager_description(vl);
        else
                r = dump_link_description(vl, strv_skip(argv, 1));
        if (r < 0)
                return r;

        return 1; /* done */
}
