/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hashmap.h"
#include "log.h"
#include "mkdir-label.h"
#include "path-util.h"
#include "shutdown-stats.h"
#include "time-util.h"
#include "unit.h"

#define SHUTDOWN_STATS_DIR "/var/lib/systemd/shutdown-stats"
#define SHUTDOWN_STATS_FILE SHUTDOWN_STATS_DIR "/last-shutdown.json"

int manager_save_shutdown_stats(Manager *m) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *units_array = NULL;
        _cleanup_free_ char *json_str = NULL;
        Unit *u;
        int r;

        assert(m);

        if (!MANAGER_IS_SYSTEM(m))
                return 0;

        /* Only save if we're actually shutting down */
        if (!IN_SET(m->objective, MANAGER_REBOOT, MANAGER_POWEROFF, MANAGER_HALT, MANAGER_KEXEC))
                return 0;

        log_debug("Saving shutdown statistics...");

        /* Create array of unit shutdown times */
        r = sd_json_variant_new_array(&units_array, NULL, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to create JSON array: %m");

        HASHMAP_FOREACH(u, m->units) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *unit_obj = NULL;
                usec_t shutdown_time = 0;

                /* Skip units that weren't active or don't have timing info */
                if (u->inactive_enter_timestamp.monotonic == 0 ||
                    u->active_exit_timestamp.monotonic == 0)
                        continue;

                /* Skip units that were stopped before shutdown started */
                if (u->inactive_enter_timestamp.monotonic < m->timestamps[MANAGER_TIMESTAMP_SHUTDOWN_START].monotonic)
                        continue;

                /* Calculate shutdown time */
                if (u->inactive_enter_timestamp.monotonic > u->active_exit_timestamp.monotonic)
                        shutdown_time = u->inactive_enter_timestamp.monotonic - u->active_exit_timestamp.monotonic;

                if (shutdown_time == 0)
                        continue;

                /* Only save units that took time to stop */
                if (!IN_SET(unit_type_from_string(unit_type_to_string(u->type)),
                           UNIT_SERVICE, UNIT_MOUNT, UNIT_SWAP, UNIT_SCOPE, UNIT_SOCKET))
                        continue;

                r = sd_json_buildo(&unit_obj,
                                  SD_JSON_BUILD_PAIR_STRING("unit", u->id),
                                  SD_JSON_BUILD_PAIR_INTEGER("shutdown_time_usec", shutdown_time),
                                  SD_JSON_BUILD_PAIR_INTEGER("active_exit_timestamp", u->active_exit_timestamp.monotonic),
                                  SD_JSON_BUILD_PAIR_INTEGER("inactive_enter_timestamp", u->inactive_enter_timestamp.monotonic));
                if (r < 0)
                        return log_error_errno(r, "Failed to build unit JSON object: %m");

                r = sd_json_variant_append_array(&units_array, unit_obj);
                if (r < 0)
                        return log_error_errno(r, "Failed to append unit to array: %m");
        }

        /* Build the final JSON object */
        r = sd_json_buildo(&v,
                          SD_JSON_BUILD_PAIR_INTEGER("shutdown_start_timestamp", m->timestamps[MANAGER_TIMESTAMP_SHUTDOWN_START].monotonic),
                          SD_JSON_BUILD_PAIR_INTEGER("timestamp", now(CLOCK_REALTIME)),
                          SD_JSON_BUILD_PAIR_VARIANT("units", units_array));
        if (r < 0)
                return log_error_errno(r, "Failed to build JSON object: %m");

        /* Convert to string */
        r = sd_json_variant_format(v, 0, &json_str);
        if (r < 0)
                return log_error_errno(r, "Failed to format JSON: %m");

        /* Create directory if needed */
        r = mkdir_safe_label(SHUTDOWN_STATS_DIR, 0755, 0, 0, MKDIR_WARN_MODE);
        if (r < 0 && r != -EEXIST)
                return log_error_errno(r, "Failed to create shutdown stats directory: %m");

        /* Write to file with sync to ensure it's on disk before shutdown */
        r = write_string_file(SHUTDOWN_STATS_FILE, json_str,
                            WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_SYNC);
        if (r < 0)
                return log_error_errno(r, "Failed to write shutdown stats: %m");

        log_info("Saved shutdown statistics for %zu units to %s",
                sd_json_variant_elements(units_array), SHUTDOWN_STATS_FILE);

        return 0;
}
