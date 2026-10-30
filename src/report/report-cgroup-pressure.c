/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "metrics.h"
#include "path-util.h"
#include "psi-util.h"
#include "report-cgroup.h"
#include "string-util.h"
#include "time-util.h"

static bool pressure_absent(int r) {
        return IN_SET(r, -ENOENT, -ENODATA) || ERRNO_IS_NEG_NOT_SUPPORTED(r);
}

int report_cgroup_pressure_send(
                const MetricFamily *mf,
                sd_varlink *link,
                const char *cgroup_fs_path,
                const char *unit) {

        int r;

        assert(mf && mf[0].name && mf[1].name);
        assert(link);
        assert(cgroup_fs_path);
        assert(unit);

        for (PressureResource resource = 0; resource < _PRESSURE_RESOURCE_MAX; resource++) {
                const char *name = pressure_resource_to_string(resource);

                _cleanup_free_ char *p = path_join(cgroup_fs_path, strjoina(name, ".pressure"));
                if (!p)
                        return log_oom();

                _cleanup_fclose_ FILE *f = NULL;
                r = fopen_unlocked(p, "re", &f);
                if (r < 0) {
                        log_full_errno(pressure_absent(r) ? LOG_DEBUG : LOG_WARNING, r,
                                       "Failed to open '%s', ignoring: %m", p);
                        continue;
                }

                PressureType type;
                FOREACH_ARGUMENT(type, PRESSURE_TYPE_SOME, PRESSURE_TYPE_FULL) {
                        ResourcePressure rp;

                        /* read_resource_pressure_file() consumes the stream up to the line it is
                         * looking for, so rewind between passes. That way, neither the order the
                         * kernel writes the lines in nor the order we ask for them here matters. */
                        rewind(f);

                        r = read_resource_pressure_file(f, type, &rp);
                        if (r < 0) {
                                log_full_errno(pressure_absent(r) ? LOG_DEBUG : LOG_WARNING, r,
                                               "Failed to read '%s', ignoring: %m", p);
                                continue;
                        }

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;
                        r = sd_json_buildo(&fields,
                                           SD_JSON_BUILD_PAIR_STRING("resource", name),
                                           SD_JSON_BUILD_PAIR_STRING("type", pressure_type_to_string(type)));
                        if (r < 0)
                                return r;

                        r = metric_build_send_double(
                                        mf + 0,
                                        link,
                                        unit,
                                        (double) rp.avg10 / LOADAVG_FIXED_POINT_1_0,
                                        fields);
                        if (r < 0)
                                return r;

                        r = metric_build_send_double(
                                        mf + 1,
                                        link,
                                        unit,
                                        (double) rp.total / USEC_PER_SEC,
                                        fields);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}
