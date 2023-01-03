/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "missing_threads.h"
#include "parse-util.h"
#include "psi-util.h"
#include "string-util.h"
#include "stat-util.h"
#include "strv.h"

int read_resource_pressure(const char *path, PressureType type, ResourcePressure *ret) {
        _cleanup_free_ char *line = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        unsigned field_filled = 0;
        ResourcePressure rp = {};
        const char *t, *cline;
        char *word;
        int r;

        assert(path);
        assert(IN_SET(type, PRESSURE_TYPE_SOME, PRESSURE_TYPE_FULL));
        assert(ret);

        if (type == PRESSURE_TYPE_SOME)
                t = "some";
        else if (type == PRESSURE_TYPE_FULL)
                t = "full";
        else
                return -EINVAL;

        r = fopen_unlocked(path, "re", &f);
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_free_ char *l = NULL;
                char *w;

                r = read_line(f, LONG_LINE_MAX, &l);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                w = first_word(l, t);
                if (w) {
                        line = TAKE_PTR(l);
                        cline = w;
                        break;
                }
        }

        if (!line)
                return -ENODATA;

        /* extracts either avgX=Y.Z or total=X */
        while ((r = extract_first_word(&cline, &word, NULL, 0)) > 0) {
                _cleanup_free_ char *w = word;
                const char *v;

                if ((v = startswith(w, "avg10="))) {
                        if (field_filled & (1U << 0))
                                return -EINVAL;

                        field_filled |= 1U << 0;
                        r = parse_loadavg_fixed_point(v, &rp.avg10);
                } else if ((v = startswith(w, "avg60="))) {
                        if (field_filled & (1U << 1))
                                return -EINVAL;

                        field_filled |= 1U << 1;
                        r = parse_loadavg_fixed_point(v, &rp.avg60);
                } else if ((v = startswith(w, "avg300="))) {
                        if (field_filled & (1U << 2))
                                return -EINVAL;

                        field_filled |= 1U << 2;
                        r = parse_loadavg_fixed_point(v, &rp.avg300);
                } else if ((v = startswith(w, "total="))) {
                        if (field_filled & (1U << 3))
                                return -EINVAL;

                        field_filled |= 1U << 3;
                        r = safe_atou64(v, &rp.total);
                } else
                        continue;

                if (r < 0)
                        return r;
        }

        if (r < 0)
                return r;

        if (field_filled != 15U)
                return -EINVAL;

        *ret = rp;
        return 0;
}

int is_pressure_supported(void) {
        static thread_local int cached = -1;
        int r;

        /* The pressure files, both under /proc/ and in cgroups, will exist even if the kernel has PSI
         * support disabled; we have to read the file to make sure it doesn't return -EOPNOTSUPP */

        if (cached >= 0)
                return cached;

        FOREACH_STRING(p, "/proc/pressure/cpu", "/proc/pressure/io", "/proc/pressure/memory") {
                r = read_virtual_file(p, 0, NULL, NULL);
                if (r < 0) {
                        if (r == -ENOENT || ERRNO_IS_NOT_SUPPORTED(r))
                                return (cached = false);

                        return r;
                }
        }

        return (cached = true);
}
