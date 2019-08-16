/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "dirent-util.h"
#include "dropin.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio-label.h"
#include "fs-util.h"
#include "hashmap.h"
#include "log.h"
#include "macro.h"
#include "mkdir.h"
#include "path-util.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"

int drop_in_file(const char *dir, const char *unit, unsigned level,
                 const char *name, char **ret_p, char **ret_q) {

        char prefix[DECIMAL_STR_MAX(unsigned)];
        _cleanup_free_ char *b = NULL, *p = NULL, *q = NULL;

        assert(unit);
        assert(name);
        assert(ret_p);
        assert(ret_q);

        sprintf(prefix, "%u", level);

        b = xescape(name, "/.");
        if (!b)
                return -ENOMEM;

        if (!filename_is_valid(b))
                return -EINVAL;

        p = strjoin(dir, "/", unit, ".d");
        q = strjoin(p, "/", prefix, "-", b, ".conf");
        if (!p || !q)
                return -ENOMEM;

        *ret_p = TAKE_PTR(p);
        *ret_q = TAKE_PTR(q);
        return 0;
}

int write_drop_in(const char *dir, const char *unit, unsigned level,
                  const char *name, const char *data) {

        _cleanup_free_ char *p = NULL, *q = NULL;
        int r;

        assert(dir);
        assert(unit);
        assert(name);
        assert(data);

        r = drop_in_file(dir, unit, level, name, &p, &q);
        if (r < 0)
                return r;

        (void) mkdir_p(p, 0755);
        return write_string_file_atomic_label(q, data);
}

int write_drop_in_format(const char *dir, const char *unit, unsigned level,
                         const char *name, const char *format, ...) {
        _cleanup_free_ char *p = NULL;
        va_list ap;
        int r;

        assert(dir);
        assert(unit);
        assert(name);
        assert(format);

        va_start(ap, format);
        r = vasprintf(&p, format, ap);
        va_end(ap);

        if (r < 0)
                return -ENOMEM;

        return write_drop_in(dir, unit, level, name, p);
}

static int unit_file_add_dir(
                const char *original_root,
                const char *path,
                char ***dirs) {

        _cleanup_free_ char *chased = NULL;
        int r;

        assert(path);

        /* This adds [original_root]/path to dirs, if it exists. */

        r = chase_symlinks(path, original_root, 0, &chased);
        if (r == -ENOENT) /* Ignore -ENOENT, after all most units won't have a drop-in dir. */
                return 0;
        if (r == -ENAMETOOLONG) {
                /* Also, ignore -ENAMETOOLONG but log about it. After all, users are not even able to create the
                 * drop-in dir in such case. This mostly happens for device units with an overly long /sys path. */
                log_debug_errno(r, "Path '%s' too long, couldn't canonicalize, ignoring.", path);
                return 0;
        }
        if (r < 0)
                return log_warning_errno(r, "Failed to canonicalize path '%s': %m", path);

        if (strv_consume(dirs, TAKE_PTR(chased)) < 0)
                return log_oom();

        return 0;
}

static int unit_file_find_dirs(
                const char *original_root,
                Set *unit_path_cache,
                const char *unit_path,
                const char *name,
                const char *suffix,
                char ***dirs) {

        _cleanup_free_ char *prefix = NULL, *instance = NULL, *built = NULL;
        bool is_instance, chopped;
        const char *dash;
        UnitType type;
        char *path;
        size_t n;
        int r;

        assert(unit_path);
        assert(name);
        assert(suffix);

        path = strjoina(unit_path, "/", name, suffix);
        if (!unit_path_cache || set_get(unit_path_cache, path)) {
                r = unit_file_add_dir(original_root, path, dirs);
                if (r < 0)
                        return r;
        }

        is_instance = unit_name_is_valid(name, UNIT_NAME_INSTANCE);
        if (is_instance) { /* Also try the template dir */
                _cleanup_free_ char *template = NULL;

                r = unit_name_template(name, &template);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate template from unit name: %m");

                r = unit_file_find_dirs(original_root, unit_path_cache, unit_path, template, suffix, dirs);
                if (r < 0)
                        return r;
        }

        /* Let's see if there's a "-" prefix for this unit name. If so, let's invoke ourselves for it. This will then
         * recursively do the same for all our prefixes. i.e. this means given "foo-bar-waldo.service" we'll also
         * search "foo-bar-.service" and "foo-.service".
         *
         * Note the order in which we do it: we traverse up adding drop-ins on each step. This means the more specific
         * drop-ins may override the more generic drop-ins, which is the intended behaviour. */

        r = unit_name_to_prefix(name, &prefix);
        if (r < 0)
                return log_error_errno(r, "Failed to derive unit name prefix from unit name: %m");

        chopped = false;
        for (;;) {
                dash = strrchr(prefix, '-');
                if (!dash) /* No dash? if so we are done */
                        return 0;

                n = (size_t) (dash - prefix);
                if (n == 0) /* Leading dash? If so, we are done */
                        return 0;

                if (prefix[n+1] != 0 || chopped) {
                        prefix[n+1] = 0;
                        break;
                }

                /* Trailing dash? If so, chop it off and try again, but not more than once. */
                prefix[n] = 0;
                chopped = true;
        }

        if (!unit_prefix_is_valid(prefix))
                return 0;

        type = unit_name_to_type(name);
        if (type < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Failed to to derive unit type from unit name: %s",
                                       name);

        if (is_instance) {
                r = unit_name_to_instance(name, &instance);
                if (r < 0)
                        return log_error_errno(r, "Failed to derive unit name instance from unit name: %m");
        }

        r = unit_name_build_from_type(prefix, instance, type, &built);
        if (r < 0)
                return log_error_errno(r, "Failed to build prefix unit name: %m");

        return unit_file_find_dirs(original_root, unit_path_cache, unit_path, built, suffix, dirs);
}

int unit_file_find_dropin_paths(
                const char *original_root,
                char **lookup_path,
                Set *unit_path_cache,
                const char *dir_suffix,
                const char *file_suffix,
                const Set *names,
                char ***ret) {

        _cleanup_strv_free_ char **dirs = NULL;
        char *name, **p;
        Iterator i;
        int r;

        assert(ret);

        SET_FOREACH(name, names, i)
                STRV_FOREACH(p, lookup_path)
                        (void) unit_file_find_dirs(original_root, unit_path_cache, *p, name, dir_suffix, &dirs);

        if (strv_isempty(dirs)) {
                *ret = NULL;
                return 0;
        }

        r = conf_files_list_strv(ret, file_suffix, NULL, 0, (const char**) dirs);
        if (r < 0)
                return log_warning_errno(r, "Failed to create the list of configuration files: %m");

        return 1;
}
