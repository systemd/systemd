/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "alloc-util.h"
#include "conf-files.h"
#include "dropin.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio-label.h"
#include "mkdir.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

int drop_in_file(const char *dir, const char *unit, unsigned level,
                 const char *name, char **_p, char **_q) {

        _cleanup_free_ char *b = NULL;
        char *p, *q;

        char prefix[DECIMAL_STR_MAX(unsigned)];

        assert(unit);
        assert(name);
        assert(_p);
        assert(_q);

        sprintf(prefix, "%u", level);

        b = xescape(name, "/.");
        if (!b)
                return -ENOMEM;

        if (!filename_is_valid(b))
                return -EINVAL;

        p = strjoin(dir, "/", unit, ".d", NULL);
        if (!p)
                return -ENOMEM;

        q = strjoin(p, "/", prefix, "-", b, ".conf", NULL);
        if (!q) {
                free(p);
                return -ENOMEM;
        }

        *_p = p;
        *_q = q;
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

static int iterate_dir(
                const char *path,
                UnitDependency dependency,
                dependency_consumer_t consumer,
                void *arg,
                char ***strv) {

        _cleanup_closedir_ DIR *d = NULL;
        int r;

        assert(path);

        /* The config directories are special, since the order of the
         * drop-ins matters */
        if (dependency < 0)  {
                r = strv_extend(strv, path);
                if (r < 0)
                        return log_oom();

                return 0;
        }

        assert(consumer);

        d = opendir(path);
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open directory %s: %m", path);
        }

        for (;;) {
                struct dirent *de;
                _cleanup_free_ char *f = NULL;

                errno = 0;
                de = readdir(d);
                if (!de && errno != 0)
                        return log_error_errno(errno, "Failed to read directory %s: %m", path);

                if (!de)
                        break;

                if (hidden_file(de->d_name))
                        continue;

                f = strjoin(path, "/", de->d_name, NULL);
                if (!f)
                        return log_oom();

                r = consumer(dependency, de->d_name, f, arg);
                if (r < 0)
                        return r;
        }

        return 0;
}

int unit_file_process_dir(
                Set *unit_path_cache,
                const char *unit_path,
                const char *name,
                const char *suffix,
                UnitDependency dependency,
                dependency_consumer_t consumer,
                void *arg,
                char ***strv) {

        _cleanup_free_ char *path = NULL;
        int r;

        assert(unit_path);
        assert(name);
        assert(suffix);

        path = strjoin(unit_path, "/", name, suffix, NULL);
        if (!path)
                return log_oom();

        if (!unit_path_cache || set_get(unit_path_cache, path))
                (void) iterate_dir(path, dependency, consumer, arg, strv);

        if (unit_name_is_valid(name, UNIT_NAME_INSTANCE)) {
                _cleanup_free_ char *template = NULL, *p = NULL;
                /* Also try the template dir */

                r = unit_name_template(name, &template);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate template from unit name: %m");

                p = strjoin(unit_path, "/", template, suffix, NULL);
                if (!p)
                        return log_oom();

                if (!unit_path_cache || set_get(unit_path_cache, p))
                        (void) iterate_dir(p, dependency, consumer, arg, strv);
        }

        return 0;
}

int unit_file_find_dropin_paths(
                char **lookup_path,
                Set *unit_path_cache,
                Set *names,
                char ***paths) {

        _cleanup_strv_free_ char **strv = NULL, **ans = NULL;
        Iterator i;
        char *t;
        int r;

        assert(paths);

        SET_FOREACH(t, names, i) {
                char **p;

                STRV_FOREACH(p, lookup_path)
                        unit_file_process_dir(unit_path_cache, *p, t, ".d", _UNIT_DEPENDENCY_INVALID, NULL, NULL, &strv);
        }

        if (strv_isempty(strv))
                return 0;

        r = conf_files_list_strv(&ans, ".conf", NULL, (const char**) strv);
        if (r < 0)
                return log_warning_errno(r, "Failed to get list of configuration files: %m");

        *paths = ans;
        ans = NULL;
        return 1;
}
