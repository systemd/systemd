/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/utsname.h>
#include <errno.h>
#include <stdio.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "def.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "pager.h"
#include "path-util.h"
#include "pretty-print.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "util.h"

static bool urlify_enabled(void) {
        static int cached_urlify_enabled = -1;

        /* Unfortunately 'less' doesn't support links like this yet 😭, hence let's disable this as long as there's a
         * pager in effect. Let's drop this check as soon as less got fixed a and enough time passed so that it's safe
         * to assume that a link-enabled 'less' version has hit most installations. */

        if (cached_urlify_enabled < 0) {
                int val;

                val = getenv_bool("SYSTEMD_URLIFY");
                if (val >= 0)
                        cached_urlify_enabled = val;
                else
                        cached_urlify_enabled = colors_enabled() && !pager_have();
        }

        return cached_urlify_enabled;
}

int terminal_urlify(const char *url, const char *text, char **ret) {
        char *n;

        assert(url);

        /* Takes an URL and a pretty string and formats it as clickable link for the terminal. See
         * https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda for details. */

        if (isempty(text))
                text = url;

        if (urlify_enabled())
                n = strjoin("\x1B]8;;", url, "\a", text, "\x1B]8;;\a");
        else
                n = strdup(text);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

int file_url_from_path(const char *path, char **ret) {
        _cleanup_free_ char *absolute = NULL;
        struct utsname u;
        char *url = NULL;
        int r;

        if (uname(&u) < 0)
                return -errno;

        if (!path_is_absolute(path)) {
                r = path_make_absolute_cwd(path, &absolute);
                if (r < 0)
                        return r;

                path = absolute;
        }

        /* As suggested by https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda, let's include the local
         * hostname here. Note that we don't use gethostname_malloc() or gethostname_strict() since we are interested
         * in the raw string the kernel has set, whatever it may be, under the assumption that terminals are not overly
         * careful with validating the strings either. */

        url = strjoin("file://", u.nodename, path);
        if (!url)
                return -ENOMEM;

        *ret = url;
        return 0;
}

int terminal_urlify_path(const char *path, const char *text, char **ret) {
        _cleanup_free_ char *url = NULL;
        int r;

        assert(path);

        /* Much like terminal_urlify() above, but takes a file system path as input
         * and turns it into a proper file:// URL first. */

        if (isempty(path))
                return -EINVAL;

        if (isempty(text))
                text = path;

        if (!urlify_enabled()) {
                char *n;

                n = strdup(text);
                if (!n)
                        return -ENOMEM;

                *ret = n;
                return 0;
        }

        r = file_url_from_path(path, &url);
        if (r < 0)
                return r;

        return terminal_urlify(url, text, ret);
}

int terminal_urlify_man(const char *page, const char *section, char **ret) {
        const char *url, *text;

        url = strjoina("man:", page, "(", section, ")");
        text = strjoina(page, "(", section, ") man page");

        return terminal_urlify(url, text, ret);
}

static int cat_file(const char *filename, bool newline) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *urlified = NULL;
        int r;

        f = fopen(filename, "re");
        if (!f)
                return -errno;

        r = terminal_urlify_path(filename, NULL, &urlified);
        if (r < 0)
                return r;

        printf("%s%s# %s%s\n",
               newline ? "\n" : "",
               ansi_highlight_blue(),
               urlified,
               ansi_normal());
        fflush(stdout);

        for (;;) {
                _cleanup_free_ char *line = NULL;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read \"%s\": %m", filename);
                if (r == 0)
                        break;

                puts(line);
        }

        return 0;
}

int cat_files(const char *file, char **dropins, CatFlags flags) {
        char **path;
        int r;

        if (file) {
                r = cat_file(file, false);
                if (r == -ENOENT && (flags & CAT_FLAGS_MAIN_FILE_OPTIONAL))
                        printf("%s# config file %s not found%s\n",
                               ansi_highlight_magenta(),
                               file,
                               ansi_normal());
                else if (r < 0)
                        return log_warning_errno(r, "Failed to cat %s: %m", file);
        }

        STRV_FOREACH(path, dropins) {
                r = cat_file(*path, file || path != dropins);
                if (r < 0)
                        return log_warning_errno(r, "Failed to cat %s: %m", *path);
        }

        return 0;
}

void print_separator(void) {

        /* Outputs a separator line that resolves to whitespace when copied from the terminal. We do that by outputting
         * one line filled with spaces with ANSI underline set, followed by a second (empty) line. */

        if (underline_enabled()) {
                size_t i, c;

                c = columns();

                flockfile(stdout);
                fputs_unlocked(ANSI_UNDERLINE, stdout);

                for (i = 0; i < c; i++)
                        fputc_unlocked(' ', stdout);

                fputs_unlocked(ANSI_NORMAL "\n\n", stdout);
                funlockfile(stdout);
        } else
                fputs("\n\n", stdout);
}

static int guess_type(const char **name, char ***prefixes, bool *is_collection, const char **extension) {
        /* Try to figure out if name is like tmpfiles.d/ or systemd/system-presets/,
         * i.e. a collection of directories without a main config file. */

        _cleanup_free_ char *n = NULL;
        bool usr = false, run = false, coll = false;
        const char *ext = ".conf";
        /* This is static so that the array doesn't get deallocated when we exit the function */
        static const char* const std_prefixes[] = { CONF_PATHS(""), NULL };
        static const char* const usr_prefixes[] = { CONF_PATHS_USR(""), NULL };
        static const char* const run_prefixes[] = { "/run/", NULL };

        if (path_equal(*name, "environment.d"))
                /* Special case: we need to include /etc/environment in the search path, even
                 * though the whole concept is called environment.d. */
                *name = "environment";

        n = strdup(*name);
        if (!n)
                return log_oom();

        delete_trailing_chars(n, "/");

        if (endswith(n, ".d"))
                coll = true;

        if (path_equal(n, "environment"))
                usr = true;

        if (path_equal(n, "udev/hwdb.d"))
                ext = ".hwdb";

        if (path_equal(n, "udev/rules.d"))
                ext = ".rules";

        if (path_equal(n, "kernel/install.d"))
                ext = ".install";

        if (path_equal(n, "systemd/ntp-units.d")) {
                coll = true;
                ext = ".list";
        }

        if (path_equal(n, "systemd/relabel-extra.d")) {
                coll = run = true;
                ext = ".relabel";
        }

        if (PATH_IN_SET(n, "systemd/system-preset", "systemd/user-preset")) {
                coll = true;
                ext = ".preset";
        }

        if (path_equal(n, "systemd/user-preset"))
                usr = true;

        *prefixes = (char**) (usr ? usr_prefixes : run ? run_prefixes : std_prefixes);
        *is_collection = coll;
        *extension = ext;
        return 0;
}

int conf_files_cat(const char *root, const char *name) {
        _cleanup_strv_free_ char **dirs = NULL, **files = NULL;
        _cleanup_free_ char *path = NULL;
        char **prefixes, **prefix;
        bool is_collection;
        const char *extension;
        char **t;
        int r;

        r = guess_type(&name, &prefixes, &is_collection, &extension);
        if (r < 0)
                return r;

        STRV_FOREACH(prefix, prefixes) {
                assert(endswith(*prefix, "/"));
                r = strv_extendf(&dirs, "%s%s%s", *prefix, name,
                                 is_collection ? "" : ".d");
                if (r < 0)
                        return log_error_errno(r, "Failed to build directory list: %m");
        }

        r = conf_files_list_strv(&files, extension, root, 0, (const char* const*) dirs);
        if (r < 0)
                return log_error_errno(r, "Failed to query file list: %m");

        if (!is_collection) {
                path = path_join(root, "/etc", name);
                if (!path)
                        return log_oom();
        }

        if (DEBUG_LOGGING) {
                log_debug("Looking for configuration in:");
                if (path)
                        log_debug("   %s", path);
                STRV_FOREACH(t, dirs)
                        log_debug("   %s/*%s", *t, extension);
        }

        /* show */
        return cat_files(path, files, CAT_FLAGS_MAIN_FILE_OPTIONAL);
}
