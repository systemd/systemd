/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "conf-files.h"
#include "constants.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "generator.h"
#include "log.h"
#include "proc-cmdline.h"
#include "special.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"

static const char *arg_dest = NULL;

static char **arg_proc_cmdline_modules = NULL;
static const char conf_file_dirs[] = CONF_PATHS_NULSTR("modules-load.d");

STATIC_DESTRUCTOR_REGISTER(arg_proc_cmdline_modules, strv_freep);

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        int r;

        if (proc_cmdline_key_streq(key, "modules_load")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = strv_split_and_extend(&arg_proc_cmdline_modules, value, ",", /* filter_duplicates = */ true);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse modules_load= kernel command line option: %m");
        }

        return 0;
}

static int add_module_load(const char *name) {
        _cleanup_free_ char *e = NULL;
        char *p;

        p = strdupa_safe(name);
        if (!p)
                return log_oom();

        e = unit_name_escape(string_replace_char(p, '-', '_'));
        if (!e)
                return log_oom();

        return generator_add_symlink_full(arg_dest, SPECIAL_MODULES_LOAD_TARGET, "wants",
                                          SYSTEM_DATA_UNIT_DIR "/modprobe@.service", e);
}

static int add_modules_from_file(const char *path) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *pp = NULL;
        int r;

        assert(path);

        r = search_and_fopen_nulstr(path, "re", NULL, conf_file_dirs, &f, &pp);
        if (r < 0) {
                if (r == -ENOENT)
                        return 0;

                return log_error_errno(r, "Failed to open %s: %m", path);
        }

        log_debug("add modules from: %s", pp);
        for (;;) {
                _cleanup_free_ char *line = NULL;
                int k;

                k = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (k < 0)
                        return log_error_errno(k, "Failed to read file '%s': %m", pp);
                if (k == 0)
                        break;

                if (isempty(line))
                        continue;
                if (strchr(COMMENTS, *line))
                        continue;
                if (!string_is_safe_ascii(line))
                        continue;

                k = add_module_load(line);
                RET_GATHER(r, k);
        }

        return r;
}

static int add_modules_from_cmdline(void) {
        int r;

        r = 0;
        STRV_FOREACH(i, arg_proc_cmdline_modules) {
                int k = add_module_load(*i);
                if (k != 0)
                        RET_GATHER(r, log_error_errno(k, "Failed to enable load for module %s: %m", *i));
        }

        return r;
}

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        _cleanup_strv_free_ char **files = NULL;
        int k, r;

        assert_se(arg_dest = dest);

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, PROC_CMDLINE_STRIP_RD_PREFIX);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        RET_GATHER(r, add_modules_from_cmdline());

        k = conf_files_list_nulstr(&files, ".conf", NULL, 0, conf_file_dirs);
        if (k < 0)
                RET_GATHER(r, log_error_errno(k, "Failed to enumerate modules-load.d files: %m"));
        else
                STRV_FOREACH(fn, files)
                        RET_GATHER(r, add_modules_from_file(*fn));

        return r;
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
