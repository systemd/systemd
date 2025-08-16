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

static int add_modules_from_conf_file(ConfFile *c) {
        _cleanup_fclose_ FILE *f = NULL;
        int ret = 0, r;

        assert(c);

        f = fopen(FORMAT_PROC_FD_PATH(c->fd), "re");
        if (!f)
                return log_error_errno(errno, "Failed to open file %s: %m", c->original_path);

        log_debug("add modules from: %s", c->original_path);
        for (;;) {
                _cleanup_free_ char *line = NULL;

                r = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read file %s: %m", c->original_path);
                if (r == 0)
                        break;

                if (isempty(line))
                        continue;
                if (strchr(COMMENTS, *line))
                        continue;
                if (!string_is_safe_ascii(line))
                        continue;

                r = add_module_load(line);
                if (r < 0) {
                        log_error_errno(r, "Failed to enable load for module '%s': %m", line);
                        RET_GATHER(ret, r);
                }
        }

        return ret;
}

static int add_modules_from_cmdline(void) {
        int ret = 0, r;

        STRV_FOREACH(i, arg_proc_cmdline_modules) {
                r = add_module_load(*i);
                if (r != 0)
                        RET_GATHER(ret, log_error_errno(r, "Failed to enable load for module '%s': %m", *i));
        }

        return ret;
}

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        ConfFile **files = NULL;
        size_t n_files = 0;
        int ret = 0, r;

        CLEANUP_ARRAY(files, n_files, conf_file_free_many);

        assert_se(arg_dest = dest);

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, PROC_CMDLINE_STRIP_RD_PREFIX);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        ret = add_modules_from_cmdline();

        r = conf_files_list_nulstr_full(".conf", /* root = */ NULL, CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED,
                                        conf_file_dirs, &files, &n_files);
        if (r < 0)
                return RET_GATHER(ret, log_error_errno(r, "Failed to enumerate modules-load.d files: %m"));

        FOREACH_ARRAY(cf, files, n_files)
                RET_GATHER(r, add_modules_from_conf_file(*cf));

        return ret;
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
