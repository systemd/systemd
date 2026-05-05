/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "alloc-util.h"
#include "conf-files.h"
#include "format-table.h"
#include "help-util.h"
#include "log.h"
#include "options.h"
#include "parse-argument.h"
#include "pretty-print.h"
#include "static-destruct.h"
#include "udevadm.h"
#include "udevadm-util.h"

static char *arg_root = NULL;
static CatFlags arg_cat_flags = 0;
static bool arg_config = false;

STATIC_DESTRUCTOR_REGISTER(arg_root, freep);

static int help(void) {
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = option_parser_get_help_table_ns("udevadm-cat", &options);
        if (r < 0)
                return r;

        help_cmdline("cat [OPTIONS...] [FILE...]");
        help_abstract("Show udev rules files.");
        help_section("Options");
        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("udevadm", "8");
        return 0;
}

static int parse_argv(int argc, char *argv[], char ***remaining_args) {
        int r;

        assert(argc >= 0);
        assert(argv);
        assert(remaining_args);

        OptionParser opts = { argc, argv, .namespace = "udevadm-cat" };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_NAMESPACE("udevadm-cat"): {}

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION_WITH_HIDDEN_V:
                        return print_version();

                OPTION_LONG("root", "PATH",
                            "Operate on an alternate filesystem root"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ true, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("tldr", NULL,
                            "Skip comments and empty lines"):
                        arg_cat_flags = CAT_TLDR;
                        break;

                OPTION_LONG("config", NULL,
                            "Show udev.conf rather than udev rules files"):
                        arg_config = true;
                        break;
                }

        if (arg_config && option_parser_get_n_args(&opts) > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Combination of --config and FILEs is not supported.");

        *remaining_args = option_parser_get_args(&opts);
        return 1;
}

int verb_cat_main(int argc, char *argv[], uintptr_t _data, void *userdata) {
        char **args = NULL;
        int r;

        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        if (arg_config)
                return conf_files_cat(arg_root, "udev/udev.conf", arg_cat_flags);

        ConfFile **files = NULL;
        size_t n_files = 0;

        CLEANUP_ARRAY(files, n_files, conf_file_free_array);

        r = search_rules_files(args, arg_root, &files, &n_files);
        if (r < 0)
                return r;

        /* udev rules file does not support dropin configs. So, we can safely pass multiple files as dropins. */
        return cat_files_full(/* file= */ NULL, files, n_files, arg_cat_flags);
}
