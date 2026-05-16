/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "format-table.h"
#include "help-util.h"
#include "homectl-prompts.h"
#include "main-func.h"
#include "options.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "verbs.h"

static int help(void) {
        _cleanup_(table_unrefp) Table *options = NULL, *verbs = NULL;
        int r;

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        r = verbs_get_help_table(&verbs);
        if (r < 0)
                return r;

        (void) table_sync_column_widths(0, options, verbs);

        help_cmdline("[OPTIONS...] VERB [USERNAME]");
        help_abstract("Exercise homectl prompt functions in isolation.");

        help_section("Verbs");
        r = table_print_or_warn(verbs);
        if (r < 0)
                return r;

        help_section("Options");
        return table_print_or_warn(options);
}

VERB(verb_groups, "groups", "[USER]", VERB_ANY, 2, 0, "Select groups");
static int verb_groups(int argc, char *argv[], uintptr_t _data, void *userdata) {
        assert(argv);

        const char *username = argv[1] ?: "test";
        int r;

        _cleanup_strv_free_ char **t = NULL;

        r = prompt_groups(username, &t);
        if (r < 0)
                return r;

        _cleanup_free_ char *s = ASSERT_PTR(strv_join(t, ", "));
        log_info("groups: %s → %s", username, s);
        return 0;
}

VERB(verb_shell, "shell", "[USER]", VERB_ANY, 2, 0, "Select shell");
static int verb_shell(int argc, char *argv[], uintptr_t _data, void *userdata) {
        assert(argv);

        const char *username = argv[1] ?: "test";
        int r;

        _cleanup_free_ char *s = NULL;

        r = prompt_shell(username, &s);
        if (r < 0)
                return r;

        log_info("shell: %s → %s", username, strnull(s));
        return 0;
}

static int parse_argv(int argc, char **argv, char ***remaining_args) {
        assert(argc >= 0);
        assert(argv);
        assert(remaining_args);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();
                }

        *remaining_args = option_parser_get_args(&opts);
        return 1;
}

static int run(int argc, char **argv) {
        int r;

        test_setup_logging(LOG_DEBUG);

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        return dispatch_verb(args, /* userdata= */ NULL);
}

DEFINE_MAIN_FUNCTION(run);
