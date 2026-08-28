/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "alloc-util.h"
#include "homectl-prompts.h"
#include "main-func.h"
#include "options.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "verbs.h"

COMMAND(
        "test-homectl-prompts\0",
        "Exercise homectl prompt functions in isolation.",
);

VERB(verb_groups, "groups", "[USER]\0", VERB_ANY, 2, 0, "Select groups");
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

VERB(verb_shell, "shell", "[USER]\0", VERB_ANY, 2, 0, "Select shell");
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
                        return command_print_help();

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
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
