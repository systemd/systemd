/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "build.h"
#include "format-table.h"
#include "gpt.h"
#include "id128-print.h"
#include "id128-util.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "parse-argument.h"
#include "pretty-print.h"
#include "string-util.h"
#include "strv.h"
#include "verbs.h"

static Id128PrettyPrintMode arg_mode = ID128_PRINT_ID128;
static sd_id128_t arg_app = SD_ID128_NULL;
static bool arg_value = false;
static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;

VERB_NOARG(verb_new, "new", "Generate a new ID");
static int verb_new(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return id128_print_new(arg_mode);
}

VERB_NOARG(verb_machine_id, "machine-id", "Print the ID of current machine");
static int verb_machine_id(int argc, char *argv[], uintptr_t _data, void *userdata) {
        sd_id128_t id;
        int r;

        if (sd_id128_is_null(arg_app))
                r = sd_id128_get_machine(&id);
        else
                r = sd_id128_get_machine_app_specific(arg_app, &id);
        if (r < 0)
                return log_error_errno(r, "Failed to get %smachine-ID: %m",
                                       sd_id128_is_null(arg_app) ? "" : "app-specific ");

        return id128_pretty_print(id, arg_mode);
}

VERB_NOARG(verb_boot_id, "boot-id", "Print the ID of current boot");
static int verb_boot_id(int argc, char *argv[], uintptr_t _data, void *userdata) {
        sd_id128_t id;
        int r;

        if (sd_id128_is_null(arg_app))
                r = sd_id128_get_boot(&id);
        else
                r = sd_id128_get_boot_app_specific(arg_app, &id);
        if (r < 0)
                return log_error_errno(r, "Failed to get %sboot-ID: %m",
                                       sd_id128_is_null(arg_app) ? "" : "app-specific ");

        return id128_pretty_print(id, arg_mode);
}

VERB_NOARG(verb_invocation_id, "invocation-id", "Print the ID of current invocation");
static int verb_invocation_id(int argc, char *argv[], uintptr_t _data, void *userdata) {
        sd_id128_t id;
        int r;

        if (!sd_id128_is_null(arg_app))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Verb \"invocation-id\" cannot be combined with --app-specific=.");

        r = sd_id128_get_invocation(&id);
        if (r < 0)
                return log_error_errno(r, "Failed to get invocation-ID: %m");

        return id128_pretty_print(id, arg_mode);
}

VERB_NOARG(verb_var_uuid, "var-partition-uuid", "Print the UUID for the /var/ partition");
static int verb_var_uuid(int argc, char *argv[], uintptr_t _data, void *userdata) {
        sd_id128_t id;
        int r;

        if (!sd_id128_is_null(arg_app))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Verb \"var-partition-uuid\" cannot be combined with --app-specific=.");

        /* The DPS says that the UUID for /var/ should be keyed with machine-id. */
        r = sd_id128_get_machine_app_specific(SD_GPT_VAR, &id);
        if (r < 0)
                return log_error_errno(r, "Failed to generate machine-specific /var/ UUID: %m");

        return id128_pretty_print(id, arg_mode);
}

static int show_one(Table **table, const char *name, sd_id128_t uuid, bool first) {
        int r;

        assert(table);

        if (!name)
                name = "XYZ";

        if (arg_mode == ID128_PRINT_PRETTY) {
                _cleanup_free_ char *id = NULL;

                id = strreplace(name, "-", "_");
                if (!id)
                        return log_oom();

                ascii_strupper(id);

                r = id128_pretty_print_sample(id, uuid);
                if (r < 0)
                        return r;
                if (!first)
                        puts("");
                return 0;
        }

        if (arg_value)
                return id128_pretty_print(uuid, arg_mode);

        if (!*table) {
                *table = table_new("name", "id");
                if (!*table)
                        return log_oom();

                table_set_width(*table, 0);
        }

        return table_add_many(*table,
                              TABLE_STRING, name,
                              arg_mode == ID128_PRINT_ID128 ? TABLE_ID128 : TABLE_UUID, uuid);
}

VERB(verb_show, "show", "[NAME|UUID]", VERB_ANY, VERB_ANY, 0, "Print one or more UUIDs");
static int verb_show(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        argv = strv_skip(argv, 1);
        if (argv)
                STRV_FOREACH(p, argv) {
                        sd_id128_t uuid;
                        const char *id = NULL;

                        /* Check if the argument is an actual UUID first */
                        bool is_uuid = sd_id128_from_string(*p, &uuid) >= 0;

                        if (is_uuid)
                                id = gpt_partition_type_uuid_to_string(uuid);
                        else {
                                GptPartitionType type;

                                r = gpt_partition_type_from_string(*p, &type);
                                if (r < 0)
                                        return log_error_errno(r, "Unknown identifier \"%s\".", *p);

                                uuid = type.uuid;
                                id = *p;
                        }

                        if (!sd_id128_is_null(arg_app))
                                assert_se(sd_id128_get_app_specific(uuid, arg_app, &uuid) >= 0);

                        r = show_one(&table, id, uuid, p == argv);
                        if (r < 0)
                                return r;
                }
        else {
                if (!sd_id128_is_null(arg_app))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "'show --app-specific=' can only be used with explicit UUID input.");

                for (const GptPartitionType *e = gpt_partition_type_table; e->name; e++) {
                        r = show_one(&table, e->name, e->uuid, e == gpt_partition_type_table);
                        if (r < 0)
                                return r;
                }
        }

        if (table) {
                r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, arg_legend);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        _cleanup_(table_unrefp) Table *options = NULL, *verbs = NULL;
        int r;

        r = terminal_urlify_man("systemd-id128", "1", &link);
        if (r < 0)
                return log_oom();

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        r = verbs_get_help_table(&verbs);
        if (r < 0)
                return r;

        /* Make the 1st column same width in both tables */
        (void) table_sync_column_width(options, 0, verbs, 0);

        printf("%s [OPTIONS...] COMMAND\n\n"
               "%sGenerate and print 128-bit identifiers.%s\n"
               "\nCommands:\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal());
        table_print(verbs, stdout);

        printf("\nOptions:\n");
        table_print(options, stdout);

        printf("\nSee the %s for details.\n", link);
        return 0;
}

VERB_COMMON_HELP(help);

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser state = {};
        const char *arg;

        FOREACH_OPTION(&state, c, argc, argv, &arg, /* on_error= */ return c)
                switch (c) {
                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_COMMON_NO_LEGEND:
                        arg_legend = false;
                        break;

                OPTION_LONG("json", "FORMAT",
                            "Output inspection data in JSON (takes one of pretty, short, off)"):
                        r = parse_json_argument(arg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_SHORT('j', NULL,
                             "Equivalent to --json=pretty (on TTY) or --json=short (otherwise)"):
                        arg_json_format_flags = SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO;
                        break;

                OPTION('p', "pretty", NULL, "Generate samples of program code"):
                        arg_mode = ID128_PRINT_PRETTY;
                        arg_value = false;
                        break;

                OPTION('P', "value", NULL, "Only print the value"):
                        arg_value = true;
                        if (arg_mode == ID128_PRINT_PRETTY)
                                arg_mode = ID128_PRINT_ID128;
                        break;

                OPTION('a', "app-specific", "ID", "Generate app-specific IDs"):
                        r = id128_from_string_nonzero(arg, &arg_app);
                        if (r == -ENXIO)
                                return log_error_errno(r, "Application ID cannot be all zeros.");
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse \"%s\" as application ID: %m", arg);
                        break;

                OPTION('u', "uuid", NULL, "Output in UUID format"):
                        arg_mode = ID128_PRINT_UUID;
                        break;
                }

        *ret_args = option_parser_get_args(&state, argc, argv);
        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        char **args = NULL;  /* unnecessary initialization to appease gcc <= 13 */
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        return dispatch_verb_with_args(args, NULL);
}

DEFINE_MAIN_FUNCTION(run);
