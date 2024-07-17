/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdio.h>

#include "alloc-util.h"
#include "build.h"
#include "format-table.h"
#include "gpt.h"
#include "id128-print.h"
#include "main-func.h"
#include "parse-argument.h"
#include "pretty-print.h"
#include "strv.h"
#include "terminal-util.h"
#include "verbs.h"

static Id128PrettyPrintMode arg_mode = ID128_PRINT_ID128;
static sd_id128_t arg_app = SD_ID128_NULL;
static bool arg_value = false;
static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;

static int verb_new(int argc, char **argv, void *userdata) {
        return id128_print_new(arg_mode);
}

static int verb_machine_id(int argc, char **argv, void *userdata) {
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

static int verb_boot_id(int argc, char **argv, void *userdata) {
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

static int verb_invocation_id(int argc, char **argv, void *userdata) {
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

static int verb_var_uuid(int argc, char **argv, void *userdata) {
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

static int verb_show(int argc, char **argv, void *userdata) {
        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        argv = strv_skip(argv, 1);
        if (strv_isempty(argv)) {
                if (!sd_id128_is_null(arg_app))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "'show --app-specific=' can only be used with explicit UUID input.");

                for (const GptPartitionType *e = gpt_partition_type_table; e->name; e++) {
                        r = show_one(&table, e->name, e->uuid, e == gpt_partition_type_table);
                        if (r < 0)
                                return r;
                }
        } else
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

        if (table) {
                r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, arg_legend);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-id128", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] COMMAND\n\n"
               "%sGenerate and print 128-bit identifiers.%s\n"
               "\nCommands:\n"
               "  new                     Generate a new ID\n"
               "  machine-id              Print the ID of current machine\n"
               "  boot-id                 Print the ID of current boot\n"
               "  invocation-id           Print the ID of current invocation\n"
               "  var-partition-uuid      Print the UUID for the /var/ partition\n"
               "  show [NAME|UUID]        Print one or more UUIDs\n"
               "  help                    Show this help\n"
               "\nOptions:\n"
               "  -h --help               Show this help\n"
               "     --no-pager           Do not pipe output into a pager\n"
               "     --no-legend          Do not show the headers and footers\n"
               "     --json=FORMAT        Output inspection data in JSON (takes one of\n"
               "                          pretty, short, off)\n"
               "  -j                      Equivalent to --json=pretty (on TTY) or\n"
               "                          --json=short (otherwise)\n"
               "  -p --pretty             Generate samples of program code\n"
               "  -P --value              Only print the value\n"
               "  -a --app-specific=ID    Generate app-specific IDs\n"
               "  -u --uuid               Output in UUID format\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int verb_help(int argc, char **argv, void *userdata) {
        return help();
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
                ARG_JSON,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'              },
                { "version",      no_argument,       NULL, ARG_VERSION      },
                { "no-pager",     no_argument,       NULL, ARG_NO_PAGER     },
                { "no-legend",    no_argument,       NULL, ARG_NO_LEGEND    },
                { "json",         required_argument, NULL, ARG_JSON         },
                { "pretty",       no_argument,       NULL, 'p'              },
                { "value",        no_argument,       NULL, 'P'              },
                { "app-specific", required_argument, NULL, 'a'              },
                { "uuid",         no_argument,       NULL, 'u'              },
                {},
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hpa:uPj", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case 'j':
                        arg_json_format_flags = SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO;
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

                        break;
                case 'p':
                        arg_mode = ID128_PRINT_PRETTY;
                        arg_value = false;
                        break;

                case 'P':
                        arg_value = true;
                        if (arg_mode == ID128_PRINT_PRETTY)
                                arg_mode = ID128_PRINT_ID128;
                        break;

                case 'a':
                        r = id128_from_string_nonzero(optarg, &arg_app);
                        if (r == -ENXIO)
                                return log_error_errno(r, "Application ID cannot be all zeros.");
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse \"%s\" as application-ID: %m", optarg);
                        break;

                case 'u':
                        arg_mode = ID128_PRINT_UUID;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 1;
}

static int id128_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "new",                VERB_ANY, 1,        0,  verb_new           },
                { "machine-id",         VERB_ANY, 1,        0,  verb_machine_id    },
                { "boot-id",            VERB_ANY, 1,        0,  verb_boot_id       },
                { "invocation-id",      VERB_ANY, 1,        0,  verb_invocation_id },
                { "var-partition-uuid", VERB_ANY, 1,        0,  verb_var_uuid      },
                { "show",               VERB_ANY, VERB_ANY, 0,  verb_show          },
                { "help",               VERB_ANY, VERB_ANY, 0,  verb_help          },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return id128_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
