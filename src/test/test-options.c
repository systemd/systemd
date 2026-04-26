/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "options.h"
#include "strv.h"
#include "tests.h"

typedef struct Entry {
        const char *long_code;
        const char *argument;
        char short_code;
} Entry;

static void test_option_parse_one(
                char **argv,
                const Option options[],
                const Entry *entries,
                char **remaining,
                OptionParserMode mode) {

        _cleanup_free_ char *joined = strv_join(argv, ", ");
        log_debug("/* %s(%s) */", __func__, joined);

        _cleanup_free_ char *saved_argv0 = NULL;
        ASSERT_NOT_NULL(saved_argv0 = strdup(argv[0]));

        int argc = strv_length(argv);
        size_t i = 0, n_options = 0, n_entries = 0;

        for (const Option *o = options; o->short_code != 0 || o->long_code; o++)
                n_options++;

        for (const Entry *e = entries; e && (e->long_code || e->short_code != 0); e++)
                n_entries++;

        OptionParser state = { argc, argv, mode };
        const Option *opt;
        const char *arg;
        for (int c; (c = option_parse(options, options + n_options, &state, &opt, &arg)) != 0; ) {
                ASSERT_OK(c);
                ASSERT_NOT_NULL(opt);

                log_debug("%c %s: %s=%s",
                          opt->short_code != 0 ? opt->short_code : ' ',
                          opt->long_code ?: "",
                          strnull(opt->metavar), strnull(arg));

                ASSERT_LT(i, n_entries);
                if (entries[i].long_code)
                        ASSERT_TRUE(streq_ptr(opt->long_code, entries[i].long_code));
                if (entries[i].short_code != 0)
                        ASSERT_EQ(opt->short_code, entries[i].short_code);
                ASSERT_TRUE(streq_ptr(arg, entries[i].argument));
                i++;
        }

        ASSERT_EQ(i, n_entries);

        char **args = option_parser_get_args(&state);
        ASSERT_TRUE(strv_equal(args, remaining));
        ASSERT_STREQ(argv[0], saved_argv0);

        ASSERT_EQ(option_parser_get_n_args(&state), strv_length(remaining));
}

static void test_option_invalid_one(
                char **argv,
                const Option options[static 1]) {

        _cleanup_free_ char *joined = strv_join(argv, ", ");
        log_debug("/* %s(%s) */", __func__, joined);

        _cleanup_free_ char *saved_argv0 = NULL;
        ASSERT_NOT_NULL(saved_argv0 = strdup(argv[0]));

        int argc = strv_length(argv);

        size_t n_options = 0;
        for (const Option *o = options; o->short_code != 0 || o->long_code; o++)
                n_options++;

        OptionParser state = { argc, argv };
        const Option *opt;
        const char *arg;

        int c = option_parse(options, options + n_options, &state, &opt, &arg);
        ASSERT_ERROR(c, EINVAL);
}

TEST(option_parse) {
        static const Option options[] = {
                { 1, .short_code = 'h', .long_code = "help" },
                { 2, .long_code = "version" },
                { 3, .short_code = 'r', .long_code = "required1", .metavar = "ARG" },
                { 4, .long_code = "required2", .metavar = "ARG" },
                { 5, .short_code = 'o', .long_code = "optional1", .metavar = "ARG", .flags = OPTION_OPTIONAL_ARG },
                { 6, .long_code = "optional2", .metavar = "ARG", .flags = OPTION_OPTIONAL_ARG },
                {}
        };

        test_option_parse_one(STRV_MAKE("arg0"),
                              options,
                              NULL,
                              NULL,
                              OPTION_PARSER_NORMAL);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "string1",
                                        "string2",
                                        "string3",
                                        "string4"),
                              options,
                              NULL,
                              STRV_MAKE("string1",
                                        "string2",
                                        "string3",
                                        "string4"),
                              OPTION_PARSER_NORMAL);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "--",
                                        "string1",
                                        "--help",
                                        "-h",
                                        "string4"),
                              options,
                              NULL,
                              STRV_MAKE("string1",
                                        "--help",
                                        "-h",
                                        "string4"),
                              OPTION_PARSER_NORMAL);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "string1",
                                        "string2",
                                        "--",
                                        "--",
                                        "string4"),
                              options,
                              NULL,
                              STRV_MAKE("string1",
                                        "string2",
                                        "--",
                                        "string4"),
                              OPTION_PARSER_NORMAL);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "string1",
                                        "string2",
                                        "string3",
                                        "string4",
                                        "--"),
                              options,
                              NULL,
                              STRV_MAKE("string1",
                                        "string2",
                                        "string3",
                                        "string4"),
                              OPTION_PARSER_NORMAL);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "--help"),
                              options,
                              (Entry[]) {
                                      { "help" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "--help",
                                        "string1",
                                        "--help"),
                              options,
                              (Entry[]) {
                                      { "help" },
                                      {}
                              },
                              STRV_MAKE("string1",
                                        "--help"),
                              OPTION_PARSER_STOP_AT_FIRST_NONOPTION);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "-h"),
                              options,
                              (Entry[]) {
                                      { "help" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "--help",
                                        "string1",
                                        "string2",
                                        "string3",
                                        "string4"),
                              options,
                              (Entry[]) {
                                      { "help" },
                                      {}
                              },
                              STRV_MAKE("string1",
                                        "string2",
                                        "string3",
                                        "string4"),
                              OPTION_PARSER_NORMAL);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "-h",
                                        "string1",
                                        "string2",
                                        "string3",
                                        "string4"),
                              options,
                              (Entry[]) {
                                      { "help" },
                                      {}
                              },
                              STRV_MAKE("string1",
                                        "string2",
                                        "string3",
                                        "string4"),
                              OPTION_PARSER_NORMAL);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "string1",
                                        "string2",
                                        "--help",
                                        "string3",
                                        "string4"),
                              options,
                              (Entry[]) {
                                      { "help" },
                                      {}
                              },
                              STRV_MAKE("string1",
                                        "string2",
                                        "string3",
                                        "string4"),
                              OPTION_PARSER_NORMAL);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "string1",
                                        "string2",
                                        "-h",
                                        "string3",
                                        "string4"),
                              options,
                              (Entry[]) {
                                      { "help" },
                                      {}
                              },
                              STRV_MAKE("string1",
                                        "string2",
                                        "string3",
                                        "string4"),
                              OPTION_PARSER_NORMAL);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "string1",
                                        "string2",
                                        "string3",
                                        "string4",
                                        "--help"),
                              options,
                              (Entry[]) {
                                      { "help" },
                                      {}
                              },
                              STRV_MAKE("string1",
                                        "string2",
                                        "string3",
                                        "string4"),
                              OPTION_PARSER_NORMAL);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "string1",
                                        "string2",
                                        "string3",
                                        "string4",
                                        "-h"),
                              options,
                              (Entry[]) {
                                      { "help" },
                                      {}
                              },
                              STRV_MAKE("string1",
                                        "string2",
                                        "string3",
                                        "string4"),
                              OPTION_PARSER_NORMAL);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "--required1", "reqarg1"),
                              options,
                              (Entry[]) {
                                      { "required1", "reqarg1" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "-r", "reqarg1"),
                              options,
                              (Entry[]) {
                                      { "required1", "reqarg1" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "string1",
                                        "string2",
                                        "-r", "reqarg1"),
                              options,
                              (Entry[]) {
                                      { "required1", "reqarg1" },
                                      {}
                              },
                              STRV_MAKE("string1",
                                        "string2"),
                              OPTION_PARSER_NORMAL);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "string1",
                                        "string2",
                                        "-r", "reqarg1"),
                              options,
                              NULL,
                              STRV_MAKE("string1",
                                        "string2",
                                        "-r", "reqarg1"),
                              OPTION_PARSER_STOP_AT_FIRST_NONOPTION);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "--optional1=optarg1"),
                              options,
                              (Entry[]) {
                                      { "optional1", "optarg1" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_STOP_AT_FIRST_NONOPTION);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "--optional1", "string1"),
                              options,
                              (Entry[]) {
                                      { "optional1", NULL },
                                      {}
                              },
                              STRV_MAKE("string1"),
                              OPTION_PARSER_NORMAL);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "-ooptarg1"),
                              options,
                              (Entry[]) {
                                      { "optional1", "optarg1" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "-o", "string1"),
                              options,
                              (Entry[]) {
                                      { "optional1", NULL },
                                      {}
                              },
                              STRV_MAKE("string1"),
                              OPTION_PARSER_NORMAL);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "string1",
                                        "--help",
                                        "--version",
                                        "string2",
                                        "--required1", "reqarg1",
                                        "--required2", "reqarg2",
                                        "--required1=reqarg3",
                                        "--required2=reqarg4",
                                        "string3",
                                        "--optional1", "string4",
                                        "--optional2", "string5",
                                        "--optional1=optarg1",
                                        "--optional2=optarg2",
                                        "-h",
                                        "-r", "reqarg5",
                                        "-rreqarg6",
                                        "-ooptarg3",
                                        "-o",
                                        "string6",
                                        "-o",
                                        "-h",
                                        "-o",
                                        "--help",
                                        "string7",
                                        "-hooptarg4",
                                        "-hrreqarg6",
                                        "--",
                                        "--help",
                                        "--required1",
                                        "--optional1"),
                              options,
                              (Entry[]) {
                                      { "help"                  },
                                      { "version"               },
                                      { "required1",  "reqarg1" },
                                      { "required2",  "reqarg2" },
                                      { "required1",  "reqarg3" },
                                      { "required2",  "reqarg4" },
                                      { "optional1",  NULL      },
                                      { "optional2",  NULL,     },
                                      { "optional1",  "optarg1" },
                                      { "optional2",  "optarg2" },
                                      { "help"                  },
                                      { "required1",  "reqarg5" },
                                      { "required1",  "reqarg6" },
                                      { "optional1",  "optarg3" },
                                      { "optional1",  NULL      },
                                      { "optional1",  NULL      },
                                      { "help"                  },
                                      { "optional1",  NULL      },
                                      { "help"                  },
                                      { "help"                  },
                                      { "optional1",  "optarg4" },
                                      { "help"                  },
                                      { "required1",  "reqarg6" },
                                      {}
                              },
                              STRV_MAKE("string1",
                                        "string2",
                                        "string3",
                                        "string4",
                                        "string5",
                                        "string6",
                                        "string7",
                                        "--help",
                                        "--required1",
                                        "--optional1"),
                              OPTION_PARSER_NORMAL);
}

TEST(option_stops_parsing) {
        static const Option options[] = {
                { 1, .short_code = 'h', .long_code = "help" },
                { 2, .long_code = "version" },
                { 3, .short_code = 'r', .long_code = "required", .metavar = "ARG" },
                { 4, .long_code = "exec", .flags = OPTION_STOPS_PARSING },
                {}
        };

        /* --exec stops parsing, subsequent --help is positional */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "--exec",
                                        "--help",
                                        "foo"),
                              options,
                              (Entry[]) {
                                      { "exec" },
                                      {}
                              },
                              STRV_MAKE("--help",
                                        "foo"),
                              OPTION_PARSER_NORMAL);

        /* Options before --exec are still parsed */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "--help",
                                        "--exec",
                                        "--version",
                                        "bar"),
                              options,
                              (Entry[]) {
                                      { "help" },
                                      { "exec" },
                                      {}
                              },
                              STRV_MAKE("--version",
                                        "bar"),
                              OPTION_PARSER_NORMAL);

        /* --exec with no trailing args */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "--exec"),
                              options,
                              (Entry[]) {
                                      { "exec" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* --exec after positional args */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "pos1",
                                        "--exec",
                                        "--help",
                                        "--required", "val"),
                              options,
                              (Entry[]) {
                                      { "exec" },
                                      {}
                              },
                              STRV_MAKE("pos1",
                                        "--help",
                                        "--required",
                                        "val"),
                              OPTION_PARSER_NORMAL);

        /* "--" after --exec: "--" is still consumed as end-of-options marker. This is needed for
         * backwards compatibility, systemd-dissect implemented this behaviour. But also, it makes
         * sense: we're unlikely to ever want to specify "--" as the first argument of whatever
         * sequence, but the user may want to specify it for clarity. */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "--exec",
                                        "--",
                                        "--help"),
                              options,
                              (Entry[]) {
                                      { "exec" },
                                      {}
                              },
                              STRV_MAKE("--help"),
                              OPTION_PARSER_NORMAL);

        /* "--" before --exec: "--" terminates first, --exec is positional */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "--",
                                        "--exec",
                                        "--help"),
                              options,
                              NULL,
                              STRV_MAKE("--exec",
                                        "--help"),
                              OPTION_PARSER_NORMAL);

        /* Multiple options then --exec then more option-like args */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "--help",
                                        "-r", "val1",
                                        "--exec",
                                        "-h",
                                        "--required", "val2"),
                              options,
                              (Entry[]) {
                                      { "help" },
                                      { "required", "val1" },
                                      { "exec" },
                                      {}
                              },
                              STRV_MAKE("-h",
                                        "--required",
                                        "val2"),
                              OPTION_PARSER_NORMAL);
}

TEST(option_group_marker) {
        static const Option options[] = {
                { 1, .short_code = 'h', .long_code = "help" },
                { 2, .long_code = "version" },
                { 0, .long_code = "AdvancedGroup", .flags = OPTION_GROUP_MARKER },
                { 3, .long_code = "debug" },
                { 4, .long_code = "Advance" },  /* prefix match with the group */
                { 5, .long_code = "defilbrilate" },
                {}
        };

        /* Group markers are skipped by the parser — only real options are returned */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "--help",
                                        "--debug"),
                              options,
                              (Entry[]) {
                                      { "help" },
                                      { "debug" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* Check that group marker name is ignored */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "--debug",
                                        "--version"),
                              options,
                              (Entry[]) {
                                      { "debug" },
                                      { "version" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* Verify that the group marker is not mistaken for an option */
        test_option_invalid_one(STRV_MAKE("arg0",
                                          "--AdvancedGroup"),
                                options);

        /* Verify that the group marker is not mistaken for an option */
        test_option_invalid_one(STRV_MAKE("arg0",
                                          "--AdvancedGroup=2"),
                                options);

        /* Verify that the group marker is not mistaken for an option, prefix match */
        test_option_invalid_one(STRV_MAKE("arg0",
                                          "--Advanced"),
                                options);

        /* Check that group marker name is ignored */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "--Advance",
                                        "--Advan"),  /* prefix match with unique prefix */
                              options,
                              (Entry[]) {
                                      { "Advance" },
                                      { "Advance" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* Partial match with multiple candidates */
        test_option_invalid_one(STRV_MAKE("arg0",
                                          "--de"),
                                options);
}

TEST(option_optional_arg) {
        static const Option options[] = {
                { 1, .short_code = 'o', .long_code = "output", .metavar = "FILE", .flags = OPTION_OPTIONAL_ARG },
                { 2, .short_code = 'h', .long_code = "help" },
                {}
        };

        /* Long option with = gets the argument */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "--output=foo.txt"),
                              options,
                              (Entry[]) {
                                      { "output", "foo.txt" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* Long option without = does NOT consume the next arg */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "--output", "foo.txt"),
                              options,
                              (Entry[]) {
                                      { "output", NULL },
                                      {}
                              },
                              STRV_MAKE("foo.txt"),
                              OPTION_PARSER_NORMAL);

        /* Short option with inline arg */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "-ofoo.txt"),
                              options,
                              (Entry[]) {
                                      { "output", "foo.txt" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* Short option without inline arg does NOT consume the next arg */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "-o", "foo.txt"),
                              options,
                              (Entry[]) {
                                      { "output", NULL },
                                      {}
                              },
                              STRV_MAKE("foo.txt"),
                              OPTION_PARSER_NORMAL);

        /* Optional arg option at end of argv */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "--output"),
                              options,
                              (Entry[]) {
                                      { "output", NULL },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* Mixed: optional arg with other options */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "--help",
                                        "--output=bar",
                                        "--help"),
                              options,
                              (Entry[]) {
                                      { "help" },
                                      { "output", "bar" },
                                      { "help" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* Short combo: -ho (h then o with no arg) */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "-ho", "pos1"),
                              options,
                              (Entry[]) {
                                      { "help" },
                                      { "output", NULL },
                                      {}
                              },
                              STRV_MAKE("pos1"),
                              OPTION_PARSER_NORMAL);

        /* Short combo: -hobar (h then o with inline arg "bar") */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "-hobar"),
                              options,
                              (Entry[]) {
                                      { "help" },
                                      { "output", "bar" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);
}

/* Test the OPTION, OPTION_LONG, OPTION_SHORT, OPTION_FULL, OPTION_GROUP macros
 * by using them in a FOREACH_OPTION_FULL switch, as they would be used in real code. */

static void test_macros_parse_one(
                char **argv,
                const Entry *entries,
                char **remaining,
                OptionParserMode mode) {

        _cleanup_free_ char *joined = strv_join(argv, ", ");
        log_debug("/* %s(%s) */", __func__, joined);

        _cleanup_free_ char *saved_argv0 = NULL;
        ASSERT_NOT_NULL(saved_argv0 = strdup(argv[0]));

        int argc = strv_length(argv);
        size_t i = 0, n_entries = 0;

        for (const Entry *e = entries; e && (e->long_code || e->short_code != 0); e++)
                n_entries++;

        OptionParser state = { argc, argv, mode };
        const Option *opt;
        const char *arg;

        FOREACH_OPTION_FULL(&state, c, &opt, &arg, ASSERT_TRUE(false)) {
                log_debug("%c %s: %s=%s",
                          opt->short_code != 0 ? opt->short_code : ' ',
                          opt->long_code ?: "",
                          strnull(opt->metavar), strnull(arg));

                ASSERT_LT(i, n_entries);
                if (entries[i].long_code)
                        ASSERT_TRUE(streq_ptr(opt->long_code, entries[i].long_code));
                if (entries[i].short_code != 0)
                        ASSERT_EQ(opt->short_code, entries[i].short_code);
                ASSERT_TRUE(streq_ptr(arg, entries[i].argument));

                if (streq_ptr(entries[i].long_code, "optional2"))
                        ASSERT_EQ(opt->data, 666u);
                else
                        ASSERT_EQ(opt->data, 0u);

                i++;

                switch (c) {

                /* OPTION: short + long, no arg */
                OPTION('h', "help", NULL, "Show this help"):
                        break;

                /* OPTION_LONG: long only, no arg */
                OPTION_LONG("version", NULL, "Show package version"):
                        break;

                /* OPTION_SHORT: short only, no arg */
                OPTION_SHORT('v', NULL, "Enable verbose mode"):
                        break;

                /* OPTION: short + long, required arg */
                OPTION('r', "required", "ARG", "Required arg option"):
                        break;

                /* OPTION_FULL: optional arg */
                OPTION_FULL(OPTION_OPTIONAL_ARG, 'o', "optional", "ARG", "Optional arg option"):
                        break;

                /* OPTION_FULL_DATA: optional arg */
                OPTION_FULL_DATA(OPTION_OPTIONAL_ARG, 'O', "optional2", "ARG", 666, "Optional arg option"):
                        break;

                /* OPTION_FULL: stops parsing */
                OPTION_FULL(OPTION_STOPS_PARSING, 0, "exec", NULL, "Stop parsing after this"):
                        break;

                /* OPTION_GROUP: group marker (never returned by parser) */
                OPTION_GROUP("Advanced"): {}

                /* OPTION_LONG: long only, in the "Advanced" group */
                OPTION_LONG("debug", NULL, "Enable debug mode"):
                        break;

                OPTION_POSITIONAL:
                        break;

                default:
                        log_error("Unexpected option id: %d", c);
                        ASSERT_TRUE(false);
                }
        }

        ASSERT_EQ(i, n_entries);

        char **args = option_parser_get_args(&state);
        ASSERT_TRUE(strv_equal(args, remaining));
        ASSERT_STREQ(argv[0], saved_argv0);
}

TEST(option_macros) {
        /* OPTION: long form */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--help"),
                              (Entry[]) {
                                      { "help" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* OPTION: short form */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "-h"),
                              (Entry[]) {
                                      { "help" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* OPTION_LONG: only accessible via long form */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--version"),
                              (Entry[]) {
                                      { "version" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* OPTION_SHORT: only accessible via short form */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "-v"),
                              (Entry[]) {
                                      { .short_code = 'v' },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* OPTION with required arg: long --required=ARG */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--required=val1"),
                              (Entry[]) {
                                      { "required", "val1" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* OPTION with required arg: long --required ARG */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--required", "val1"),
                              (Entry[]) {
                                      { "required", "val1" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* OPTION with required arg: short -r ARG */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "-r", "val1"),
                              (Entry[]) {
                                      { "required", "val1" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* OPTION with required arg: short -rARG */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "-rval1"),
                              (Entry[]) {
                                      { "required", "val1" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* OPTION_FULL with OPTION_OPTIONAL_ARG: long with = */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--optional=val1"),
                              (Entry[]) {
                                      { "optional", "val1" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* OPTION_FULL with OPTION_OPTIONAL_ARG: long without = doesn't consume next */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--optional", "pos1"),
                              (Entry[]) {
                                      { "optional", NULL },
                                      {}
                              },
                              STRV_MAKE("pos1"),
                              OPTION_PARSER_NORMAL);

        /* OPTION_FULL with OPTION_OPTIONAL_ARG: short inline */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "-oval1"),
                              (Entry[]) {
                                      { "optional", "val1" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* OPTION_FULL with OPTION_OPTIONAL_ARG: short without inline */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "-o", "pos1"),
                              (Entry[]) {
                                      { "optional", NULL },
                                      {}
                              },
                              STRV_MAKE("pos1"),
                              OPTION_PARSER_NORMAL);

        /* OPTION_FULL with OPTION_STOPS_PARSING: stops further option parsing */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--exec",
                                        "--help",
                                        "--version"),
                              (Entry[]) {
                                      { "exec" },
                                      {}
                              },
                              STRV_MAKE("--help",
                                        "--version"),
                              OPTION_PARSER_NORMAL);

        /* OPTION_STOPS_PARSING: options before are still parsed */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--help",
                                        "--exec",
                                        "-h",
                                        "--debug"),
                              (Entry[]) {
                                      { "help" },
                                      { "exec" },
                                      {}
                              },
                              STRV_MAKE("-h",
                                        "--debug"),
                              OPTION_PARSER_NORMAL);

        /* OPTION_STOPS_PARSING with "--": "--" after exec is still consumed */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--exec",
                                        "--",
                                        "--help"),
                              (Entry[]) {
                                      { "exec" },
                                      {}
                              },
                              STRV_MAKE("--help"),
                              OPTION_PARSER_NORMAL);

        /* OPTION_STOPS_PARSING with "--": "--" before exec takes precedence */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--",
                                        "--exec",
                                        "--help"),
                              (Entry[]) {
                                      {}
                              },
                              STRV_MAKE("--exec",
                                        "--help"),
                              OPTION_PARSER_NORMAL);

        /* OPTION_GROUP: group marker is transparent to parsing, --debug in Advanced group works */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--debug"),
                              (Entry[]) {
                                      { "debug" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* Mixed: all macro types together */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "pos1",
                                        "-h",
                                        "--version",
                                        "-v",
                                        "--required=rval",
                                        "--optional=oval",
                                        "--optional2=oval",
                                        "--debug",
                                        "pos2",
                                        "-o",
                                        "--help"),
                              (Entry[]) {
                                      { "help" },
                                      { "version" },
                                      { .short_code = 'v' },
                                      { "required", "rval" },
                                      { "optional", "oval" },
                                      { "optional2", "oval" },
                                      { "debug" },
                                      { "optional", NULL },
                                      { "help" },
                                      {}
                              },
                              STRV_MAKE("pos1",
                                        "pos2"),
                              OPTION_PARSER_NORMAL);

        /* Short option combos with macros: -hv (help + verbose) */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "-hv"),
                              (Entry[]) {
                                      { "help" },
                                      { .short_code = 'v' },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* Short option combo with required arg: -hrval (help + required with arg "val") */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "-hrval"),
                              (Entry[]) {
                                      { "help" },
                                      { "required", "val" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* Short option combo with optional arg: -hoval (help + optional with arg "val") */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "-hoval"),
                              (Entry[]) {
                                      { "help" },
                                      { "optional", "val" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* OPTION_STOPS_PARSING then "--": "--" is still consumed after exec */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--help",
                                        "--exec",
                                        "--",
                                        "--version",
                                        "-h"),
                              (Entry[]) {
                                      { "help" },
                                      { "exec" },
                                      {}
                              },
                              STRV_MAKE("--version",
                                        "-h"),
                              OPTION_PARSER_NORMAL);

        /* OPTION_STOPS_PARSING then later "--": "--" is not consumed */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--help",
                                        "--exec",
                                        "--version",
                                        "--",
                                        "-h"),
                              (Entry[]) {
                                      { "help" },
                                      { "exec" },
                                      {}
                              },
                              STRV_MAKE("--version",
                                        "--",
                                        "-h"),
                              OPTION_PARSER_NORMAL);

        /* OPTION_STOPS_PARSING then "--" twice: second "--" is not consumed */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--help",
                                        "--exec",
                                        "--",
                                        "--",
                                        "--version",
                                        "-h"),
                              (Entry[]) {
                                      { "help" },
                                      { "exec" },
                                      {}
                              },
                              STRV_MAKE("--",
                                        "--version",
                                        "-h"),
                              OPTION_PARSER_NORMAL);

        /* Basic OPTION_POSITIONAL use */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--help",
                                        "arg1",
                                        "--debug",
                                        "arg2"),
                              (Entry[]) {
                                      { "help" },
                                      { "(positional)", "arg1" },
                                      { "debug" },
                                      { "(positional)", "arg2" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_RETURN_POSITIONAL_ARGS);

        /* OPTION_POSITIONAL combined with OPTION_STOPS_PARSING */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--help",
                                        "arg1",
                                        "--exec",
                                        "arg2"),
                              (Entry[]) {
                                      { "help" },
                                      { "(positional)", "arg1" },
                                      { "exec" },
                                      {}
                              },
                              STRV_MAKE("arg2"),
                              OPTION_PARSER_RETURN_POSITIONAL_ARGS);
}

/* Test the pattern used by nspawn's --user: an optional-arg option that also
 * peeks at the next arg to handle legacy "space-separated" form. */
TEST(option_optional_arg_consume) {
        static const Option options[] = {
                { 1, .short_code = 'h', .long_code = "help" },
                { 2, .long_code = "user", .metavar = "NAME", .flags = OPTION_OPTIONAL_ARG },
                { 3, .short_code = 'u', .long_code = "uid", .metavar = "USER" },
                {}
        };

        /* --user=NAME: optional arg provided via = */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "--user=root"),
                              options,
                              (Entry[]) {
                                      { "user", "root" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* --user without arg: next arg is an option, so no consumption */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "--user",
                                        "--help"),
                              options,
                              (Entry[]) {
                                      { "user", NULL },
                                      { "help" },
                                      {}
                              },
                              NULL,
                              OPTION_PARSER_NORMAL);

        /* --user without arg: next arg is positional (doesn't start with -).
         * The option parser returns NULL for the arg. The caller would then
         * use option_parser_next_arg/consume_next_arg to grab it. */
        {
                char **argv = STRV_MAKE("arg0", "--user", "someuser", "pos1");
                int argc = strv_length(argv);

                OptionParser state = { argc, argv };
                const Option *opt;
                const char *arg;

                ASSERT_OK_POSITIVE(option_parse(options, options + 3, &state, &opt, &arg));
                ASSERT_STREQ(opt->long_code, "user");
                ASSERT_NULL(arg);
                ASSERT_STREQ(option_parser_next_arg(&state), "someuser");
                ASSERT_STREQ(option_parser_consume_next_arg(&state), "someuser");

                ASSERT_EQ(option_parse(options, options + 3, &state, &opt, &arg), 0);

                ASSERT_TRUE(strv_equal(option_parser_get_args(&state), STRV_MAKE("pos1")));
        }

        /* --user at end of args: no next arg, so scope mode */
        {
                char **argv = STRV_MAKE("arg0", "--user");
                int argc = strv_length(argv);

                OptionParser state = { argc, argv };
                const Option *opt;
                const char *arg;

                ASSERT_OK_POSITIVE(option_parse(options, options + 3, &state, &opt, &arg));
                ASSERT_STREQ(opt->long_code, "user");
                ASSERT_NULL(arg);
                ASSERT_NULL(option_parser_next_arg(&state));
                ASSERT_NULL(option_parser_consume_next_arg(&state));

                ASSERT_EQ(option_parse(options, options + 3, &state, &opt, &arg), 0);

                ASSERT_TRUE(strv_isempty(option_parser_get_args(&state)));
        }

        /* --user followed by -u (option): scope mode, -u gets its own processing */
        {
                char **argv = STRV_MAKE("arg0", "--user", "-u", "nobody");
                int argc = strv_length(argv);

                OptionParser state = { argc, argv };
                const Option *opt;
                const char *arg;

                ASSERT_OK_POSITIVE(option_parse(options, options + 3, &state, &opt, &arg));
                ASSERT_STREQ(opt->long_code, "user");
                ASSERT_NULL(arg);
                ASSERT_STREQ(option_parser_next_arg(&state), "-u");

                ASSERT_OK_POSITIVE(option_parse(options, options + 3, &state, &opt, &arg));
                ASSERT_STREQ(opt->long_code, "uid");
                ASSERT_STREQ(arg, "nobody");
                ASSERT_NULL(option_parser_next_arg(&state));
                ASSERT_NULL(option_parser_consume_next_arg(&state));

                ASSERT_EQ(option_parse(options, options + 3, &state, &opt, &arg), 0);

                ASSERT_TRUE(strv_isempty(option_parser_get_args(&state)));
        }

        /* "Functional test": --user followed by -u (option): scope mode, -u gets its own processing,
         * handled like in a real option parser. */
        {
                char **argv = STRV_MAKE("arg0", "--user", "-u", "nobody", "nogroup", "--user=nobody", "--user");
                int argc = strv_length(argv);

                OptionParser state = { argc, argv };
                const Option *opt;
                const char *arg;
                int scope_seen = 0;
                int nobody_seen = 0;

                for (int c; (c = option_parse(options, options + 3, &state, &opt, &arg)) != 0; ) {
                        ASSERT_OK(c);

                        if (streq_ptr(opt->long_code, "user")) {
                                if (!arg) {
                                        const char *t = option_parser_next_arg(&state);
                                        if (t && t[0] != '-')
                                                arg = option_parser_consume_next_arg(&state);
                                }

                                if (arg) {
                                        ASSERT_STREQ(arg, "nobody");
                                        nobody_seen ++;
                                } else
                                        scope_seen ++;

                        } else if (streq_ptr(opt->long_code, "uid")) {
                                ASSERT_STREQ(arg, "nobody");
                                nobody_seen ++;
                        }
                }

                ASSERT_EQ(nobody_seen, 2);
                ASSERT_EQ(scope_seen, 2);
                ASSERT_TRUE(strv_equal(option_parser_get_args(&state), STRV_MAKE("nogroup")));
        }
}

static void test_option_get_synopsis_one(
                const Option *opt,
                const char *joiner,
                bool show_metavar,
                const char *expected) {
        log_debug("%s", expected);
        _cleanup_free_ char *s = option_get_synopsis(". ", opt, joiner, show_metavar);
        ASSERT_STREQ(s, expected);
}

TEST(option_get_synopsis) {
        test_option_get_synopsis_one(&(const Option) { 0, 0, 'x', "xxx", "X" }, "/",  true,  ". -x/--xxx=X");
        test_option_get_synopsis_one(&(const Option) { 0, 0, 'x', "xxx", "X" }, NULL, true,  ". -x --xxx=X");
        test_option_get_synopsis_one(&(const Option) { 0, 0, 'x', "xxx", "X" }, "/",  false, ". -x/--xxx=" );
        test_option_get_synopsis_one(&(const Option) { 0, 0, 'x', "xxx", "X" }, " ",  true,  ". -x --xxx=X");
        test_option_get_synopsis_one(&(const Option) { 0, 0, 'x', "xxx", "X" }, " ",  false, ". -x --xxx=" );
        test_option_get_synopsis_one(&(const Option) { 0, 0,   0, "xxx", "X" }, "+",  true,  ". --xxx=X"   );
        test_option_get_synopsis_one(&(const Option) { 0, 0,   0, "xxx", "X" }, "+",  false, ". --xxx="    );
        test_option_get_synopsis_one(&(const Option) { 0, 0, 'x', NULL,  "X" }, " ",  true,  ". -x X"      );
        test_option_get_synopsis_one(&(const Option) { 0, 0, 'x', NULL,  "X" }, "/",  false, ". -x"        );

        test_option_get_synopsis_one(&(const Option) { 0, 0, 'x', "xxx", "A B" }, "/", true,  ". -x/--xxx='A B'");
        test_option_get_synopsis_one(&(const Option) { 0, 0, 'x', "xxx", "A B" }, " ", true,  ". -x --xxx='A B'");
        test_option_get_synopsis_one(&(const Option) { 0, 0,   0, "xxx", "A B" }, "+", true,  ". --xxx='A B'"   );
        test_option_get_synopsis_one(&(const Option) { 0, 0, 'x', NULL,  "A B" }, " ", true,  ". -x 'A B'"      );

        test_option_get_synopsis_one(&(const Option) { 0, OPTION_OPTIONAL_ARG, 'x', "xxx", "X" }, "/",  true,  ". -x/--xxx[=X]");
        test_option_get_synopsis_one(&(const Option) { 0, OPTION_OPTIONAL_ARG, 'x', "xxx", "X" }, NULL, true,  ". -x --xxx[=X]");
        /* Note: --xxx[=] would be silly, so we show --xxx=. It's a corner case. Maybe this should change. */
        test_option_get_synopsis_one(&(const Option) { 0, OPTION_OPTIONAL_ARG, 'x', "xxx", "X" }, "/",  false, ". -x/--xxx="   );
        test_option_get_synopsis_one(&(const Option) { 0, OPTION_OPTIONAL_ARG, 'x', "xxx", "X" }, " ",  true,  ". -x --xxx[=X]");
        test_option_get_synopsis_one(&(const Option) { 0, OPTION_OPTIONAL_ARG, 'x', "xxx", "X" }, " ",  false, ". -x --xxx="   );
        test_option_get_synopsis_one(&(const Option) { 0, OPTION_OPTIONAL_ARG,   0, "xxx", "X" }, "+",  true,  ". --xxx[=X]"   );
        test_option_get_synopsis_one(&(const Option) { 0, OPTION_OPTIONAL_ARG,   0, "xxx", "X" }, "+",  false, ". --xxx="      );
        test_option_get_synopsis_one(&(const Option) { 0, OPTION_OPTIONAL_ARG, 'x', NULL,  "X" }, " ",  true,  ". -x [X]"      );
        test_option_get_synopsis_one(&(const Option) { 0, OPTION_OPTIONAL_ARG, 'x', NULL,  "X" }, "/",  false, ". -x"          );

        test_option_get_synopsis_one(&(const Option) { 0, OPTION_OPTIONAL_ARG, 'x', "xxx", "A B" }, "/", true,  ". -x/--xxx[='A B']");
        test_option_get_synopsis_one(&(const Option) { 0, OPTION_OPTIONAL_ARG, 'x', "xxx", "A B" }, " ", true,  ". -x --xxx[='A B']");
        test_option_get_synopsis_one(&(const Option) { 0, OPTION_OPTIONAL_ARG,   0, "xxx", "A B" }, "+", true,  ". --xxx[='A B']"   );
        test_option_get_synopsis_one(&(const Option) { 0, OPTION_OPTIONAL_ARG, 'x', NULL,  "A B" }, " ", true,  ". -x ['A B']"      );

        test_option_get_synopsis_one(&(const Option) { 0, OPTION_OPTIONAL_ARG | OPTION_HELP_ENTRY | OPTION_STOPS_PARSING,
                                                       'x', "xxx", "A B" }, "/", true,  ". -x/--xxx[='A B']");

        test_option_get_synopsis_one(&(const Option) { 0, OPTION_HELP_ENTRY_VERBATIM, 'u', "special special",  "unused" }, "/",  true, ". special special");
        test_option_get_synopsis_one(&(const Option) { 0, OPTION_POSITIONAL_ENTRY, 'u', "(fixed)", "unused" }, "/",  true, ". (fixed)");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
