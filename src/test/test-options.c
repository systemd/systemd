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
                char **remaining) {

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

        OptionParser state = {};
        const Option *opt;
        const char *arg;
        for (int c; (c = option_parse(options, options + n_options, &state, argc, argv, &opt, &arg)) != 0; ) {
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

        char **args = option_parser_get_args(&state, argc, argv);
        ASSERT_TRUE(strv_equal(args, remaining));
        ASSERT_STREQ(argv[0], saved_argv0);

        ASSERT_EQ(option_parser_get_n_args(&state, argc, argv), strv_length(remaining));
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

        OptionParser state = {};
        const Option *opt;
        const char *arg;

        int c = option_parse(options, options + n_options, &state, argc, argv, &opt, &arg);
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
                              NULL);

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
                                        "string4"));

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
                                        "string4"));

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
                                        "string4"));

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
                                        "string4"));

        test_option_parse_one(STRV_MAKE("arg0",
                                        "--help"),
                              options,
                              (Entry[]) {
                                      { "help" },
                                      {}
                              },
                              NULL);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "-h"),
                              options,
                              (Entry[]) {
                                      { "help" },
                                      {}
                              },
                              NULL);

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
                                        "string4"));

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
                                        "string4"));

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
                                        "string4"));

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
                                        "string4"));

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
                                        "string4"));

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
                                        "string4"));

        test_option_parse_one(STRV_MAKE("arg0",
                                        "--required1", "reqarg1"),
                              options,
                              (Entry[]) {
                                      { "required1", "reqarg1" },
                                      {}
                              },
                              NULL);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "-r", "reqarg1"),
                              options,
                              (Entry[]) {
                                      { "required1", "reqarg1" },
                                      {}
                              },
                              NULL);

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
                                        "string2"));

        test_option_parse_one(STRV_MAKE("arg0",
                                        "--optional1=optarg1"),
                              options,
                              (Entry[]) {
                                      { "optional1", "optarg1" },
                                      {}
                              },
                              NULL);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "--optional1", "string1"),
                              options,
                              (Entry[]) {
                                      { "optional1", NULL },
                                      {}
                              },
                              STRV_MAKE("string1"));

        test_option_parse_one(STRV_MAKE("arg0",
                                        "-ooptarg1"),
                              options,
                              (Entry[]) {
                                      { "optional1", "optarg1" },
                                      {}
                              },
                              NULL);

        test_option_parse_one(STRV_MAKE("arg0",
                                        "-o", "string1"),
                              options,
                              (Entry[]) {
                                      { "optional1", NULL },
                                      {}
                              },
                              STRV_MAKE("string1"));

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
                                        "--optional1"));
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
                                        "foo"));

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
                                        "bar"));

        /* --exec with no trailing args */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "--exec"),
                              options,
                              (Entry[]) {
                                      { "exec" },
                                      {}
                              },
                              NULL);

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
                                        "val"));

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
                              STRV_MAKE("--help"));

        /* "--" before --exec: "--" terminates first, --exec is positional */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "--",
                                        "--exec",
                                        "--help"),
                              options,
                              NULL,
                              STRV_MAKE("--exec",
                                        "--help"));

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
                                        "val2"));
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
                              NULL);

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
                              NULL);

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
                              NULL);

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
                              NULL);

        /* Long option without = does NOT consume the next arg */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "--output", "foo.txt"),
                              options,
                              (Entry[]) {
                                      { "output", NULL },
                                      {}
                              },
                              STRV_MAKE("foo.txt"));

        /* Short option with inline arg */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "-ofoo.txt"),
                              options,
                              (Entry[]) {
                                      { "output", "foo.txt" },
                                      {}
                              },
                              NULL);

        /* Short option without inline arg does NOT consume the next arg */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "-o", "foo.txt"),
                              options,
                              (Entry[]) {
                                      { "output", NULL },
                                      {}
                              },
                              STRV_MAKE("foo.txt"));

        /* Optional arg option at end of argv */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "--output"),
                              options,
                              (Entry[]) {
                                      { "output", NULL },
                                      {}
                              },
                              NULL);

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
                              NULL);

        /* Short combo: -ho (h then o with no arg) */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "-ho", "pos1"),
                              options,
                              (Entry[]) {
                                      { "help" },
                                      { "output", NULL },
                                      {}
                              },
                              STRV_MAKE("pos1"));

        /* Short combo: -hobar (h then o with inline arg "bar") */
        test_option_parse_one(STRV_MAKE("arg0",
                                        "-hobar"),
                              options,
                              (Entry[]) {
                                      { "help" },
                                      { "output", "bar" },
                                      {}
                              },
                              NULL);
}

/* Test the OPTION, OPTION_LONG, OPTION_SHORT, OPTION_FULL, OPTION_GROUP macros
 * by using them in a FOREACH_OPTION_FULL switch, as they would be used in real code. */

static void test_macros_parse_one(
                char **argv,
                const Entry *entries,
                char **remaining) {

        _cleanup_free_ char *joined = strv_join(argv, ", ");
        log_debug("/* %s(%s) */", __func__, joined);

        _cleanup_free_ char *saved_argv0 = NULL;
        ASSERT_NOT_NULL(saved_argv0 = strdup(argv[0]));

        int argc = strv_length(argv);
        size_t i = 0, n_entries = 0;

        for (const Entry *e = entries; e && (e->long_code || e->short_code != 0); e++)
                n_entries++;

        OptionParser state = {};
        const Option *opt;
        const char *arg;

        FOREACH_OPTION_FULL(&state, c, argc, argv, &opt, &arg, ASSERT_TRUE(false)) {
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

                /* OPTION_FULL: stops parsing */
                OPTION_FULL(OPTION_STOPS_PARSING, 0, "exec", NULL, "Stop parsing after this"):
                        break;

                /* OPTION_GROUP: group marker (never returned by parser) */
                OPTION_GROUP("Advanced"):
                        break;

                /* OPTION_LONG: long only, in the "Advanced" group */
                OPTION_LONG("debug", NULL, "Enable debug mode"):
                        break;

                default:
                        log_error("Unexpected option id: %d", c);
                        ASSERT_TRUE(false);
                }
        }

        ASSERT_EQ(i, n_entries);

        char **args = option_parser_get_args(&state, argc, argv);
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
                              NULL);

        /* OPTION: short form */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "-h"),
                              (Entry[]) {
                                      { "help" },
                                      {}
                              },
                              NULL);

        /* OPTION_LONG: only accessible via long form */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--version"),
                              (Entry[]) {
                                      { "version" },
                                      {}
                              },
                              NULL);

        /* OPTION_SHORT: only accessible via short form */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "-v"),
                              (Entry[]) {
                                      { .short_code = 'v' },
                                      {}
                              },
                              NULL);

        /* OPTION with required arg: long --required=ARG */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--required=val1"),
                              (Entry[]) {
                                      { "required", "val1" },
                                      {}
                              },
                              NULL);

        /* OPTION with required arg: long --required ARG */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--required", "val1"),
                              (Entry[]) {
                                      { "required", "val1" },
                                      {}
                              },
                              NULL);

        /* OPTION with required arg: short -r ARG */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "-r", "val1"),
                              (Entry[]) {
                                      { "required", "val1" },
                                      {}
                              },
                              NULL);

        /* OPTION with required arg: short -rARG */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "-rval1"),
                              (Entry[]) {
                                      { "required", "val1" },
                                      {}
                              },
                              NULL);

        /* OPTION_FULL with OPTION_OPTIONAL_ARG: long with = */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--optional=val1"),
                              (Entry[]) {
                                      { "optional", "val1" },
                                      {}
                              },
                              NULL);

        /* OPTION_FULL with OPTION_OPTIONAL_ARG: long without = doesn't consume next */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--optional", "pos1"),
                              (Entry[]) {
                                      { "optional", NULL },
                                      {}
                              },
                              STRV_MAKE("pos1"));

        /* OPTION_FULL with OPTION_OPTIONAL_ARG: short inline */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "-oval1"),
                              (Entry[]) {
                                      { "optional", "val1" },
                                      {}
                              },
                              NULL);

        /* OPTION_FULL with OPTION_OPTIONAL_ARG: short without inline */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "-o", "pos1"),
                              (Entry[]) {
                                      { "optional", NULL },
                                      {}
                              },
                              STRV_MAKE("pos1"));

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
                                        "--version"));

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
                                        "--debug"));

        /* OPTION_STOPS_PARSING with "--": "--" after exec is still consumed */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--exec",
                                        "--",
                                        "--help"),
                              (Entry[]) {
                                      { "exec" },
                                      {}
                              },
                              STRV_MAKE("--help"));

        /* OPTION_STOPS_PARSING with "--": "--" before exec takes precedence */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--",
                                        "--exec",
                                        "--help"),
                              (Entry[]) {
                                      {}
                              },
                              STRV_MAKE("--exec",
                                        "--help"));

        /* OPTION_GROUP: group marker is transparent to parsing, --debug in Advanced group works */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "--debug"),
                              (Entry[]) {
                                      { "debug" },
                                      {}
                              },
                              NULL);

        /* Mixed: all macro types together */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "pos1",
                                        "-h",
                                        "--version",
                                        "-v",
                                        "--required=rval",
                                        "--optional=oval",
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
                                      { "debug" },
                                      { "optional", NULL },
                                      { "help" },
                                      {}
                              },
                              STRV_MAKE("pos1",
                                        "pos2"));

        /* Short option combos with macros: -hv (help + verbose) */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "-hv"),
                              (Entry[]) {
                                      { "help" },
                                      { .short_code = 'v' },
                                      {}
                              },
                              NULL);

        /* Short option combo with required arg: -hrval (help + required with arg "val") */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "-hrval"),
                              (Entry[]) {
                                      { "help" },
                                      { "required", "val" },
                                      {}
                              },
                              NULL);

        /* Short option combo with optional arg: -hoval (help + optional with arg "val") */
        test_macros_parse_one(STRV_MAKE("arg0",
                                        "-hoval"),
                              (Entry[]) {
                                      { "help" },
                                      { "optional", "val" },
                                      {}
                              },
                              NULL);

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
                                        "-h"));

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
                                        "-h"));

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
                                        "-h"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
