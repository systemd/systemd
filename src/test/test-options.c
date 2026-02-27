/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "options.h"
#include "strv.h"
#include "tests.h"

typedef struct Entry {
        const char *long_code;
        const char *argument;
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

        for (const Option *o = options; o->short_code || o->long_code; o++)
                n_options++;

        for (const Entry *e = entries; e && e->long_code; e++)
                n_entries++;

        OptionParser state = {};
        const Option *opt;
        const char *arg;
        for (int c; (c = option_parse(options, options + n_options, &state, argc, argv, &opt, &arg)) != 0; ) {
                ASSERT_OK(c);
                ASSERT_NOT_NULL(opt);

                log_debug("%c %s: %s=%s",
                          opt->short_code ?: ' ', opt->long_code ?: "",
                          strnull(opt->metavar), strnull(arg));

                ASSERT_LT(i, n_entries);
                ASSERT_TRUE(streq_ptr(opt->long_code, entries[i].long_code));
                ASSERT_TRUE(streq_ptr(arg, entries[i].argument));
                i++;
        }

        ASSERT_EQ(i, n_entries);

        char **args = option_parser_get_args(&state, argc, argv);
        ASSERT_TRUE(strv_equal(args, remaining));
        ASSERT_STREQ(argv[0], saved_argv0);
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

DEFINE_TEST_MAIN(LOG_DEBUG);
