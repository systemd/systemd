/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "strv.h"
#include "tests.h"

typedef struct Entry {
        int opt;
        const char *argument;
        const char *nextarg;
} Entry;

static void test_getopt_long_one(
                char **argv,
                const char *optstring,
                const struct option *longopts,
                const Entry *entries,
                char **remaining) {

        _cleanup_free_ char *joined = strv_join(argv, ", ");
        log_debug("/* %s(%s) */", __func__, joined);

        _cleanup_free_ char *saved_argv0 = NULL;
        ASSERT_NOT_NULL(saved_argv0 = strdup(argv[0]));

        int c, argc = strv_length(argv);
        size_t i = 0, n_entries = 0;

        for (const Entry *e = entries; e && e->opt != 0; e++)
                n_entries++;

        optind = 0;
        while ((c = getopt_long(argc, argv, optstring, longopts, NULL)) >= 0) {
                if (c < 0x100)
                        log_debug("%c: %s", c, strna(optarg));
                else
                        log_debug("0x%x: %s", (unsigned) c, strna(optarg));

                ASSERT_LT(i, n_entries);
                ASSERT_EQ(c, entries[i].opt);
                ASSERT_STREQ(optarg, entries[i].argument);
                if (entries[i].nextarg)
                        ASSERT_STREQ(argv[optind], entries[i].nextarg);
                i++;
        }

        ASSERT_EQ(i, n_entries);
        ASSERT_LE(optind, argc);
        ASSERT_EQ(argc - optind, (int) strv_length(remaining));
        for (int j = optind; j < argc; j++)
                ASSERT_STREQ(argv[j], remaining[j - optind]);
        ASSERT_STREQ(argv[0], saved_argv0);
}

TEST(getopt_long) {
        enum {
                ARG_VERSION = 0x100,
                ARG_REQUIRED,
                ARG_OPTIONAL,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'          },
                { "version" ,  no_argument,       NULL, ARG_VERSION  },
                { "required1", required_argument, NULL, 'r'          },
                { "required2", required_argument, NULL, ARG_REQUIRED },
                { "optional1", optional_argument, NULL, 'o'          },
                { "optional2", optional_argument, NULL, ARG_OPTIONAL },
                {},
        };

        test_getopt_long_one(STRV_MAKE("arg0"),
                             "hr:o::", options,
                             NULL,
                             NULL);

        test_getopt_long_one(STRV_MAKE("arg0",
                                       "string1",
                                       "string2",
                                       "string3",
                                       "string4"),
                             "hr:o::", options,
                             NULL,
                             STRV_MAKE("string1",
                                       "string2",
                                       "string3",
                                       "string4"));

        test_getopt_long_one(STRV_MAKE("arg0",
                                       "--",
                                       "string1",
                                       "string2",
                                       "string3",
                                       "string4"),
                             "hr:o::", options,
                             NULL,
                             STRV_MAKE("string1",
                                       "string2",
                                       "string3",
                                       "string4"));

        test_getopt_long_one(STRV_MAKE("arg0",
                                       "string1",
                                       "string2",
                                       "--",
                                       "string3",
                                       "string4"),
                             "hr:o::", options,
                             NULL,
                             STRV_MAKE("string1",
                                       "string2",
                                       "string3",
                                       "string4"));

        test_getopt_long_one(STRV_MAKE("arg0",
                                       "string1",
                                       "string2",
                                       "string3",
                                       "string4",
                                       "--"),
                             "hr:o::", options,
                             NULL,
                             STRV_MAKE("string1",
                                       "string2",
                                       "string3",
                                       "string4"));

        test_getopt_long_one(STRV_MAKE("arg0",
                                       "--help"),
                             "hr:o::", options,
                             (Entry[]) {
                                     { 'h',          NULL                },
                                     {}
                             },
                             NULL);

        test_getopt_long_one(STRV_MAKE("arg0",
                                       "-h"),
                             "hr:o::", options,
                             (Entry[]) {
                                     { 'h',          NULL                },
                                     {}
                             },
                             NULL);

        test_getopt_long_one(STRV_MAKE("arg0",
                                       "--help",
                                       "string1",
                                       "string2",
                                       "string3",
                                       "string4"),
                             "hr:o::", options,
                             (Entry[]) {
                                     { 'h',          NULL                },
                                     {}
                             },
                             STRV_MAKE("string1",
                                       "string2",
                                       "string3",
                                       "string4"));

        test_getopt_long_one(STRV_MAKE("arg0",
                                       "-h",
                                       "string1",
                                       "string2",
                                       "string3",
                                       "string4"),
                             "hr:o::", options,
                             (Entry[]) {
                                     { 'h',          NULL                },
                                     {}
                             },
                             STRV_MAKE("string1",
                                       "string2",
                                       "string3",
                                       "string4"));

        test_getopt_long_one(STRV_MAKE("arg0",
                                       "string1",
                                       "string2",
                                       "--help",
                                       "string3",
                                       "string4"),
                             "hr:o::", options,
                             (Entry[]) {
                                     { 'h',          NULL                },
                                     {}
                             },
                             STRV_MAKE("string1",
                                       "string2",
                                       "string3",
                                       "string4"));

        test_getopt_long_one(STRV_MAKE("arg0",
                                       "string1",
                                       "string2",
                                       "-h",
                                       "string3",
                                       "string4"),
                             "hr:o::", options,
                             (Entry[]) {
                                     { 'h',          NULL                },
                                     {}
                             },
                             STRV_MAKE("string1",
                                       "string2",
                                       "string3",
                                       "string4"));

        test_getopt_long_one(STRV_MAKE("arg0",
                                       "string1",
                                       "string2",
                                       "string3",
                                       "string4",
                                       "--help"),
                             "hr:o::", options,
                             (Entry[]) {
                                     { 'h',          NULL                },
                                     {}
                             },
                             STRV_MAKE("string1",
                                       "string2",
                                       "string3",
                                       "string4"));

        test_getopt_long_one(STRV_MAKE("arg0",
                                       "string1",
                                       "string2",
                                       "string3",
                                       "string4",
                                       "-h"),
                             "hr:o::", options,
                             (Entry[]) {
                                     { 'h',          NULL                },
                                     {}
                             },
                             STRV_MAKE("string1",
                                       "string2",
                                       "string3",
                                       "string4"));

        test_getopt_long_one(STRV_MAKE("arg0",
                                       "--required1", "reqarg1"),
                             "hr:o::", options,
                             (Entry[]) {
                                     { 'r',          "reqarg1"           },
                                     {}
                             },
                             NULL);

        test_getopt_long_one(STRV_MAKE("arg0",
                                       "-r", "reqarg1"),
                             "hr:o::", options,
                             (Entry[]) {
                                     { 'r',          "reqarg1"           },
                                     {}
                             },
                             NULL);

        test_getopt_long_one(STRV_MAKE("arg0",
                                       "string1",
                                       "string2",
                                       "-r", "reqarg1"),
                             "hr:o::", options,
                             (Entry[]) {
                                     { 'r',          "reqarg1"           },
                                     {}
                             },
                             STRV_MAKE("string1",
                                       "string2"));

        test_getopt_long_one(STRV_MAKE("arg0",
                                       "--optional1=optarg1"),
                             "hr:o::", options,
                             (Entry[]) {
                                     { 'o',          "optarg1"           },
                                     {}
                             },
                             NULL);

        test_getopt_long_one(STRV_MAKE("arg0",
                                       "--optional1", "string1"),
                             "hr:o::", options,
                             (Entry[]) {
                                     { 'o',          NULL,     "string1" },
                                     {}
                             },
                             STRV_MAKE("string1"));

        test_getopt_long_one(STRV_MAKE("arg0",
                                       "-ooptarg1"),
                             "hr:o::", options,
                             (Entry[]) {
                                     { 'o',          "optarg1"           },
                                     {}
                             }, NULL);

        test_getopt_long_one(STRV_MAKE("arg0",
                                       "-o", "string1"),
                             "hr:o::", options,
                             (Entry[]) {
                                     { 'o',          NULL,     "string1" },
                                     {}
                             },
                             STRV_MAKE("string1"));

        test_getopt_long_one(STRV_MAKE("arg0",
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
                             "hr:o::", options,
                             (Entry[]) {
                                     { 'h'                               },
                                     { ARG_VERSION                       },
                                     { 'r',          "reqarg1"           },
                                     { ARG_REQUIRED, "reqarg2"           },
                                     { 'r',          "reqarg3"           },
                                     { ARG_REQUIRED, "reqarg4"           },
                                     { 'o',          NULL,     "string4" },
                                     { ARG_OPTIONAL, NULL,     "string5" },
                                     { 'o',          "optarg1"           },
                                     { ARG_OPTIONAL, "optarg2"           },
                                     { 'h'                               },
                                     { 'r',          "reqarg5"           },
                                     { 'r',          "reqarg6"           },
                                     { 'o',          "optarg3"           },
                                     { 'o',          NULL,     "string6" },
                                     { 'o',          NULL,     "-h"      },
                                     { 'h'                               },
                                     { 'o',          NULL,     "--help"  },
                                     { 'h'                               },
                                     { 'h'                               },
                                     { 'o',          "optarg4"           },
                                     { 'h'                               },
                                     { 'r',          "reqarg6"           },
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
static void test_getopt_one(
                char **argv,
                const char *optstring,
                const Entry *entries,
                char **remaining) {

        _cleanup_free_ char *joined = strv_join(argv, ", ");
        log_debug("/* %s(%s) */", __func__, joined);

        _cleanup_free_ char *saved_argv0 = NULL;
        ASSERT_NOT_NULL(saved_argv0 = strdup(argv[0]));

        int c, argc = strv_length(argv);
        size_t i = 0, n_entries = 0;

        for (const Entry *e = entries; e && e->opt != 0; e++)
                n_entries++;

        optind = 0;
        while ((c = getopt(argc, argv, optstring)) >= 0) {
                log_debug("%c: %s", c, strna(optarg));

                ASSERT_LT(i, n_entries);
                ASSERT_EQ(c, entries[i].opt);
                ASSERT_STREQ(optarg, entries[i].argument);
                if (entries[i].nextarg)
                        ASSERT_STREQ(argv[optind], entries[i].nextarg);
                i++;
        }

        ASSERT_EQ(i, n_entries);
        ASSERT_LE(optind, argc);
        ASSERT_EQ(argc - optind, (int) strv_length(remaining));
        for (int j = optind; j < argc; j++)
                ASSERT_STREQ(argv[j], remaining[j - optind]);
        ASSERT_STREQ(argv[0], saved_argv0);
}

TEST(getopt) {
        test_getopt_one(STRV_MAKE("arg0"),
                        "hr:o::",
                        NULL,
                        NULL);

        test_getopt_one(STRV_MAKE("arg0",
                                  "string1",
                                  "string2"),
                        "hr:o::",
                        NULL,
                        STRV_MAKE("string1",
                                  "string2"));

        test_getopt_one(STRV_MAKE("arg0",
                                  "-h"),
                        "hr:o::",
                        (Entry[]) {
                                { 'h',          NULL                },
                                {}
                        },
                        NULL);

        test_getopt_one(STRV_MAKE("arg0",
                                  "-r", "reqarg1"),
                        "hr:o::",
                        (Entry[]) {
                                { 'r',          "reqarg1"           },
                                {}
                        },
                        NULL);

        test_getopt_one(STRV_MAKE("arg0",
                                  "string1",
                                  "string2",
                                  "-r", "reqarg1"),
                        "hr:o::",
                        (Entry[]) {
                                { 'r',          "reqarg1"           },
                                {}
                        },
                        STRV_MAKE("string1",
                                  "string2"));

        test_getopt_one(STRV_MAKE("arg0",
                                  "-ooptarg1"),
                        "hr:o::",
                        (Entry[]) {
                                { 'o',          "optarg1"           },
                                {}
                        },
                        NULL);

        test_getopt_one(STRV_MAKE("arg0",
                                  "-o", "string1"),
                        "hr:o::",
                        (Entry[]) {
                                { 'o',          NULL,     "string1" },
                                {}
                        },
                        STRV_MAKE("string1"));

        test_getopt_one(STRV_MAKE("arg0",
                                  "string1",
                                  "string2",
                                  "string3",
                                  "-h",
                                  "-r", "reqarg5",
                                  "-rreqarg6",
                                  "-ooptarg3",
                                  "-o",
                                  "string6",
                                  "-o",
                                  "-h",
                                  "-o",
                                  "string7",
                                  "-hooptarg4",
                                  "-hrreqarg6"),
                             "hr:o::",
                             (Entry[]) {
                                     { 'h'                               },
                                     { 'r',          "reqarg5"           },
                                     { 'r',          "reqarg6"           },
                                     { 'o',          "optarg3"           },
                                     { 'o',          NULL,     "string6" },
                                     { 'o',          NULL,     "-h"      },
                                     { 'h'                               },
                                     { 'o',          NULL,     "string7" },
                                     { 'h'                               },
                                     { 'o',          "optarg4"           },
                                     { 'h'                               },
                                     { 'r',          "reqarg6"           },
                                     {}
                             },
                             STRV_MAKE("string1",
                                       "string2",
                                       "string3",
                                       "string6",
                                       "string7"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
