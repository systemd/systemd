/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "build.h"
#include "generator.h"
#include "options.h"
#include "strv.h"
#include "tests.h"
#include "verbs.h"

static int noop_dispatcher(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return 0;
}

#define test_dispatch_one(argv, verbs, expected) \
        ASSERT_EQ(_dispatch_verb(argv, verbs, verbs + ELEMENTSOF(verbs) - 1, NULL), expected);

TEST(verbs) {
        static const Verb verbs[] = {
                { "help",        VERB_ANY, VERB_ANY, 0,                 noop_dispatcher },
                { "list-images", VERB_ANY, 1,        0,                 noop_dispatcher },
                { "list",        VERB_ANY, 2,        VERB_DEFAULT,      noop_dispatcher },
                { "status",      2,        VERB_ANY, 0,                 noop_dispatcher },
                { "Group2",      VERB_ANY, VERB_ANY, VERB_GROUP_MARKER, NULL            },
                { "show",        VERB_ANY, VERB_ANY, 0,                 noop_dispatcher },
                { "terminate",   2,        VERB_ANY, 0,                 noop_dispatcher },
                { "Group3",      0,        0,        VERB_GROUP_MARKER, NULL            },
                { "login",       2,        2,        0,                 noop_dispatcher },
                { "copy-to",     3,        4,        0,                 noop_dispatcher },
                {}
        };

        /* not found */
        test_dispatch_one(STRV_MAKE("command-not-found"), verbs, -EINVAL);

        /* found */
        test_dispatch_one(STRV_MAKE("show"), verbs, 0);

        /* found, too few args */
        test_dispatch_one(STRV_MAKE("copy-to", "foo"), verbs, -EINVAL);

        /* found, meets min args */
        test_dispatch_one(STRV_MAKE("status", "foo", "bar"), verbs, 0);

        /* found, too many args */
        test_dispatch_one(STRV_MAKE("copy-to", "foo", "bar", "baz", "quux", "qaax"), verbs, -EINVAL);

        /* no verb, but a default is set */
        test_dispatch_one(STRV_EMPTY, verbs, 0);

        /* the group entry shall not be found */
        test_dispatch_one(STRV_MAKE("Group2"), verbs, -EINVAL);

        /* the group entry shall not be found */
        test_dispatch_one(STRV_MAKE("Group3"), verbs, -EINVAL);
}

TEST(verbs_no_default) {
        static const Verb verbs[] = {
                { "help", VERB_ANY, VERB_ANY, 0, noop_dispatcher },
                {},
        };

        test_dispatch_one(STRV_MAKE(NULL), verbs, -EINVAL);
        test_dispatch_one(STRV_MAKE("hel"), verbs, -EINVAL);
        test_dispatch_one(STRV_MAKE("helpp"), verbs, -EINVAL);
        test_dispatch_one(STRV_MAKE("hgrejgoraoiosafso"), verbs, -EINVAL);
}

TEST(verbs_no_default_many) {
        static const Verb verbs[] = {
                { "help",        VERB_ANY, VERB_ANY, 0,                 noop_dispatcher },
                { "list-images", VERB_ANY, 1,        0,                 noop_dispatcher },
                { "list",        VERB_ANY, 2,        0,                 noop_dispatcher },
                { "status",      2,        VERB_ANY, 0,                 noop_dispatcher },
                { "Specials",    VERB_ANY, VERB_ANY, VERB_GROUP_MARKER, NULL            },
                { "show",        VERB_ANY, VERB_ANY, 0,                 noop_dispatcher },
                { "terminate",   2,        VERB_ANY, 0,                 noop_dispatcher },
                { "login",       2,        2,        0,                 noop_dispatcher },
                { "copy-to",     3,        4,        0,                 noop_dispatcher },
                {}
        };

        test_dispatch_one(STRV_MAKE(NULL), verbs, -EINVAL);
        test_dispatch_one(STRV_MAKE("hel"), verbs, -EINVAL);
        test_dispatch_one(STRV_MAKE("helpp"), verbs, -EINVAL);
        test_dispatch_one(STRV_MAKE("hgrejgoraoiosafso"), verbs, -EINVAL);
        test_dispatch_one(STRV_MAKE("Specials"), verbs, -EINVAL);
}

static const CommandDescription introspect_command = {
        .names = "test-verbs\0",
        .abstract = "Test the verb machinery.",
        .man_pages = "systemd(1)\0",
};

static const Verb introspect_verbs[] = {
        { .flags = VERB_COMMAND_MARKER, .data = (uintptr_t) &introspect_command },
        { .verb = "alpha", .min_args = VERB_ANY, .max_args = VERB_ANY, .dispatch = noop_dispatcher,
          .argspec = "FORM1\0FORM2…\0", .help = "Alpha verb", .option_namespace = "test-verbs-alpha" },
        { .verb = "beta", .min_args = VERB_ANY, .max_args = VERB_ANY, .dispatch = noop_dispatcher,
          .help = "Beta verb" },
        { .verb = "Greek Letters", .flags = VERB_GROUP_MARKER },
        { .verb = "gamma", .flags = VERB_OPTION_REQUIRED | VERB_DEPRECATED,
          .min_args = VERB_ANY, .max_args = VERB_ANY, .dispatch = noop_dispatcher,
          .help = "Gamma verb", .footer = "Gamma footer" },
        {}
};

static const Option introspect_options[] = {
        { 1, .long_code = "test-verbs-alpha", .flags = OPTION_NAMESPACE_MARKER },
        { 2, .short_code = 'x', .long_code = "example", .metavar = "ARG", .help = "An example option" },
        { 3, .long_code = "experimental", .flags = OPTION_EXPERIMENTAL, .help = "An experimental option" },
        {}
};

TEST(introspect_cli_verb_options) {
        ASSERT_OK(_introspect_cli(introspect_verbs, introspect_verbs + ELEMENTSOF(introspect_verbs) - 1,
                                  introspect_options, introspect_options + ELEMENTSOF(introspect_options) - 1,
                                  SD_JSON_FORMAT_OFF));
}

TEST(command_print_verb_help) {
        ASSERT_OK(_command_print_verb_help(introspect_verbs, introspect_verbs + ELEMENTSOF(introspect_verbs) - 1,
                                           introspect_options, introspect_options + ELEMENTSOF(introspect_options) - 1,
                                           "alpha"));
        ASSERT_OK(_command_print_verb_help(introspect_verbs, introspect_verbs + ELEMENTSOF(introspect_verbs) - 1,
                                           introspect_options, introspect_options + ELEMENTSOF(introspect_options) - 1,
                                           "beta"));
        ASSERT_OK(_command_print_verb_help(introspect_verbs, introspect_verbs + ELEMENTSOF(introspect_verbs) - 1,
                                           introspect_options, introspect_options + ELEMENTSOF(introspect_options) - 1,
                                           "gamma"));
}

static const CommandDescription common_command = {
        .names = "test-verbs\0",
        .abstract = "Test the parser for the common options.",
        .man_pages = "systemd(1)\0",
        .option_namespace = "common",
};

static const Verb common_verbs[] = {
        { .flags = VERB_COMMAND_MARKER, .data = (uintptr_t) &common_command },
        { .verb = "alpha", .min_args = VERB_ANY, .max_args = VERB_ANY, .dispatch = noop_dispatcher,
          .help = "Alpha verb" },
        {}
};

static void test_common_parse_argv_one(
                char **argv,
                size_t min_args,
                size_t max_args,
                int expected,
                char **expected_args) {

        _cleanup_free_ char *joined = strv_join(argv, ", ");
        log_debug("/* %s(%s, %zu, %zu) */", __func__, joined, min_args, max_args);

        char **args = NULL;
        ASSERT_EQ(_common_parse_argv(common_verbs, common_verbs + ELEMENTSOF(common_verbs) - 1,
                                     /* options= */ NULL, /* options_end= */ NULL,
                                     (int) strv_length(argv), argv,
                                     min_args, max_args, max_args > 0 ? &args : NULL),
                  expected);
        if (expected > 0 && max_args > 0)
                ASSERT_TRUE(strv_equal(args, expected_args));
        else
                ASSERT_NULL(args);
}

TEST(common_parse_argv) {
        /* The common options are defined in libsystemd-shared, hence found even though no options
         * are passed. */
        test_common_parse_argv_one(STRV_MAKE("test-verbs", "--help"), 0, SIZE_MAX, 0, NULL);
        test_common_parse_argv_one(STRV_MAKE("test-verbs", "-h"), 0, SIZE_MAX, 0, NULL);
        test_common_parse_argv_one(STRV_MAKE("test-verbs", "--version"), 0, SIZE_MAX, 0, NULL);
        test_common_parse_argv_one(STRV_MAKE("test-verbs", "--introspect-cli"), 0, SIZE_MAX,
                                   experimental_enabled() ? 0 : -EPERM, NULL);

        /* Positional arguments are returned, and "--" is consumed wherever it appears. */
        test_common_parse_argv_one(STRV_MAKE("test-verbs"), 0, SIZE_MAX, 1, STRV_EMPTY);
        test_common_parse_argv_one(STRV_MAKE("test-verbs", "alpha", "x"), 0, SIZE_MAX, 1,
                                   STRV_MAKE("alpha", "x"));
        test_common_parse_argv_one(STRV_MAKE("test-verbs", "--", "alpha"), 0, SIZE_MAX, 1,
                                   STRV_MAKE("alpha"));
        test_common_parse_argv_one(STRV_MAKE("test-verbs", "alpha", "--", "-x"), 0, SIZE_MAX, 1,
                                   STRV_MAKE("alpha", "-x"));

        /* Anything else is an unknown option. */
        test_common_parse_argv_one(STRV_MAKE("test-verbs", "--foo"), 0, SIZE_MAX, -EINVAL, NULL);
        test_common_parse_argv_one(STRV_MAKE("test-verbs", "-x"), 0, SIZE_MAX, -EINVAL, NULL);
        test_common_parse_argv_one(STRV_MAKE("test-verbs", "alpha", "--foo"), 0, SIZE_MAX, -EINVAL, NULL);

        /* The number of positional arguments is checked, but only after the options were handled. */
        test_common_parse_argv_one(STRV_MAKE("test-verbs"), 0, 0, 1, NULL);
        test_common_parse_argv_one(STRV_MAKE("test-verbs", "--"), 0, 0, 1, NULL);
        test_common_parse_argv_one(STRV_MAKE("test-verbs", "x"), 0, 0, -EINVAL, NULL);
        test_common_parse_argv_one(STRV_MAKE("test-verbs", "--help", "x"), 0, 0, 0, NULL);
        test_common_parse_argv_one(STRV_MAKE("test-verbs"), 1, 1, -EINVAL, NULL);
        test_common_parse_argv_one(STRV_MAKE("test-verbs", "x"), 1, 1, 1, STRV_MAKE("x"));
        test_common_parse_argv_one(STRV_MAKE("test-verbs", "x", "y"), 1, 1, -EINVAL, NULL);
        test_common_parse_argv_one(STRV_MAKE("test-verbs"), 0, 1, 1, STRV_EMPTY);
        test_common_parse_argv_one(STRV_MAKE("test-verbs", "--", "-x"), 0, 1, 1, STRV_MAKE("-x"));
        test_common_parse_argv_one(STRV_MAKE("test-verbs", "x", "y"), 0, 1, -EINVAL, NULL);
        test_common_parse_argv_one(STRV_MAKE("test-verbs", "x", "y"), 1, 2, 1, STRV_MAKE("x", "y"));
}

static const char *generator_dirs[3];

static int test_generator_impl(const char *dest, const char *dest_early, const char *dest_late) {
        generator_dirs[0] = dest;
        generator_dirs[1] = dest_early;
        generator_dirs[2] = dest_late;
        return 42;
}

static void test_generator_main_one(
                char **argv,
                int expected,
                const char *dest,
                const char *dest_early,
                const char *dest_late) {

        _cleanup_free_ char *joined = strv_join(argv, ", ");
        log_debug("/* %s(%s) */", __func__, joined);

        zero(generator_dirs);
        ASSERT_EQ(_generator_main(common_verbs, common_verbs + ELEMENTSOF(common_verbs) - 1,
                                  /* options= */ NULL, /* options_end= */ NULL,
                                  (int) strv_length(argv), argv,
                                  test_generator_impl),
                  expected);
        ASSERT_STREQ(generator_dirs[0], dest);
        ASSERT_STREQ(generator_dirs[1], dest_early);
        ASSERT_STREQ(generator_dirs[2], dest_late);
}

TEST(generator_main) {
        /* One directory is used for all three outputs, three are passed through. */
        test_generator_main_one(STRV_MAKE("test-verbs", "/a"), 42, "/a", "/a", "/a");
        test_generator_main_one(STRV_MAKE("test-verbs", "/a", "/b", "/c"), 42, "/a", "/b", "/c");
        test_generator_main_one(STRV_MAKE("test-verbs", "--", "/a"), 42, "/a", "/a", "/a");

        /* Any other count is rejected before the implementation is called. */
        test_generator_main_one(STRV_MAKE("test-verbs"), -EINVAL, NULL, NULL, NULL);
        test_generator_main_one(STRV_MAKE("test-verbs", "/a", "/b"), -EINVAL, NULL, NULL, NULL);
        test_generator_main_one(STRV_MAKE("test-verbs", "/a", "/b", "/c", "/d"), -EINVAL, NULL, NULL, NULL);

        /* The common options are handled, and win over the count check. */
        test_generator_main_one(STRV_MAKE("test-verbs", "--help"), 0, NULL, NULL, NULL);
        test_generator_main_one(STRV_MAKE("test-verbs", "-h"), 0, NULL, NULL, NULL);
        test_generator_main_one(STRV_MAKE("test-verbs", "--version"), 0, NULL, NULL, NULL);
        test_generator_main_one(STRV_MAKE("test-verbs", "--introspect-cli"),
                                experimental_enabled() ? 0 : -EPERM, NULL, NULL, NULL);
        test_generator_main_one(STRV_MAKE("test-verbs", "--help", "/a", "/b"), 0, NULL, NULL, NULL);
        test_generator_main_one(STRV_MAKE("test-verbs", "--foo", "/a"), -EINVAL, NULL, NULL, NULL);
}

DEFINE_TEST_MAIN(LOG_INFO);
