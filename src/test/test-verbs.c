/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "sd-json.h"

#include "build.h"
#include "fd-util.h"
#include "fileio.h"
#include "generator.h"
#include "options.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
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

static void test_common_parse_argv_mode_one(
                OptionParserMode mode,
                char **argv,
                size_t min_args,
                size_t max_args,
                int expected,
                char **expected_args) {

        _cleanup_free_ char *joined = strv_join(argv, ", ");
        log_debug("/* %s(%i, %s, %zu, %zu) */", __func__, (int) mode, joined, min_args, max_args);

        char **args = NULL;
        ASSERT_EQ(_common_parse_argv(common_verbs, common_verbs + ELEMENTSOF(common_verbs) - 1,
                                     /* options= */ NULL, /* options_end= */ NULL,
                                     (int) strv_length(argv), argv,
                                     mode, min_args, max_args, max_args > 0 ? &args : NULL),
                  expected);
        if (expected > 0 && max_args > 0)
                ASSERT_TRUE(strv_equal(args, expected_args));
        else
                ASSERT_NULL(args);
}

static void test_common_parse_argv_one(
                char **argv,
                size_t min_args,
                size_t max_args,
                int expected,
                char **expected_args) {
        test_common_parse_argv_mode_one(OPTION_PARSER_NORMAL, argv, min_args, max_args,
                                        expected, expected_args);
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

        /* With OPTION_PARSER_STOP_AT_FIRST_NONOPTION, everything from the first positional argument on
         * is data, even if it looks like an option or "--". */
        test_common_parse_argv_mode_one(OPTION_PARSER_STOP_AT_FIRST_NONOPTION,
                                        STRV_MAKE("test-verbs", "--help", "x"), 0, SIZE_MAX, 0, NULL);
        test_common_parse_argv_mode_one(OPTION_PARSER_STOP_AT_FIRST_NONOPTION,
                                        STRV_MAKE("test-verbs", "-x", "y"), 0, SIZE_MAX, -EINVAL, NULL);
        test_common_parse_argv_mode_one(OPTION_PARSER_STOP_AT_FIRST_NONOPTION,
                                        STRV_MAKE("test-verbs", "--", "-x", "y"), 0, SIZE_MAX, 1,
                                        STRV_MAKE("-x", "y"));
        test_common_parse_argv_mode_one(OPTION_PARSER_STOP_AT_FIRST_NONOPTION,
                                        STRV_MAKE("test-verbs", "x", "--help"), 0, SIZE_MAX, 1,
                                        STRV_MAKE("x", "--help"));
        test_common_parse_argv_mode_one(OPTION_PARSER_STOP_AT_FIRST_NONOPTION,
                                        STRV_MAKE("test-verbs", "x", "--", "-y"), 0, SIZE_MAX, 1,
                                        STRV_MAKE("x", "--", "-y"));
        test_common_parse_argv_mode_one(OPTION_PARSER_STOP_AT_FIRST_NONOPTION,
                                        STRV_MAKE("test-verbs", "x", "--help"), 1, 1, -EINVAL, NULL);
}

static const CommandDescription multicall_command = {
        .names = "other-program\0",
        .abstract = "The other program of a multicall binary.",
        .man_pages = "systemd(1)\0",
        .option_namespace = "common",
};

static const CommandDescription foreign_command = {
        .names = "foreign-program\0",
        .abstract = "The program of a multicall binary which parses its own options.",
        .man_pages = "systemd(1)\0",
        /* .option_namespace unset, like a program with an OptionParser of its own. */
};

/* Two commands in the same namespace, the one named like the test binary listed second, after a
 * command outside of the namespace. */
static const Verb multicall_verbs[] = {
        { .flags = VERB_COMMAND_MARKER, .data = (uintptr_t) &foreign_command },
        { .flags = VERB_COMMAND_MARKER, .data = (uintptr_t) &multicall_command },
        { .flags = VERB_COMMAND_MARKER, .data = (uintptr_t) &common_command },
        {}
};

static void test_common_parse_argv_multicall_one(const char *invoked_as, const char *expected_abstract) {
        int r;

        log_debug("/* %s(%s) */", __func__, strna(invoked_as));

        if (invoked_as)
                ASSERT_OK_ERRNO(setenv("SYSTEMD_INVOKED_AS", invoked_as, /* overwrite= */ true));
        else
                ASSERT_OK_ERRNO(unsetenv("SYSTEMD_INVOKED_AS"));

        /* The help output is the only way to see which command was selected, so capture stdout. */
        _cleanup_close_ int fd = open_tmpfile_unlinkable(/* directory= */ NULL, O_RDWR);
        ASSERT_OK(fd);
        _cleanup_close_ int saved_stdout = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
        ASSERT_OK_ERRNO(saved_stdout);
        ASSERT_OK_ERRNO(fflush(stdout));
        ASSERT_OK_ERRNO(dup2(fd, STDOUT_FILENO));

        r = _common_parse_argv(multicall_verbs, multicall_verbs + ELEMENTSOF(multicall_verbs) - 1,
                               /* options= */ NULL, /* options_end= */ NULL,
                               2, STRV_MAKE("test-verbs", "--help"),
                               OPTION_PARSER_NORMAL,
                               /* min_args= */ 0, /* max_args= */ 0,
                               /* ret_args= */ NULL);

        ASSERT_OK_ERRNO(fflush(stdout));
        ASSERT_OK_ERRNO(dup2(saved_stdout, STDOUT_FILENO));
        ASSERT_EQ(r, 0);

        ASSERT_OK_ERRNO(lseek(fd, 0, SEEK_SET));
        _cleanup_fclose_ FILE *f = take_fdopen(&fd, "r");
        ASSERT_NOT_NULL(f);
        _cleanup_free_ char *output = NULL;
        ASSERT_OK(read_full_stream(f, &output, /* ret_size= */ NULL));
        ASSERT_NOT_NULL(strstr(output, expected_abstract));
}

TEST(common_parse_argv_multicall) {
        /* The command named like the program is described, regardless of the order in the section. */
        test_common_parse_argv_multicall_one(NULL, "Test the parser for the common options.");
        test_common_parse_argv_multicall_one("other-program", "The other program of a multicall binary.");
        test_common_parse_argv_multicall_one("/usr/bin/other-program",
                                             "The other program of a multicall binary.");

        /* A name which contains the command name is accepted, like invoked_as() does, and wins over
         * the position in the section. */
        test_common_parse_argv_multicall_one("other-program.real",
                                             "The other program of a multicall binary.");
        test_common_parse_argv_multicall_one("/usr/lib/other-program-wrapper",
                                             "The other program of a multicall binary.");
        test_common_parse_argv_multicall_one("test-verbs.standalone",
                                             "Test the parser for the common options.");

        /* For any other name, the first command in the namespace is the fallback. */
        test_common_parse_argv_multicall_one("unknown-name", "The other program of a multicall binary.");

        /* A command outside of the namespace is never selected, even if named like the program: its
         * options are not the ones being parsed. */
        test_common_parse_argv_multicall_one("foreign-program", "The other program of a multicall binary.");
        test_common_parse_argv_multicall_one("foreign-program.real",
                                             "The other program of a multicall binary.");

        ASSERT_OK_ERRNO(unsetenv("SYSTEMD_INVOKED_AS"));
}

static void test_common_parse_argv_passthrough_one(char **argv, int expected) {
        _cleanup_free_ char *joined = strv_join(argv, ", ");
        log_debug("/* %s(%s) */", __func__, joined);

        _cleanup_strv_free_ char **copy = strv_copy(argv);
        ASSERT_NOT_NULL(copy);

        ASSERT_EQ(_common_parse_argv_passthrough(common_verbs, common_verbs + ELEMENTSOF(common_verbs) - 1,
                                                 /* options= */ NULL, /* options_end= */ NULL,
                                                 (int) strv_length(argv), argv),
                  expected);

        /* A command line which is passed on must be unchanged. */
        if (expected > 0)
                ASSERT_TRUE(strv_equal(argv, copy));
}

TEST(common_parse_argv_passthrough) {
        /* Nothing but common options is handled. */
        test_common_parse_argv_passthrough_one(STRV_MAKE("test-verbs", "--help"), 0);
        test_common_parse_argv_passthrough_one(STRV_MAKE("test-verbs", "-h"), 0);
        test_common_parse_argv_passthrough_one(STRV_MAKE("test-verbs", "--version"), 0);
        test_common_parse_argv_passthrough_one(STRV_MAKE("test-verbs", "--help", "--version"), 0);

        /* Abbreviations work, and an option which this build refuses is reported, not passed on. */
        test_common_parse_argv_passthrough_one(STRV_MAKE("test-verbs", "--intro"),
                                               experimental_enabled() ? 0 : -EPERM);

        /* Everything else is left alone. */
        test_common_parse_argv_passthrough_one(STRV_MAKE("test-verbs"), 1);
        test_common_parse_argv_passthrough_one(STRV_MAKE("test-verbs", "-c", "true"), 1);
        test_common_parse_argv_passthrough_one(STRV_MAKE("test-verbs", "true", "-c"), 1);
        test_common_parse_argv_passthrough_one(STRV_MAKE("test-verbs", "-i"), 1);
        test_common_parse_argv_passthrough_one(STRV_MAKE("test-verbs", "--norc"), 1);
        test_common_parse_argv_passthrough_one(STRV_MAKE("test-verbs", "--help", "x"), 1);
        test_common_parse_argv_passthrough_one(STRV_MAKE("test-verbs", "--", "x"), 1);
        test_common_parse_argv_passthrough_one(STRV_MAKE("test-verbs", "--"), 1);
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
