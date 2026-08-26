/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

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
        .man_pages = "systemd.1\0",
};

static const Verb introspect_verbs[] = {
        { .flags = VERB_COMMAND_MARKER, .data = (uintptr_t) &introspect_command },
        { .verb = "alpha", .min_args = VERB_ANY, .max_args = VERB_ANY, .dispatch = noop_dispatcher,
          .argspec = "ARG", .help = "Alpha verb", .option_namespace = "test-verbs-alpha" },
        { .verb = "beta", .min_args = VERB_ANY, .max_args = VERB_ANY, .dispatch = noop_dispatcher,
          .help = "Beta verb" },
        { .verb = "gamma", .flags = VERB_OPTION_REQUIRED,
          .min_args = VERB_ANY, .max_args = VERB_ANY, .dispatch = noop_dispatcher,
          .help = "Gamma verb", .footer = "Gamma footer" },
};

static const Option introspect_options[] = {
        { 1, .long_code = "test-verbs-alpha", .flags = OPTION_NAMESPACE_MARKER },
        { 2, .short_code = 'x', .long_code = "example", .metavar = "ARG", .help = "An example option" },
};

TEST(introspect_cli_verb_options) {
        /* Gcc doesn't like introspect_verbs + ELEMENTSOF(introspect_verbs) and
         * introspect_options + ELEMENTSOF(introspect_options) being passes as param.
         * But we are passing those pointers as delimiters, never reading the data. */
        DISABLE_WARNING_STRINGOP_OVERREAD;
        ASSERT_OK(_introspect_cli(introspect_verbs, introspect_verbs + ELEMENTSOF(introspect_verbs),
                                  introspect_options, introspect_options + ELEMENTSOF(introspect_options),
                                  SD_JSON_FORMAT_OFF));
        REENABLE_WARNING;
}

TEST(command_print_verb_help) {
        DISABLE_WARNING_STRINGOP_OVERREAD;
        ASSERT_OK(_command_print_verb_help(introspect_verbs, introspect_verbs + ELEMENTSOF(introspect_verbs),
                                           introspect_options, introspect_options + ELEMENTSOF(introspect_options),
                                           "alpha"));
        ASSERT_OK(_command_print_verb_help(introspect_verbs, introspect_verbs + ELEMENTSOF(introspect_verbs),
                                           introspect_options, introspect_options + ELEMENTSOF(introspect_options),
                                           "beta"));
        ASSERT_OK(_command_print_verb_help(introspect_verbs, introspect_verbs + ELEMENTSOF(introspect_verbs),
                                           introspect_options, introspect_options + ELEMENTSOF(introspect_options),
                                           "gamma"));
        REENABLE_WARNING;
}

DEFINE_TEST_MAIN(LOG_INFO);
