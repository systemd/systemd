/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "memstream-util.h"
#include "path-util.h"
#include "process-util.h"
#include "shell-completion.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

#define BASH_COMPLETION_PATH "/usr/share/bash-completion/bash_completion"

static int noop_dispatcher(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return 0;
}

static const char* const colors[] = {
        "red",
        "green",
        NULL
};

static const CommandDescription test_command = { .names = "test-tool\0" };

static const Verb verbs[] = {
        { .flags = VERB_COMMAND_MARKER, .data = (uintptr_t) &test_command },
        { .verb = "build", .min_args = VERB_ANY, .max_args = 1, .dispatch = noop_dispatcher, .help = "Build" },
        { .verb = "inspect", .min_args = 2, .max_args = VERB_ANY, .dispatch = noop_dispatcher, .help = "Inspect",
          .completion = OPTION_COMPLETE_FILE },
        { .verb = "paint", .min_args = 2, .max_args = 2, .dispatch = noop_dispatcher, .help = "Paint",
          .choices = colors },
        { .verb = "read-at", .min_args = 2, .max_args = 2, .dispatch = noop_dispatcher, .help = "Read @file",
          .completion = OPTION_COMPLETE_AT_FILE },
        { .verb = "read-key", .min_args = 2, .max_args = 2, .dispatch = noop_dispatcher, .help = "Read key:@file",
          .completion = OPTION_COMPLETE_KEY_AT_FILE },
        /* A verb without a help text is hidden. */
        { .verb = "hidden", .min_args = VERB_ANY, .max_args = VERB_ANY, .dispatch = noop_dispatcher },
        /* --help doesn't list deprecated verbs. */
        { .verb = "outdated", .min_args = VERB_ANY, .max_args = VERB_ANY, .dispatch = noop_dispatcher,
          .flags = VERB_DEPRECATED, .help = "Outdated" },
        /* The verbs of other commands of a multicall binary are not completed. */
        { .flags = VERB_COMMAND_MARKER, .data = (uintptr_t) &test_command },
        { .verb = "foreign", .min_args = VERB_ANY, .max_args = VERB_ANY, .dispatch = noop_dispatcher, .help = "Foreign" },
        {}
};

static const Option options[] = {
        { .id = 1, .short_code = 'h', .long_code = "help", .help = "Show this help" },
        { .id = 2, .long_code = "file", .metavar = "PATH", .help = "A [file]", .flags = OPTION_REPEATABLE,
          .completion = OPTION_COMPLETE_FILE },
        { .id = 3, .long_code = "dir", .metavar = "DIR", .help = "A directory", .completion = OPTION_COMPLETE_DIRECTORY },
        { .id = 4, .long_code = "text", .metavar = "TEXT|@PATH", .help = "Text", .completion = OPTION_COMPLETE_AT_FILE },
        { .id = 5, .long_code = "section", .metavar = "NAME:TEXT|@PATH", .help = "Section",
          .completion = OPTION_COMPLETE_KEY_AT_FILE },
        { .id = 6, .short_code = 'c', .long_code = "color", .metavar = "COLOR", .help = "Color with 'quotes'", .choices = colors },
        { .id = 7, .short_code = 's', .long_code = "sign", .help = "Sign" },
        { .id = 8, .long_code = "no-sign", .help = "Don't sign" },
        /* An option without a help text is hidden. */
        { .id = 9, .long_code = "secret", .metavar = "PATH" },
        { .id = 10, .short_code = 'd', .long_code = "diff", .metavar = "BOOL", .flags = OPTION_OPTIONAL_ARG,
          .help = "Diff", .choices = colors },
        /* The options of other namespaces are not completed. */
        { .id = 11, .flags = OPTION_NAMESPACE_MARKER, .long_code = "other" },
        { .id = 12, .long_code = "foreign", .help = "Foreign" },
        {}
};

static char* print_completion_full(
                const char *shell,
                const Verb *test_verbs,
                size_t n_verbs,
                const Option *test_options,
                size_t n_options) {
        _cleanup_(memstream_done) MemStream m = {};
        char *script;

        FILE *f = memstream_init(&m);
        ASSERT_NOT_NULL(f);

        ASSERT_OK(_shell_completion_print(f,
                                          test_verbs, test_verbs + n_verbs,
                                          test_options, test_options ? test_options + n_options : NULL,
                                          "test-tool", shell));

        ASSERT_OK(memstream_finalize(&m, &script, /* ret_size= */ NULL));
        return script;
}

static char* print_completion(const char *shell) {
        return print_completion_full(shell, verbs, ELEMENTSOF(verbs) - 1, options, ELEMENTSOF(options) - 1);
}

static void run_script(const char *shell, const char *script, bool syntax_only) {
        _cleanup_free_ char *path = NULL;
        int r;

        if (find_executable(shell, &path) < 0) {
                log_notice("%s not found, not running the script.", shell);
                return;
        }

        _cleanup_(unlink_tempfilep) char file[] = "/var/tmp/test-shell-completion.XXXXXX";
        _cleanup_close_ int fd = ASSERT_OK(mkostemp_safe(file));
        ASSERT_OK(write_string_file(file, script, WRITE_STRING_FILE_AVOID_NEWLINE));

        r = ASSERT_OK(pidref_safe_fork("(sh-syntax)", FORK_WAIT|FORK_LOG|FORK_DEATHSIG_SIGKILL, /* ret= */ NULL));
        if (r == 0) {
                execl(path, shell, syntax_only ? "-n" : "-f", file, NULL);
                _exit(EXIT_FAILURE);
        }
}

TEST(bash) {
        /* The fixture contains visible, hidden, deprecated, and foreign entries. Bash must receive only
         * the visible names and a syntactically valid script. */
        _cleanup_free_ char *script = print_completion("bash");
        log_debug("%s", script);

        ASSERT_NOT_NULL(strstr(script, "__systemd_complete() {"));
        ASSERT_NOT_NULL(strstr(script, "_test_tool_completion() {"));
        ASSERT_NOT_NULL(strstr(script,
                               "    options+=(--help)\n"
                               "    opts[--help]=''\n"
                               "    options+=(-h)\n"
                               "    opts[-h]=''\n"
                               "    options+=(--file)\n"
                               "    opts[--file]='file'\n"));
        ASSERT_NOT_NULL(strstr(script, "    opts[--section]='key-at-file'\n"));
        ASSERT_NOT_NULL(strstr(script, "    choices[-c]='red green'\n"));
        ASSERT_NOT_NULL(strstr(script, "    opts[--diff]='?default'\n"));
        ASSERT_NOT_NULL(strstr(script, "    opts[--secret]='default'\n"));
        ASSERT_NULL(strstr(script, "options+=(--secret)"));
        ASSERT_NOT_NULL(strstr(script,
                               "    verbs+=(paint)\n"
                               "    verb_choices[paint]='red green'\n"
                               "    verb_max[paint]=2\n"));
        ASSERT_NOT_NULL(strstr(script, "    verb_arguments[inspect]='file'\n"));
        ASSERT_NOT_NULL(strstr(script, "complete -F _test_tool_completion test-tool\n"));
        ASSERT_NULL(strstr(script, "hidden"));
        ASSERT_NULL(strstr(script, "outdated"));
        ASSERT_NULL(strstr(script, "foreign"));

        run_script("bash", script, /* syntax_only= */ true);
}

TEST(zsh) {
        /* The same fixture exercises zsh actions, escaping, aliases, and optional arguments. The script
         * must describe the visible entries and pass the shell syntax check. */
        _cleanup_free_ char *script = print_completion("zsh");
        log_debug("%s", script);

        ASSERT_TRUE(startswith(script, "#compdef test-tool\n"));
        ASSERT_NOT_NULL(strstr(script,
                               "    local -a verbs=(\n"
                               "        build:Build\n"
                               "        inspect:Inspect\n"
                               "        paint:Paint\n"));
        ASSERT_NOT_NULL(strstr(script, "(inspect) { _files; } ;;"));
        ASSERT_NOT_NULL(strstr(script, "(paint) (( CURRENT <= 2 )) && { compadd -- red green; } ;;"));
        ASSERT_NOT_NULL(strstr(script, "(read-at) (( CURRENT <= 2 )) && { compset -P @ && _files; } ;;"));
        ASSERT_NOT_NULL(strstr(script, "$'*--file=[A \\\\[file\\\\]]:argument:{_files}'"));
        ASSERT_NOT_NULL(strstr(script, "$'(--dir)--dir=[A directory]:argument:{_files -/}'"));
        ASSERT_NOT_NULL(strstr(script, "$'(--text)--text=[Text]:argument:{compset -P @ && _files}'"));
        ASSERT_NOT_NULL(strstr(script, "$'(--section)--section=[Section]:argument:"
                                       "{compset -P 1 \\'*\\\\:\\' && compset -P 1 \\'*@\\' && _files}'"));
        ASSERT_NOT_NULL(strstr(script, "$'(--color -c)--color=[Color with \\'quotes\\']:argument:(red green)'"));
        ASSERT_NOT_NULL(strstr(script, "$'(--sign -s --no-sign)--sign[Sign]'"));
        ASSERT_NOT_NULL(strstr(script, "(--no-sign --sign -s)--no-sign"));
        ASSERT_NOT_NULL(strstr(script, "!(--secret)--secret=[]:argument:"));
        ASSERT_NOT_NULL(strstr(script, "$'(--diff -d)--diff=-[Diff]::argument:(red green)'"));
        ASSERT_NOT_NULL(strstr(script, "$'(--diff -d)-d-[Diff]::argument:(red green)'"));
        ASSERT_NOT_NULL(strstr(script, "'*::test-tool verb:_test_tool_verb'\n"));
        ASSERT_NULL(strstr(script, "hidden"));
        ASSERT_NULL(strstr(script, "outdated"));
        ASSERT_NULL(strstr(script, "foreign"));

        run_script("zsh", script, /* syntax_only= */ true);
}

TEST(bash_arguments) {
        /* The generated function must parse the same argument forms as OptionParser. A temporary file
         * also checks @PATH completion for options and positional arguments, including split word breaks.
         * The generated function calls _comp_initialize and other helpers from bash-completion. The test
         * is skipped when the bash-completion library isn't installed. */
        if (access(BASH_COMPLETION_PATH, F_OK) < 0) {
                log_notice_errno(errno, "Failed to access %s, skipping: %m", BASH_COMPLETION_PATH);
                return;
        }

        _cleanup_free_ char *script = print_completion("bash");
        ASSERT_NOT_NULL(strextend(&script,
                "source " BASH_COMPLETION_PATH "\n"
                "set -eu\n"
                "compopt() { :; }\n"
                "check() {\n"
                "    local expected=$1 cur=$2\n"
                "    COMP_LINE=$3\n"
                "    COMP_POINT=${#COMP_LINE}\n"
                "    shift 3\n"
                "    COMP_WORDS=(\"$@\")\n"
                "    COMP_CWORD=$((${#COMP_WORDS[@]} - 1))\n"
                "    _test_tool_completion test-tool \"$cur\" '' || :\n"
                "    [[ ${COMPREPLY[*]} == \"$expected\" ]] || { declare -p COMP_WORDS COMPREPLY; exit 1; }\n"
                "}\n"
                "# Attached short arguments, option clusters, and long abbreviations must preserve verb selection.\n"
                "check red r 'test-tool -c r' test-tool -c r\n"
                "check -cred -cr 'test-tool -cr' test-tool -cr\n"
                "check -dred -dr 'test-tool -dr' test-tool -dr\n"
                "check paint p 'test-tool -hc red p' test-tool -hc red p\n"
                "check inspect ins 'test-tool --col red ins' test-tool --col red ins\n"
                "check red r 'test-tool --col=r' test-tool --col = r\n"
                "check inspect ins 'test-tool --secret dummy ins' test-tool --secret dummy ins\n"
                "check paint p 'test-tool --diff p' test-tool --diff p\n"
                "check '' --secret 'test-tool --secret' test-tool --secret\n"
                "# The file fixture must complete for options and verbs with each supported word-break layout.\n"
                "work=$(mktemp -d /var/tmp/test-shell-completion.XXXXXX)\n"
                "trap 'rm -rf \"$work\"' EXIT\n"
                "cd \"$work\"\n"
                "touch payload\n"
                "check payload pa 'test-tool inspect pa' test-tool inspect pa\n"
                "check @payload @pa 'test-tool --text @pa' test-tool --text @pa\n"
                "check @payload @pa 'test-tool read-at @pa' test-tool read-at @pa\n"
                "check key:@payload key:@pa 'test-tool read-key key:@pa' test-tool read-key key:@pa\n"
                "check @payload @pa 'test-tool read-key key:@pa' test-tool read-key key : @pa\n"
                "check '' '' 'test-tool read-at @payload ' test-tool read-at @payload ''\n"
                "check payload pa 'test-tool inspect -- pa' test-tool inspect -- pa\n"));
        run_script("bash", script, /* syntax_only= */ false);
}

TEST(command_selection) {
        /* Adjacent shared command markers must retain the first command's verbs. Its named namespace
         * and selected group must exclude unrelated options in both shells. */
        static const CommandDescription first = {
                .names = "first\0", .option_namespace = "selected", .option_groups = "Chosen\0",
                .flags = COMMAND_VERBS_SHARED,
        }, second = { .names = "second\0", .flags = COMMAND_VERBS_SHARED },
                other = { .names = "other\0" };
        static const Verb commands[] = {
                { .flags = VERB_COMMAND_MARKER, .data = (uintptr_t) &first },
                { .flags = VERB_COMMAND_MARKER, .data = (uintptr_t) &second },
                { .verb = "merge", .dispatch = noop_dispatcher, .help = "Merge", .max_args = 1 },
                { .flags = VERB_COMMAND_MARKER, .data = (uintptr_t) &other },
                { .verb = "foreign", .dispatch = noop_dispatcher, .help = "Foreign" },
        };
        static const Option grouped[] = {
                { .flags = OPTION_NAMESPACE_MARKER, .long_code = "unrelated" },
                { .long_code = "foreign", .help = "Foreign" },
                { .flags = OPTION_NAMESPACE_MARKER, .long_code = "selected" },
                { .flags = OPTION_GROUP_MARKER, .long_code = "Chosen" },
                { .long_code = "chosen", .help = "Chosen" },
                { .flags = OPTION_GROUP_MARKER, .long_code = "Excluded" },
                { .long_code = "excluded", .help = "Excluded" },
        };

        FOREACH_STRING(shell, "bash", "zsh") {
                _cleanup_free_ char *script = print_completion_full(shell, commands, ELEMENTSOF(commands),
                                                                  grouped, ELEMENTSOF(grouped));
                ASSERT_NOT_NULL(strstr(script, "merge"));
                ASSERT_NOT_NULL(strstr(script, "--chosen"));
                ASSERT_NULL(strstr(script, "foreign"));
                ASSERT_NULL(strstr(script, "--excluded"));
                run_script(shell, script, /* syntax_only= */ true);
        }
}

TEST(shared_options) {
        /* A command with no binary-local option table uses libshared's common namespace. Completion
         * must include the same help and version options as the help renderer. */
        static const CommandDescription common = { .names = "common-test\0", .option_namespace = "common" };
        static const Verb commands[] = { { .flags = VERB_COMMAND_MARKER, .data = (uintptr_t) &common } };

        FOREACH_STRING(shell, "bash", "zsh") {
                _cleanup_free_ char *script = print_completion_full(shell, commands, ELEMENTSOF(commands),
                                                                  /* test_options= */ NULL, /* n_options= */ 0);
                ASSERT_NOT_NULL(strstr(script, "--help"));
                ASSERT_NOT_NULL(strstr(script, "--version"));
                if (streq(shell, "bash"))
                        ASSERT_NULL(strstr(script, "options+=(--introspect-cli)"));
                else
                        ASSERT_NOT_NULL(strstr(script, "!(--introspect-cli)--introspect-cli[]"));
                run_script(shell, script, /* syntax_only= */ true);
        }
}

TEST(unsupported) {
        /* A shell outside the supported list must fail with EOPNOTSUPP for an otherwise valid table. */
        ASSERT_ERROR(_shell_completion_print(stdout,
                                             verbs, verbs + ELEMENTSOF(verbs) - 1,
                                             options, options + ELEMENTSOF(options) - 1,
                                             "test-tool", "fish"),
                     EOPNOTSUPP);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
