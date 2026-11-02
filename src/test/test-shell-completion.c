/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "path-util.h"
#include "process-util.h"
#include "shell-completion.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

static int noop_dispatcher(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return 0;
}

static const char* const colors[] = {
        "red",
        "green",
        NULL
};

static const Verb verbs[] = {
        { .verb = "build", .min_args = VERB_ANY, .max_args = 1, .dispatch = noop_dispatcher, .help = "Build" },
        { .verb = "inspect", .min_args = 2, .max_args = VERB_ANY, .dispatch = noop_dispatcher, .help = "Inspect",
          .completion = OPTION_COMPLETE_FILE },
        { .verb = "paint", .min_args = 2, .max_args = 2, .dispatch = noop_dispatcher, .help = "Paint",
          .choices = colors },
        /* A verb without a help text is hidden. */
        { .verb = "hidden", .min_args = VERB_ANY, .max_args = VERB_ANY, .dispatch = noop_dispatcher },
        /* --help doesn't list deprecated verbs. */
        { .verb = "outdated", .min_args = VERB_ANY, .max_args = VERB_ANY, .dispatch = noop_dispatcher,
          .flags = VERB_DEPRECATED, .help = "Outdated" },
        /* The verbs of other commands of a multicall binary are not completed. */
        { .flags = VERB_COMMAND_MARKER },
        { .verb = "foreign", .min_args = VERB_ANY, .max_args = VERB_ANY, .dispatch = noop_dispatcher, .help = "Foreign" },
        {}
};

static const Option options[] = {
        { .id = 1, .short_code = 'h', .long_code = "help", .help = "Show this help" },
        { .id = 2, .long_code = "file", .metavar = "PATH", .help = "A [file]",
          .completion = OPTION_COMPLETE_FILE|OPTION_COMPLETE_REPEATABLE },
        { .id = 3, .long_code = "dir", .metavar = "DIR", .help = "A directory", .completion = OPTION_COMPLETE_DIRECTORY },
        { .id = 4, .long_code = "text", .metavar = "TEXT|@PATH", .help = "Text", .completion = OPTION_COMPLETE_AT_FILE },
        { .id = 5, .long_code = "section", .metavar = "NAME:TEXT|@PATH", .help = "Section",
          .completion = OPTION_COMPLETE_KEY_AT_FILE },
        { .id = 6, .long_code = "color", .metavar = "COLOR", .help = "Color with 'quotes'", .choices = colors },
        { .id = 7, .long_code = "sign", .help = "Sign" },
        { .id = 8, .long_code = "no-sign", .help = "Don't sign" },
        /* An option without a help text is hidden. */
        { .id = 9, .long_code = "secret" },
        { .id = 10, .short_code = 'd', .long_code = "diff", .metavar = "BOOL", .flags = OPTION_OPTIONAL_ARG,
          .help = "Diff" },
        /* The options of other namespaces are not completed. */
        { .id = 11, .flags = OPTION_NAMESPACE_MARKER, .long_code = "other" },
        { .id = 12, .long_code = "foreign", .help = "Foreign" },
        {}
};

static char* print_completion(const char *shell) {
        _cleanup_close_ int fd = ASSERT_OK_ERRNO(open_tmpfile_unlinkable(/* directory= */ NULL, O_RDWR));
        _cleanup_close_ int saved_stdout = ASSERT_OK_ERRNO(fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3));
        ASSERT_OK_ERRNO(fflush(stdout));
        ASSERT_OK_ERRNO(dup2(fd, STDOUT_FILENO));

        int r = _shell_completion_print(verbs, verbs + ELEMENTSOF(verbs) - 1, options, options + ELEMENTSOF(options) - 1,
                                        "test-tool", shell);

        ASSERT_OK_ERRNO(fflush(stdout));
        ASSERT_OK_ERRNO(dup2(saved_stdout, STDOUT_FILENO));
        ASSERT_OK(r);

        _cleanup_free_ char *script = NULL;
        ASSERT_OK(read_full_file_full(fd, /* filename= */ NULL, /* offset= */ 0, SIZE_MAX, /* flags= */ 0,
                                      /* bind_name= */ NULL, &script, /* ret_size= */ NULL));
        return TAKE_PTR(script);
}

static void check_syntax(const char *shell, const char *script) {
        _cleanup_free_ char *path = NULL;
        int r;

        if (find_executable(shell, &path) < 0) {
                log_notice("%s not found, not checking the syntax of the script.", shell);
                return;
        }

        _cleanup_(unlink_tempfilep) char file[] = "/tmp/test-shell-completion.XXXXXX";
        _cleanup_close_ int fd = ASSERT_OK(mkostemp_safe(file));
        ASSERT_OK(write_string_file(file, script, WRITE_STRING_FILE_AVOID_NEWLINE));

        r = ASSERT_OK(pidref_safe_fork("(sh-syntax)", FORK_WAIT|FORK_LOG|FORK_DEATHSIG_SIGKILL, /* ret= */ NULL));
        if (r == 0) {
                execl(path, shell, "-n", file, NULL);
                _exit(EXIT_FAILURE);
        }
}

TEST(bash) {
        _cleanup_free_ char *script = print_completion("bash");
        log_debug("%s", script);

        ASSERT_NOT_NULL(strstr(script, "_test_tool_completion() {"));
        ASSERT_NOT_NULL(strstr(script, "local -a options=(--help -h --file --dir --text --section --color --sign --no-sign --diff -d)"));
        ASSERT_NOT_NULL(strstr(script, "local -a verbs=(build inspect paint)"));
        ASSERT_NOT_NULL(strstr(script, "local -A choices=([--color]=$'red green')"));
        ASSERT_NOT_NULL(strstr(script, "local -A arguments=([--file]=file [--dir]=directory [--text]=at-file "
                                       "[--section]=key-at-file [--color]=default [--diff]=default [-d]=default)"));
        ASSERT_NOT_NULL(strstr(script, "local -A optional=([--diff]=1 [-d]=1)"));
        ASSERT_NOT_NULL(strstr(script, "local -A verb_choices=([paint]=$'red green')"));
        ASSERT_NOT_NULL(strstr(script, "local -A verb_arguments=([inspect]=file)"));
        ASSERT_NOT_NULL(strstr(script, "local -A verb_max=([build]=1 [paint]=2)"));
        ASSERT_NOT_NULL(strstr(script, "complete -F _test_tool_completion test-tool\n"));
        ASSERT_NULL(strstr(script, "secret"));
        ASSERT_NULL(strstr(script, "hidden"));
        ASSERT_NULL(strstr(script, "outdated"));
        ASSERT_NULL(strstr(script, "foreign"));

        check_syntax("bash", script);
}

TEST(zsh) {
        _cleanup_free_ char *script = print_completion("zsh");
        log_debug("%s", script);

        ASSERT_TRUE(startswith(script, "#compdef test-tool\n"));
        ASSERT_NOT_NULL(strstr(script, "local -a verbs=(build:Build inspect:Inspect paint:Paint)"));
        ASSERT_NOT_NULL(strstr(script, "(inspect) _files ;;"));
        ASSERT_NOT_NULL(strstr(script, "(paint) (( CURRENT <= 2 )) && { local -a choices=($'red green'); compadd -- ${=choices}; } ;;"));
        ASSERT_NOT_NULL(strstr(script, "$'*--file=[A \\\\[file\\\\]]:argument:_files'"));
        ASSERT_NOT_NULL(strstr(script, "$'(--dir)--dir=[A directory]:argument:_files -/'"));
        ASSERT_NOT_NULL(strstr(script, "$'(--text)--text=[Text]:argument:_test_tool_at_file'"));
        ASSERT_NOT_NULL(strstr(script, "$'(--section)--section=[Section]:argument:_test_tool_key_at_file'"));
        ASSERT_NOT_NULL(strstr(script, "$'(--color)--color=[Color with \\'quotes\\']:argument:(red green)'"));
        ASSERT_NOT_NULL(strstr(script, "$'(--sign --no-sign)--sign[Sign]'"));
        ASSERT_NOT_NULL(strstr(script, "$'(--diff -d)--diff=-[Diff]::argument:'"));
        ASSERT_NOT_NULL(strstr(script, "$'(--diff -d)-d-[Diff]::argument:'"));
        ASSERT_NOT_NULL(strstr(script, "'*::test-tool verb:_test_tool_verb'\n"));
        ASSERT_NULL(strstr(script, "secret"));
        ASSERT_NULL(strstr(script, "hidden"));
        ASSERT_NULL(strstr(script, "outdated"));
        ASSERT_NULL(strstr(script, "foreign"));

        check_syntax("zsh", script);
}

TEST(unsupported) {
        ASSERT_ERROR(_shell_completion_print(verbs, verbs + ELEMENTSOF(verbs) - 1, options, options + ELEMENTSOF(options) - 1,
                                             "test-tool", "fish"),
                     EOPNOTSUPP);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
