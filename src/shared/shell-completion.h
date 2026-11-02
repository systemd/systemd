/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "log.h"
#include "options.h"
#include "verbs.h"

extern const char* const shell_completion_shells[];

/* Prints a bash or zsh completion script for 'program', generated from the options and verbs that --help
 * lists. Only the options of the first option namespace and the verbs of the first command are completed.
 * Returns -EOPNOTSUPP for other shells. */
int _shell_completion_print(
                const Verb verbs[],
                const Verb verbs_end[],
                const Option options[],
                const Option options_end[],
                const char *program,
                const char *shell);
#define shell_completion_print(program, shell)                          \
        _shell_completion_print(                                        \
                __start_SYSTEMD_VERBS, __stop_SYSTEMD_VERBS,            \
                __start_SYSTEMD_OPTIONS, __stop_SYSTEMD_OPTIONS,        \
                program, shell)

static inline int verb_shell_completion(int argc, char **argv, uintptr_t data, void *userdata) {
        const char *program = (const char*) data ?: program_invocation_short_name;
        int r;

        r = shell_completion_print(program, argv[1]);
        if (r == -EOPNOTSUPP)
                return log_error_errno(r, "Unsupported shell '%s': choose from bash, zsh", argv[1]);
        if (r < 0)
                return log_error_errno(r, "Failed to print the completion script: %m");

        return 0;
}

#define VERB_COMMON_COMPLETION(program)                                 \
        VERB_SCOPE_NS_FULL(static, verb_shell_completion, "completion", /* ns= */ NULL, "SHELL\0", 2, 2, 0, \
                           /* dat= */ (uintptr_t) (program), "Print the completion script for a shell", \
                           /* ft= */ NULL, .choices = shell_completion_shells)
