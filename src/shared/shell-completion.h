/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "options.h"
#include "verbs.h"

extern const char* const shell_completion_shells[];

/* Prints a bash or zsh completion script for 'program', generated from the options and verbs that --help
 * lists. The first command selects its option namespace, option groups, and shared verbs.
 * Returns -EOPNOTSUPP for other shells. */
int _shell_completion_print(
                FILE *f,
                const Verb verbs[],
                const Verb verbs_end[],
                const Option options[],
                const Option options_end[],
                const char *program,
                const char *shell);

/* The same as _shell_completion_print(), but prints to stdout and logs errors. If 'program' is NULL, the
 * invocation name is used. */
int _verb_shell_completion_print(
                const Verb verbs[],
                const Verb verbs_end[],
                const Option options[],
                const Option options_end[],
                const char *program,
                const char *shell);

static inline int verb_shell_completion(int argc, char **argv, uintptr_t data, void *userdata) {
        return _verb_shell_completion_print(
                        __start_SYSTEMD_VERBS, __stop_SYSTEMD_VERBS,
                        __start_SYSTEMD_OPTIONS, __stop_SYSTEMD_OPTIONS,
                        (const char*) data, argv[1]);
}

#define VERB_COMMON_COMPLETION(program)                                 \
        VERB_SCOPE_NS_FULL(static, verb_shell_completion, "completion", /* ns= */ NULL, "SHELL\0", 2, 2, 0, \
                           /* dat= */ (uintptr_t) (program), "Print the completion script for a shell", \
                           /* ft= */ NULL, .choices = shell_completion_shells)
