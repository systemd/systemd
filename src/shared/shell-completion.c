/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "escape.h"
#include "fileio.h"
#include "log.h"
#include "shell-completion.h"
#include "string-util.h"
#include "strv.h"

const char* const shell_completion_shells[] = {
        "bash",
        "zsh",
        NULL
};

static const char bash_helper[] =
#include "shell-completion-bash.inc"
        ;

static void print_choices(FILE *f, const char* const *choices) {
        /* The choices are written without quotes. bash and zsh split a choice that contains whitespace
         * into several words, and they expand a choice that contains a special character such as "*". */
        STRV_FOREACH(c, choices)
                assert(!strpbrk(*c, SHELL_NEED_QUOTES WHITESPACE));

        fputstrv(f, (char**) choices, " ", NULL);
}

static const char* const bash_kinds[_OPTION_COMPLETE_MAX] = {
        [OPTION_COMPLETE_DEFAULT]     = "default",
        [OPTION_COMPLETE_FILE]        = "file",
        [OPTION_COMPLETE_DIRECTORY]   = "directory",
        [OPTION_COMPLETE_AT_FILE]     = "at-file",
        [OPTION_COMPLETE_KEY_AT_FILE] = "key-at-file",
};

static const char* const zsh_actions[_OPTION_COMPLETE_MAX] = {
        [OPTION_COMPLETE_FILE]        = "_files",
        [OPTION_COMPLETE_DIRECTORY]   = "_files -/",
        [OPTION_COMPLETE_AT_FILE]     = "compset -P @ && _files",
        [OPTION_COMPLETE_KEY_AT_FILE] = "compset -P 1 '*:' && compset -P 1 '*@' && _files",
};

typedef struct Tables {
        const Verb **verbs;
        size_t n_verbs;
        const Option **options;
        size_t n_options;
} Tables;

static void tables_done(Tables *t) {
        assert(t);

        free(t->verbs);
        free(t->options);
}

static int tables_collect(
                Tables *t,
                const Verb verbs[],
                const Verb verbs_end[],
                const Option options[],
                const Option options_end[]) {

        assert(t);

        const CommandDescription *cmd;
        const Verb *cmdverb = _verbs_find_command(verbs, verbs_end, /* name= */ NULL, &cmd);
        if (!cmdverb)
                return log_debug_errno(SYNTHETIC_ERRNO(EUCLEAN), "No command description found.");

        for (const Verb *v = verbs_find_cmd_verbs(cmdverb, verbs_end); v < verbs_end; v++) {
                if (FLAGS_SET(v->flags, VERB_COMMAND_MARKER))
                        break;
                if (verb_is_metadata(v) || verb_is_hidden(v))
                        continue;

                if (!GREEDY_REALLOC_APPEND(t->verbs, t->n_verbs, &v, 1))
                        return -ENOMEM;
        }

        const Option *start, *end;
        if (!options_find_namespace(options, options_end, cmd->option_namespace, &start, &end))
                return log_debug_errno(SYNTHETIC_ERRNO(EUCLEAN), "Option namespace %s not found.",
                                       cmd->option_namespace ?: "(unnamed)");

        const char *group = NULL;
        for (const Option *o = start; o < end; o++) {
                if (FLAGS_SET(o->flags, OPTION_NAMESPACE_MARKER))
                        break;
                if (FLAGS_SET(o->flags, OPTION_GROUP_MARKER))
                        group = o->long_code;
                if (option_is_metadata(o) || !option_group_selected(cmd->option_groups, group))
                        continue;

                if (!GREEDY_REALLOC_APPEND(t->options, t->n_options, &o, 1))
                        return -ENOMEM;
        }

        return 0;
}

static const Option* find_long_option(const Tables *t, const char *name) {
        assert(t);
        assert(name);

        FOREACH_ARRAY(o, t->options, t->n_options)
                if ((*o)->help && streq_ptr((*o)->long_code, name))
                        return *o;

        return NULL;
}

static int option_names(const Option *o, char ***ret) {
        _cleanup_strv_free_ char **names = NULL;

        assert(o);
        assert(ret);

        if (o->long_code && strv_extend_joined(&names, "--", o->long_code) < 0)
                return -ENOMEM;

        if (o->short_code != 0 && strv_extendf(&names, "-%c", o->short_code) < 0)
                return -ENOMEM;

        *ret = TAKE_PTR(names);
        return 0;
}

static char* shell_function_name(const char *program, const char *suffix) {
        _cleanup_free_ char *name = strjoin("_", program, "_", suffix);
        if (!name)
                return NULL;

        /* bash in POSIX mode doesn't accept "-" in function names. */
        string_replace_char(name, '-', '_');
        return TAKE_PTR(name);
}

static int print_bash(FILE *f, const Tables *t, const char *program) {
        int r;

        assert(f);
        assert(t);
        assert(program);

        _cleanup_free_ char *function = shell_function_name(program, "completion");
        if (!function)
                return -ENOMEM;

        fputs(bash_helper, f);
        fprintf(f,
                "\n"
                "%s() {\n"
                "    local -a options=() verbs=()\n"
                "    local -A opts=() choices=() verb_choices=() verb_arguments=() verb_max=()\n"
                "\n",
                function);

        /* The value in opts is empty for an option without an argument. Otherwise it is the kind of
         * the argument, with a "?" in front if the argument is optional. */
        FOREACH_ARRAY(i, t->options, t->n_options) {
                const Option *o = *i;

                _cleanup_strv_free_ char **names = NULL;
                r = option_names(o, &names);
                if (r < 0)
                        return r;

                STRV_FOREACH(name, names) {
                        if (o->help)
                                fprintf(f, "    options+=(%s)\n", *name);

                        fprintf(f, "    opts[%s]='%s%s'\n",
                                *name,
                                o->metavar && option_arg_optional(o) ? "?" : "",
                                o->metavar ? bash_kinds[o->completion] : "");

                        if (o->choices) {
                                fprintf(f, "    choices[%s]='", *name);
                                print_choices(f, o->choices);
                                fputs("'\n", f);
                        }
                }
        }

        FOREACH_ARRAY(i, t->verbs, t->n_verbs) {
                const Verb *v = *i;

                fprintf(f, "    verbs+=(%s)\n", v->verb);

                if (v->choices) {
                        fprintf(f, "    verb_choices[%s]='", v->verb);
                        print_choices(f, v->choices);
                        fputs("'\n", f);
                }

                if (v->completion != OPTION_COMPLETE_DEFAULT)
                        fprintf(f, "    verb_arguments[%s]='%s'\n", v->verb, bash_kinds[v->completion]);

                /* max_args includes the verb itself. */
                if (v->max_args != VERB_ANY)
                        fprintf(f, "    verb_max[%s]=%u\n", v->verb, v->max_args);
        }

        fprintf(f,
                "\n"
                "    __systemd_complete \"$@\"\n"
                "}\n"
                "\n"
                "complete -F %s %s\n",
                function, program);

        return 0;
}

static int zsh_option_spec(const Option *o, const char *name, const char *exclusive, char **ret) {
        _cleanup_free_ char *action = NULL;

        assert(o);
        assert(name);
        assert(exclusive);
        assert(ret);

        /* zsh reads a "]" in the description as the end of the description. */
        _cleanup_free_ char *description = shell_escape(strempty(o->help), "[]");
        if (!description)
                return -ENOMEM;

        if (o->metavar && o->choices) {
                _cleanup_free_ char *joined = strv_join((char**) o->choices, " ");
                if (!joined)
                        return -ENOMEM;

                action = strjoin("(", joined, ")");
                if (!action)
                        return -ENOMEM;
        } else if (o->metavar && o->completion != OPTION_COMPLETE_DEFAULT) {
                /* _arguments splits the spec at every ":" that isn't escaped with a backslash. */
                _cleanup_free_ char *escaped = shell_escape(zsh_actions[o->completion], ":");
                if (!escaped)
                        return -ENOMEM;

                /* _arguments evaluates an action in braces as shell code. */
                action = strjoin("{", escaped, "}");
                if (!action)
                        return -ENOMEM;
        }

        /* "=" and "+" accept the argument in the same word or in the next one. An optional argument has to
         * be in the same word, which "=-" and "-" require. */
        bool optional = option_arg_optional(o);
        const char *separator = !o->metavar ? "" :
                                startswith(name, "--") ? (optional ? "=-" : "=") :
                                optional ? "-" : "+";

        char *spec = strjoin(o->help ? "" : "!",
                             exclusive,
                             name,
                             separator,
                             "[", description, "]",
                             !o->metavar ? "" : optional ? "::argument:" : ":argument:",
                             strempty(action));
        if (!spec)
                return -ENOMEM;

        *ret = spec;
        return 0;
}

static int zsh_option_exclusive(const Tables *t, const Option *o, char * const *names, char **ret) {
        int r;

        assert(t);
        assert(o);
        assert(ret);

        if (FLAGS_SET(o->flags, OPTION_REPEATABLE)) {
                char *s = strdup("*");
                if (!s)
                        return -ENOMEM;

                *ret = s;
                return 0;
        }

        _cleanup_strv_free_ char **exclusive = strv_copy(names);
        if (!exclusive)
                return -ENOMEM;

        /* --foo and --no-foo set the same setting. The spec lists both names as exclusive, so that zsh
         * doesn't offer one name after the other. */
        if (o->long_code) {
                _cleanup_free_ char *negative = NULL;
                const char *opposite_name = startswith(o->long_code, "no-");
                if (!opposite_name) {
                        opposite_name = negative = strjoin("no-", o->long_code);
                        if (!negative)
                                return -ENOMEM;
                }

                const Option *opposite = find_long_option(t, opposite_name);
                if (opposite) {
                        _cleanup_strv_free_ char **opposite_names = NULL;
                        r = option_names(opposite, &opposite_names);
                        if (r < 0)
                                return r;

                        r = strv_extend_strv(&exclusive, opposite_names, /* filter_duplicates= */ true);
                        if (r < 0)
                                return r;
                }
        }

        _cleanup_free_ char *joined = strv_join(exclusive, " ");
        if (!joined)
                return -ENOMEM;

        char *s = strjoin("(", joined, ")");
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}

static int print_zsh(FILE *f, const Tables *t, const char *program) {
        int r;

        assert(f);
        assert(t);
        assert(program);

        _cleanup_free_ char *function = shell_function_name(program, "verb");
        if (!function)
                return -ENOMEM;

        fprintf(f,
                "#compdef %s\n"
                "# SPDX-License-Identifier: LGPL-2.1-or-later\n"
                "\n"
                "%s() {\n"
                "    local -a verbs=(\n",
                program, function);

        FOREACH_ARRAY(i, t->verbs, t->n_verbs) {
                _cleanup_free_ char *description = strjoin((*i)->verb, ":", (*i)->help);
                if (!description)
                        return -ENOMEM;

                _cleanup_free_ char *quoted = shell_maybe_quote(description, SHELL_ESCAPE_POSIX);
                if (!quoted)
                        return -ENOMEM;

                fprintf(f, "        %s\n", quoted);
        }

        fprintf(f,
                "    )\n"
                "    if (( CURRENT == 1 )); then\n"
                "        _describe -t commands '%s verb' verbs\n"
                "        return\n"
                "    fi\n"
                "    case $words[1] in\n",
                program);

        FOREACH_ARRAY(i, t->verbs, t->n_verbs) {
                const Verb *v = *i;

                if (!v->choices && v->completion == OPTION_COMPLETE_DEFAULT)
                        continue;

                fprintf(f, "        (%s) ", v->verb);

                /* CURRENT counts the verb, so the arguments of the verb are completed as long as CURRENT
                 * doesn't exceed max_args. */
                if (v->max_args != VERB_ANY)
                        fprintf(f, "(( CURRENT <= %u )) && ", v->max_args);

                if (v->choices) {
                        fputs("{ compadd -- ", f);
                        print_choices(f, v->choices);
                        fputs("; } ;;\n", f);
                } else
                        fprintf(f, "{ %s; } ;;\n", zsh_actions[v->completion]);
        }

        fputs("    esac\n"
              "}\n"
              "\n"
              "_arguments -s -S \\\n",
              f);

        FOREACH_ARRAY(i, t->options, t->n_options) {
                const Option *o = *i;

                _cleanup_strv_free_ char **names = NULL;
                r = option_names(o, &names);
                if (r < 0)
                        return r;

                _cleanup_free_ char *exclusive = NULL;
                r = zsh_option_exclusive(t, o, names, &exclusive);
                if (r < 0)
                        return r;

                STRV_FOREACH(name, names) {
                        _cleanup_free_ char *spec = NULL;
                        r = zsh_option_spec(o, *name, exclusive, &spec);
                        if (r < 0)
                                return r;

                        _cleanup_free_ char *quoted = shell_maybe_quote(spec, SHELL_ESCAPE_POSIX);
                        if (!quoted)
                                return -ENOMEM;

                        fprintf(f, "    %s \\\n", quoted);
                }
        }

        fprintf(f, "    '*::%s verb:%s'\n", program, function);
        return 0;
}

int _shell_completion_print(
                FILE *f,
                const Verb verbs[],
                const Verb verbs_end[],
                const Option options[],
                const Option options_end[],
                const char *program,
                const char *shell) {

        _cleanup_(tables_done) Tables t = {};
        int r;

        assert(f);
        assert(program);
        assert(shell);

        r = tables_collect(&t, verbs, verbs_end, options, options_end);
        if (r < 0)
                return r;

        if (streq(shell, "bash"))
                r = print_bash(f, &t, program);
        else if (streq(shell, "zsh"))
                r = print_zsh(f, &t, program);
        else
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Unsupported shell '%s'.", shell);
        if (r < 0)
                return r;

        return fflush_and_check(f);
}

int _verb_shell_completion_print(
                const Verb verbs[],
                const Verb verbs_end[],
                const Option options[],
                const Option options_end[],
                const char *program,
                const char *shell) {

        int r;

        assert(shell);

        r = _shell_completion_print(stdout, verbs, verbs_end, options, options_end,
                                    program ?: program_invocation_short_name, shell);
        if (r == -EOPNOTSUPP) {
                _cleanup_free_ char *shells = strv_join((char**) shell_completion_shells, ", ");
                return log_error_errno(r, "Unsupported shell '%s', expected one of: %s", shell, strna(shells));
        }
        if (r < 0)
                return log_error_errno(r, "Failed to print the completion script: %m");

        return 0;
}
