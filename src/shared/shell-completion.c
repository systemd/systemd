/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "escape.h"
#include "log.h"
#include "shell-completion.h"
#include "string-util.h"
#include "strv.h"

const char* const shell_completion_shells[] = {
        "bash",
        "zsh",
        NULL
};

typedef struct Tables {
        const Verb *verbs;
        const Verb *verbs_end;
        const Option *options;
        const Option *options_end;
} Tables;

static bool option_is_completed(const Option *o) {
        assert(o);

        /* Options without a help text, like --introspect-cli, are hidden in --help too. */
        return !option_is_metadata(o) && o->help;
}

static bool verb_is_completed(const Verb *v) {
        assert(v);

        return v->verb && v->dispatch && !verb_is_hidden(v);
}

static const Option* find_long_option(const Tables *t, const char *name) {
        assert(t);

        for (const Option *o = t->options; o && o < t->options_end; o++)
                if (option_is_completed(o) && streq_ptr(o->long_code, name))
                        return o;

        return NULL;
}

static const char* completion_kind(OptionCompletion c) {
        if (FLAGS_SET(c, OPTION_COMPLETE_FILE))
                return "file";
        if (FLAGS_SET(c, OPTION_COMPLETE_DIRECTORY))
                return "directory";
        if (FLAGS_SET(c, OPTION_COMPLETE_AT_FILE))
                return "at-file";
        if (FLAGS_SET(c, OPTION_COMPLETE_KEY_AT_FILE))
                return "key-at-file";

        return "default";
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

static char* quote_words(const char* const *words) {
        _cleanup_free_ char *joined = strv_join((char**) words, " ");
        if (!joined)
                return NULL;

        return shell_maybe_quote(joined, SHELL_ESCAPE_POSIX);
}

static char* shell_function_name(const char *program, const char *suffix) {
        _cleanup_free_ char *name = strjoin("_", program, "_", suffix);
        if (!name)
                return NULL;

        /* bash in POSIX mode doesn't accept "-" in function names. */
        string_replace_char(name, '-', '_');
        return TAKE_PTR(name);
}

static int print_bash(const Tables *t, const char *program) {
        _cleanup_free_ char *options = NULL, *choices = NULL, *arguments = NULL, *optional = NULL,
                *verbs = NULL, *verb_arguments = NULL, *verb_choices = NULL, *verb_max = NULL;
        int r;

        assert(t);
        assert(program);

        for (const Option *o = t->options; o && o < t->options_end; o++) {
                if (!option_is_completed(o))
                        continue;

                _cleanup_strv_free_ char **names = NULL;
                r = option_names(o, &names);
                if (r < 0)
                        return r;

                _cleanup_free_ char *c = NULL;
                if (o->choices) {
                        c = quote_words(o->choices);
                        if (!c)
                                return -ENOMEM;
                }

                STRV_FOREACH(name, names) {
                        if (!strextend_with_separator(&options, " ", *name))
                                return -ENOMEM;

                        if (c && strextendf_with_separator(&choices, " ", "[%s]=%s", *name, c) < 0)
                                return -ENOMEM;

                        if (o->metavar &&
                            strextendf_with_separator(&arguments, " ", "[%s]=%s", *name, completion_kind(o->completion)) < 0)
                                return -ENOMEM;

                        if (option_arg_optional(o) &&
                            strextendf_with_separator(&optional, " ", "[%s]=1", *name) < 0)
                                return -ENOMEM;
                }
        }

        for (const Verb *v = t->verbs; v && v < t->verbs_end; v++) {
                if (!verb_is_completed(v))
                        continue;

                if (!strextend_with_separator(&verbs, " ", v->verb))
                        return -ENOMEM;

                if (v->choices) {
                        _cleanup_free_ char *c = quote_words(v->choices);
                        if (!c)
                                return -ENOMEM;

                        if (strextendf_with_separator(&verb_choices, " ", "[%s]=%s", v->verb, c) < 0)
                                return -ENOMEM;
                }

                if (v->completion != 0 &&
                    strextendf_with_separator(&verb_arguments, " ", "[%s]=%s", v->verb, completion_kind(v->completion)) < 0)
                        return -ENOMEM;

                /* max_args includes the verb itself. */
                if (v->max_args != VERB_ANY &&
                    strextendf_with_separator(&verb_max, " ", "[%s]=%u", v->verb, v->max_args) < 0)
                        return -ENOMEM;
        }

        _cleanup_free_ char *function = shell_function_name(program, "completion");
        if (!function)
                return -ENOMEM;

        printf("# SPDX-License-Identifier: LGPL-2.1-or-later\n"
               "# shellcheck shell=bash\n"
               "\n"
               "%s() {\n"
               "    local cur=\"$2\" word option=\"\" verb=\"\" prefix=\"\"\n"
               "    local line=\"$COMP_LINE\" previous=\"\" wordbreak_prefix kind=\"\"\n"
               "    local -i i position=0 cword=-1 continue_options=1\n"
               "    local -a words=()\n"
               "    local -a options=(%s)\n"
               "    local -a verbs=(%s)\n"
               "    local -A choices=(%s)\n"
               "    local -A arguments=(%s)\n"
               "    local -A optional=(%s)\n"
               "    local -A verb_choices=(%s)\n"
               "    local -A verb_arguments=(%s)\n"
               "    local -A verb_max=(%s)\n",
               function,
               strempty(options),
               strempty(verbs),
               strempty(choices),
               strempty(arguments),
               strempty(optional),
               strempty(verb_choices),
               strempty(verb_arguments),
               strempty(verb_max));

        fputs(
        "\n"
        "    COMPREPLY=()\n"
        "\n"
        "    # Rejoin separators split out by Bash, including the colon in KEY:@PATH.\n"
        "    for ((i = 0; i <= COMP_CWORD; i++)); do\n"
        "        word=${COMP_WORDS[i]}\n"
        "        if ((i > 1)) && [[ $line != [[:blank:]]* ]] &&\n"
        "            [[ $word =~ ^[=@:]+$ || $previous =~ ^[=@:]+$ ]]\n"
        "        then\n"
        "            words[cword]+=$word\n"
        "        else\n"
        "            cword=$((cword + 1))\n"
        "            words[cword]=$word\n"
        "        fi\n"
        "        line=${line#*\"$word\"}\n"
        "        previous=$word\n"
        "    done\n"
        "\n"
        "    wordbreak_prefix=${words[cword]%\"$cur\"}\n"
        "    cur=${words[cword]}\n"
        "\n"
        "    for ((i = 1; i < cword; i++)); do\n"
        "        word=${words[i]}\n"
        "        if [[ -n $option ]]; then\n"
        "            option=\"\"\n"
        "        elif ((continue_options)) && [[ $word == -- ]]; then\n"
        "            continue_options=0\n"
        "        elif ((continue_options)) && [[ $word == -* ]]; then\n"
        "            # An optional argument has to follow the option in the same word.\n"
        "            if [[ $word != *=* && -n ${arguments[$word]-} && -z ${optional[$word]-} ]]; then\n"
        "                option=$word\n"
        "            fi\n"
        "        else\n"
        "            [[ -n $verb ]] || verb=$word\n"
        "            position=$((position + 1))\n"
        "        fi\n"
        "    done\n"
        "\n"
        "    if ((continue_options)) && [[ -z $option && $cur == --*=* ]]; then\n"
        "        option=${cur%%=*}\n"
        "        prefix=${option}=\n"
        "        cur=${cur#*=}\n"
        "    elif ((continue_options)) && [[ -z $option && $cur == -* ]]; then\n"
        "        readarray -t COMPREPLY < <(compgen -W \"${options[*]}\" -- \"$cur\")\n"
        "        return\n"
        "    fi\n"
        "\n"
        "    if [[ -n $option ]]; then\n"
        "        kind=${arguments[$option]-}\n"
        "        if [[ $kind == at-file || $kind == key-at-file ]]; then\n"
        "            # Undo Readline's quoting of @ when continuing a previously completed path.\n"
        "            cur=${cur/\\\\@/@}\n"
        "        fi\n"
        "        if [[ $kind == key-at-file ]]; then\n"
        "            [[ $cur == *:* ]] || return\n"
        "            prefix+=${cur%%:*}:\n"
        "            cur=${cur#*:}\n"
        "            [[ $cur == *@* ]] || return\n"
        "            prefix+=${cur%%@*}\n"
        "            cur=@${cur#*@}\n"
        "            kind=at-file\n"
        "        fi\n"
        "        if [[ $kind == at-file ]]; then\n"
        "            [[ $cur == @* ]] || return\n"
        "            prefix+=@\n"
        "            cur=${cur#@}\n"
        "            kind='file'\n"
        "        fi\n"
        "\n"
        "        if [[ -n ${choices[$option]-} ]]; then\n"
        "            readarray -t COMPREPLY < <(compgen -W \"${choices[$option]}\" -- \"$cur\")\n"
        "            kind=\"\"\n"
        "        fi\n"
        "    elif [[ -z $verb ]]; then\n"
        "        readarray -t COMPREPLY < <(compgen -W \"${verbs[*]}\" -- \"$cur\")\n"
        "    elif [[ -z ${verb_max[$verb]-} ]] || ((position < verb_max[$verb])); then\n"
        "        if [[ -n ${verb_choices[$verb]-} ]]; then\n"
        "            readarray -t COMPREPLY < <(compgen -W \"${verb_choices[$verb]}\" -- \"$cur\")\n"
        "        else\n"
        "            kind=${verb_arguments[$verb]-}\n"
        "        fi\n"
        "    fi\n"
        "\n"
        "    if [[ $kind == file || $kind == directory ]]; then\n"
        "        compopt -o filenames\n"
        "        readarray -t COMPREPLY < <(compgen -A \"$kind\" -- \"$cur\")\n"
        "        if [[ -n ${COMPREPLY[0]-} && -z ${COMPREPLY[1]-} && -d ${COMPREPLY[0]} ]]; then\n"
        "            compopt -o nospace\n"
        "        fi\n"
        "    fi\n"
        "\n"
        "    for i in \"${!COMPREPLY[@]}\"; do\n"
        "        word=\"${COMPREPLY[i]}\"\n"
        "        if [[ ( $kind == file || $kind == directory ) && -d $word ]]; then\n"
        "            word+=/\n"
        "        fi\n"
        "        word=\"${prefix}${word}\"\n"
        "        COMPREPLY[i]=${word#\"$wordbreak_prefix\"}\n"
        "    done\n"
        "}\n"
        "\n",
              stdout);

        printf("complete -F %s %s\n", function, program);
        return 0;
}

static const char* zsh_action(const char *program, OptionCompletion c, char **buf) {
        assert(program);
        assert(buf);

        if (FLAGS_SET(c, OPTION_COMPLETE_FILE))
                return "_files";
        if (FLAGS_SET(c, OPTION_COMPLETE_DIRECTORY))
                return "_files -/";
        if (FLAGS_SET(c, OPTION_COMPLETE_AT_FILE))
                return *buf = shell_function_name(program, "at_file");
        if (FLAGS_SET(c, OPTION_COMPLETE_KEY_AT_FILE))
                return *buf = shell_function_name(program, "key_at_file");

        return "";
}

static int zsh_option_spec(const char *program, const Option *o, const char *name, char * const *names, char **ret) {
        _cleanup_free_ char *spec = NULL;

        assert(program);
        assert(o);
        assert(name);
        assert(ret);

        if (FLAGS_SET(o->completion, OPTION_COMPLETE_REPEATABLE))
                spec = strdup("*");
        else {
                _cleanup_free_ char *exclusive = strv_join((char**) names, " ");
                if (!exclusive)
                        return -ENOMEM;

                spec = strjoin("(", exclusive, ")");
        }
        if (!spec)
                return -ENOMEM;

        /* zsh reads a "]" in the description as the end of the description. */
        _cleanup_free_ char *description = shell_escape(o->help, "[]");
        if (!description)
                return -ENOMEM;

        /* "=" and "+" accept the argument in the same word or in the next one. An optional argument has to
         * be in the same word, which "=-" and "-" require. */
        bool optional = option_arg_optional(o);
        const char *separator = !o->metavar ? "" :
                                startswith(name, "--") ? (optional ? "=-" : "=") :
                                optional ? "-" : "+";

        if (!strextend(&spec, name, separator, "[", description, "]"))
                return -ENOMEM;

        if (o->metavar) {
                _cleanup_free_ char *c = NULL, *buf = NULL;

                if (o->choices) {
                        _cleanup_free_ char *joined = strv_join((char**) o->choices, " ");
                        if (!joined)
                                return -ENOMEM;

                        c = strjoin("(", joined, ")");
                        if (!c)
                                return -ENOMEM;
                }

                const char *action = c ?: zsh_action(program, o->completion, &buf);
                if (!action)
                        return -ENOMEM;

                if (!strextend(&spec, optional ? "::argument:" : ":argument:", action))
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(spec);
        return 0;
}

static int print_zsh(const Tables *t, const char *program) {
        _cleanup_free_ char *verbs = NULL, *cases = NULL;
        int r;

        assert(t);
        assert(program);

        for (const Verb *v = t->verbs; v && v < t->verbs_end; v++) {
                if (!verb_is_completed(v))
                        continue;

                _cleanup_free_ char *description = strjoin(v->verb, ":", v->help);
                if (!description)
                        return -ENOMEM;

                _cleanup_free_ char *quoted = shell_maybe_quote(description, SHELL_ESCAPE_POSIX);
                if (!quoted)
                        return -ENOMEM;

                if (!strextend_with_separator(&verbs, " ", quoted))
                        return -ENOMEM;

                _cleanup_free_ char *action = NULL, *buf = NULL;
                if (v->choices) {
                        _cleanup_free_ char *c = quote_words(v->choices);
                        if (!c)
                                return -ENOMEM;

                        /* ${=choices} splits the list into words. */
                        action = strjoin("local -a choices=(", c, "); compadd -- ${=choices}");
                } else if (v->completion != 0) {
                        const char *a = zsh_action(program, v->completion, &buf);
                        action = a ? strdup(a) : NULL;
                } else
                        continue;
                if (!action)
                        return -ENOMEM;

                /* CURRENT counts the verb, so the arguments of the verb are completed as long as CURRENT
                 * doesn't exceed max_args. */
                if (v->max_args != VERB_ANY)
                        r = strextendf(&cases, "        (%s) (( CURRENT <= %u )) && { %s; } ;;\n", v->verb, v->max_args, action);
                else
                        r = strextendf(&cases, "        (%s) %s ;;\n", v->verb, action);
                if (r < 0)
                        return -ENOMEM;
        }

        _cleanup_free_ char *at_file = shell_function_name(program, "at_file"),
                *key_at_file = shell_function_name(program, "key_at_file"),
                *verb = shell_function_name(program, "verb");
        if (!at_file || !key_at_file || !verb)
                return -ENOMEM;

        printf("#compdef %s\n"
               "# SPDX-License-Identifier: LGPL-2.1-or-later\n"
               "\n"
               "%s() {\n"
               "    compset -P '@' && _files\n"
               "}\n"
               "\n"
               "%s() {\n"
               "    compset -P 1 '*:' || return\n"
               "    compset -P 1 '*@' && _files\n"
               "}\n"
               "\n"
               "%s() {\n"
               "    local -a verbs=(%s)\n"
               "    if (( CURRENT == 1 )); then\n"
               "        _describe -t commands '%s verb' verbs\n"
               "        return\n"
               "    fi\n"
               "    case $words[1] in\n"
               "%s"
               "    esac\n"
               "}\n"
               "\n"
               "_arguments -s -S \\\n",
               program,
               at_file,
               key_at_file,
               verb,
               strempty(verbs),
               program,
               strempty(cases));

        for (const Option *o = t->options; o && o < t->options_end; o++) {
                if (!option_is_completed(o))
                        continue;

                _cleanup_strv_free_ char **names = NULL;
                r = option_names(o, &names);
                if (r < 0)
                        return r;

                /* --foo and --no-foo set the same setting. The spec lists both names as exclusive, so that
                 * zsh doesn't offer one name after the other. */
                _cleanup_strv_free_ char **exclusive = strv_copy(names);
                if (!exclusive)
                        return -ENOMEM;

                const char *positive = o->long_code ? startswith(o->long_code, "no-") : NULL;
                if (positive && find_long_option(t, positive)) {
                        if (strv_extend_joined(&exclusive, "--", positive) < 0)
                                return -ENOMEM;
                } else if (o->long_code) {
                        _cleanup_free_ char *negative = strjoin("no-", o->long_code);
                        if (!negative)
                                return -ENOMEM;

                        if (find_long_option(t, negative) && strv_extend_joined(&exclusive, "--", negative) < 0)
                                return -ENOMEM;
                }

                STRV_FOREACH(name, names) {
                        _cleanup_free_ char *spec = NULL;

                        r = zsh_option_spec(program, o, *name, exclusive, &spec);
                        if (r < 0)
                                return r;

                        _cleanup_free_ char *quoted = shell_maybe_quote(spec, SHELL_ESCAPE_POSIX);
                        if (!quoted)
                                return -ENOMEM;

                        printf("    %s \\\n", quoted);
                }
        }

        printf("    '*::%s verb:%s'\n", program, verb);
        return 0;
}

int _shell_completion_print(
                const Verb verbs[],
                const Verb verbs_end[],
                const Option options[],
                const Option options_end[],
                const char *program,
                const char *shell) {

        Tables t = {
                .verbs = verbs,
                .verbs_end = verbs_end,
                .options = options,
                .options_end = options_end,
        };

        assert(program);
        assert(shell);

        /* The other option namespaces contain the options of single verbs or of the other commands of a
         * multicall binary. We only complete the options of the first namespace, and the verbs of the
         * first command. */
        if (t.options && t.options < t.options_end && FLAGS_SET(t.options->flags, OPTION_NAMESPACE_MARKER))
                t.options++;
        for (const Option *o = t.options; o && o < t.options_end; o++)
                if (FLAGS_SET(o->flags, OPTION_NAMESPACE_MARKER)) {
                        t.options_end = o;
                        break;
                }

        if (t.verbs && t.verbs < t.verbs_end && FLAGS_SET(t.verbs->flags, VERB_COMMAND_MARKER))
                t.verbs++;
        for (const Verb *v = t.verbs; v && v < t.verbs_end; v++)
                if (FLAGS_SET(v->flags, VERB_COMMAND_MARKER)) {
                        t.verbs_end = v;
                        break;
                }

        if (streq(shell, "bash"))
                return print_bash(&t, program);
        if (streq(shell, "zsh"))
                return print_zsh(&t, program);

        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Unsupported shell '%s'.", shell);
}
