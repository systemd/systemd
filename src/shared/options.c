/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-table.h"
#include "log.h"
#include "options.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"

static bool option_takes_arg(const Option *opt) {
        return ASSERT_PTR(opt)->metavar;
}

static bool option_arg_optional(const Option *opt) {
        return option_takes_arg(opt) && FLAGS_SET(opt->flags, OPTION_OPTIONAL_ARG);
}

static bool option_arg_required(const Option *opt) {
        return option_takes_arg(opt) && !FLAGS_SET(opt->flags, OPTION_OPTIONAL_ARG);
}

static bool option_is_metadata(const Option *opt) {
        /* A metadata entry that is not a real option, like the group marker */
        return  FLAGS_SET(ASSERT_PTR(opt)->flags, OPTION_GROUP_MARKER) ||
                FLAGS_SET(ASSERT_PTR(opt)->flags, OPTION_HELP_ENTRY);
}

static void shift_arg(char* argv[], int target, int source) {
        assert(argv);
        assert(target <= source);

        /* Move argv[source] before argv[target], shifting arguments inbetween */
        char *saved = argv[source];
        memmove(argv + target + 1, argv + target, (source - target) * sizeof(char*));
        argv[target] = saved;
}

static int partial_match_error(
                const Option options[],
                const Option options_end[],
                const char *optname,
                unsigned n_partial_matches) {
        int r;

        assert(startswith(ASSERT_PTR(optname), "--"));
        assert(n_partial_matches >= 2);

        /* Find options that match the prefix */
        _cleanup_strv_free_ char **s = NULL;
        for (const Option* option = options; option < options_end; option++)
                if (!option_is_metadata(option) &&
                    option->long_code &&
                    startswith(option->long_code, optname + 2)) {

                        r = strv_extendf(&s, "--%s", option->long_code);
                        if (r < 0)
                                return log_error_errno(r, "Failed to format message: %m");
                }

        assert(strv_length(s) == n_partial_matches);

        _cleanup_free_ char *p = strv_join_full(s, ", ", /* prefix= */ NULL, /* escape_separator= */ false);
        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                               "%s: option '%s' is ambiguous; possibilities: %s",
                               program_invocation_short_name, optname, strnull(p));
}

int option_parse(
                const Option options[],
                const Option options_end[],
                OptionParser *state,
                const Option **ret_option,
                const char **ret_arg) {

        /* Check and initialize */
        if (state->optind == 0) {
                if (state->argc < 1 || strv_isempty(state->argv))
                        return log_error_errno(SYNTHETIC_ERRNO(EUCLEAN), "argv cannot be empty");

                state->optind = state->positional_offset = 1;
        }

        /* Look for the next option */

        const Option *option = NULL;  /* initialization to appease gcc 13 */
        const char *optname = NULL, *optval = NULL;
        _cleanup_free_ char *_optname = NULL;  /* allocated option name */
        bool separate_optval = false;

        if (state->short_option_offset == 0) {
                /* Skip over non-option parameters */
                for (;;) {
                        if (state->optind == state->argc)
                                return 0;

                        if (streq(state->argv[state->optind], "--")) {
                                /* No more options. Move "--" before positional args so that
                                 * the list of positional args is clean. */
                                shift_arg(state->argv, state->positional_offset++, state->optind++);
                                state->parsing_stopped = true;
                        }

                        if (state->parsing_stopped)
                                return 0;

                        if (state->argv[state->optind][0] == '-' &&
                            state->argv[state->optind][1] != '\0')
                                /* Looks like we found an option parameter */
                                break;

                        state->optind++;
                }

                /* Find matching option entry.
                 * First, figure out if we have a long option or a short option. */
                assert(state->argv[state->optind][0] == '-');

                if (state->argv[state->optind][1] == '-') {
                        /* We have a long option. */
                        char *eq = strchr(state->argv[state->optind], '=');
                        if (eq) {
                                optname = _optname = strndup(state->argv[state->optind], eq - state->argv[state->optind]);
                                if (!_optname)
                                        return log_oom();

                                /* joined argument */
                                optval = eq + 1;
                        } else
                                /* argument (if any) is separate */
                                optname = state->argv[state->optind];

                        const Option *last_partial = NULL;
                        unsigned n_partial_matches = 0;  /* The commandline option matches a defined prefix. */

                        for (option = options;; option++) {
                                if (option >= options_end) {
                                        if (n_partial_matches == 0)
                                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                                       "%s: unrecognized option '%s'",
                                                                       program_invocation_short_name, optname);
                                        if (n_partial_matches > 1)
                                                return partial_match_error(options, options_end, optname, n_partial_matches);

                                        /* just one partial — good */
                                        option = last_partial;
                                        break;
                                }

                                if (option_is_metadata(option) || !option->long_code)
                                        continue;

                                /* Check if the parameter forms a prefix of the option name */
                                const char *rest = startswith(option->long_code, optname + 2);
                                if (!rest)
                                        continue;
                                if (isempty(rest))
                                        /* exact match */
                                        break;
                                /* partial match */
                                last_partial = option;
                                n_partial_matches++;
                        }
                } else
                        /* We have a short option */
                        state->short_option_offset = 1;
        }

        if (state->short_option_offset > 0) {
                char optchar = state->argv[state->optind][state->short_option_offset];

                if (asprintf(&_optname, "-%c", optchar) < 0)
                        return log_oom();
                optname = _optname;

                for (option = options;; option++) {
                        if (option >= options_end)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "%s: unrecognized option '%s'",
                                                       program_invocation_short_name, optname);

                        if (option_is_metadata(option) || optchar != option->short_code)
                                continue;

                        const char *rest = state->argv[state->optind] + state->short_option_offset + 1;

                        if (option_takes_arg(option) && !isempty(rest)) {
                                /* The rest of this parameter is the value. */
                                optval = rest;
                                state->short_option_offset = 0;
                        } else if (isempty(rest))
                                state->short_option_offset = 0;
                        else
                                state->short_option_offset++;

                        break;
                }
        }

        assert(option);

        if (optval && !option_takes_arg(option))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s: option '%s' doesn't allow an argument",
                                       program_invocation_short_name, optname);
        if (!optval && option_arg_required(option)) {
                if (!state->argv[state->optind + 1])
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "%s: option '%s' requires an argument",
                                               program_invocation_short_name, optname);
                optval = state->argv[state->optind + 1];
                separate_optval = true;
        }

        if (state->short_option_offset == 0) {
                /* We're done with this option. Adjust the array and position. */
                shift_arg(state->argv, state->positional_offset++, state->optind++);
                if (separate_optval)
                        shift_arg(state->argv, state->positional_offset++, state->optind++);
        }

        if (FLAGS_SET(option->flags, OPTION_STOPS_PARSING))
                state->parsing_stopped = true;

        if (ret_option)
                /* Return the matched Option structure to allow the caller to "know" what was matched */
                *ret_option = option;

        if (ret_arg)
                *ret_arg = optval;
        else
                /* It's fine to omit ret_arg, but only if no options return a value. */
                assert(!optval);

        return option->id;
}

char** option_parser_get_args(const OptionParser *state) {
        /* Returns positional args as a strv.
         * If "--" was found, it has been moved before state->positional_offset.
         * The array is only valid, i.e. clean without any options, after parsing
         * has naturally finished. The array that is returned is a slice of the
         * original argv array, so it must not be freed or modified. */

        assert(state->optind > 0);
        assert(state->optind == state->argc || state->parsing_stopped);
        assert(state->positional_offset <= state->argc);

        return state->argv + state->positional_offset;
}

size_t option_parser_get_n_args(const OptionParser *state) {
        assert(state->optind > 0);
        assert(state->optind == state->argc || state->parsing_stopped);
        assert(state->positional_offset <= state->argc);

        return state->argc - state->positional_offset;
}

int _option_parser_get_help_table(
                const Option options[],
                const Option options_end[],
                const char *group,
                Table **ret) {
        int r;

        assert(ret);

        _cleanup_(table_unrefp) Table *table = table_new("names", "help");
        if (!table)
                return log_oom();

        bool in_group = group == NULL;  /* Are we currently in the section on the array that forms
                                         * group <group>? The first part is the default group, so
                                         * if the group was not specified, we are in. */

        for (const Option *opt = options; opt < options_end; opt++) {
                bool group_marker = FLAGS_SET(opt->flags, OPTION_GROUP_MARKER);
                if (!in_group) {
                        in_group = group_marker && streq(group, opt->long_code);
                        continue;
                }
                if (group_marker)
                        break;  /* End of group */

                if (!opt->help)
                        /* No help string — we do not show the option */
                        continue;

                char sc[3] = "  ";
                if (opt->short_code != 0)
                        xsprintf(sc, "-%c", opt->short_code);

                /* We indent the option string by two spaces. We could set the minimum cell width and
                 * right-align for a similar result, but that'd be more work. This is only used for
                 * display.
                 *
                 * "=" is shown only when a long option is defined: -l --long=ARG, --long=ARG, -s ARG.
                 */
                bool need_eq = option_takes_arg(opt) && opt->long_code;
                _cleanup_free_ char *s = strjoin(
                                "  ",
                                sc,
                                " ",
                                opt->long_code ? "--" : "",
                                strempty(opt->long_code),
                                option_arg_optional(opt) ? "[" : "",
                                need_eq ? "=" : "",
                                strempty(opt->metavar),
                                option_arg_optional(opt) ? "]" : "");
                if (!s)
                        return log_oom();

                r = table_add_many(table, TABLE_STRING, s);
                if (r < 0)
                        return table_log_add_error(r);

                _cleanup_strv_free_ char **t = strv_split(opt->help, /* separators= */ NULL);
                if (!t)
                        return log_oom();

                r = table_add_many(table, TABLE_STRV_WRAPPED, t);
                if (r < 0)
                        return table_log_add_error(r);
        }

        table_set_header(table, false);
        *ret = TAKE_PTR(table);
        return 0;
}
