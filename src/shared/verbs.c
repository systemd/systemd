/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "build.h"
#include "env-util.h"
#include "extract-word.h"
#include "format-table.h"
#include "help-util.h"
#include "log.h"
#include "nulstr-util.h"
#include "options.h"
#include "pager.h"
#include "pretty-print.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "verbs.h"
#include "virt.h"

/* Wraps running_in_chroot() which is used in various places, but also adds an environment variable check
 * so external processes can reliably force this on. */
bool running_in_chroot_or_offline(void) {
        int r;

        /* Added to support use cases like rpm-ostree, where from %post scripts we only want to execute "preset",
         * but not "start"/"restart" for example.
         *
         * See docs/ENVIRONMENT.md for docs.
         */
        r = getenv_bool("SYSTEMD_OFFLINE");
        if (r >= 0)
                return r > 0;
        if (r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SYSTEMD_OFFLINE, ignoring: %m");

        /* We've had this condition check for a long time which basically checks for legacy chroot case like Fedora's
         * "mock", which is used for package builds.  We don't want to try to start systemd services there, since
         * without --new-chroot we don't even have systemd running, and even if we did, adding a concept of background
         * daemons to builds would be an enormous change, requiring considering things like how the journal output is
         * handled, etc.  And there's really not a use case today for a build talking to a service.
         *
         * Note this call itself also looks for a different variable SYSTEMD_IGNORE_CHROOT=1.
         */
        r = running_in_chroot();
        if (r < 0)
                log_debug_errno(r, "Failed to check if we're running in chroot, assuming not: %m");
        return r > 0;
}

bool should_bypass(const char *env_prefix) {
        char *env;
        int r;

        assert(env_prefix);

        env = strjoina(env_prefix, "_BYPASS");

        r = getenv_bool(env);
        if (r < 0 && r != -ENXIO)
                log_debug_errno(r, "Failed to parse $%s, assuming no: %m", env);
        if (r <= 0)
                return false;

        log_debug("$%s is enabled, skipping execution.", env);
        return true;
}

static bool verb_is_metadata(const Verb *verb) {
        /* A metadata entry that is not a real verb, i.e. either the command and group markers. */
        return  FLAGS_SET(ASSERT_PTR(verb)->flags, VERB_COMMAND_MARKER) ||
                FLAGS_SET(ASSERT_PTR(verb)->flags, VERB_GROUP_MARKER);
}

const Verb* verbs_find_verb(const char *name, const Verb verbs[], const Verb verbs_end[]) {
        assert(verbs);
        assert(verbs_end > verbs);
        assert((uintptr_t) verbs % sizeof(void*) == 0);
        assert(FLAGS_SET(verbs[0].flags, VERB_COMMAND_MARKER) || verbs[0].verb);

        for (const Verb *verb = verbs; verb < verbs_end; verb++) {
                if (verb_is_metadata(verb))
                        continue;

                if (name ? streq(name, verb->verb) : FLAGS_SET(verb->flags, VERB_DEFAULT))
                        return verb;
        }

        /* At the end of the list? */
        return NULL;
}

int _dispatch_verb(char **args, const Verb verbs[], const Verb verbs_end[], void *userdata) {
        int r;

        assert(verbs);
        assert(verbs_end > verbs);
        assert((uintptr_t) verbs % sizeof(void*) == 0);
        assert(FLAGS_SET(verbs[0].flags, VERB_COMMAND_MARKER) || verbs[0].verb);

        const char *name = args ? args[0] : NULL;
        size_t left = strv_length(args);

        const Verb *verb = verbs_find_verb(name, verbs, verbs_end);
        if (!verb) {
                _cleanup_strv_free_ char **verb_strv = NULL;

                for (verb = verbs; verb < verbs_end; verb++) {
                        if (verb_is_metadata(verb))
                                continue;

                        r = strv_extend(&verb_strv, verb->verb);
                        if (r < 0)
                                return log_oom();
                }
                assert(!strv_isempty(verb_strv));  /* At least one verb should be defined… */

                if (name) {
                        /* Be more helpful to the user, and give a hint what the user might have wanted to type. */
                        const char *found = strv_find_closest(verb_strv, name);
                        if (found)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unknown command verb '%s', did you mean '%s'?", name, found);

                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown command verb '%s'.", name);
                }

                if (strv_length(verb_strv) >= 2) {
                        _cleanup_free_ char *joined = strv_join(verb_strv, ", ");
                        if (!joined)
                                return log_oom();

                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Command verb required (one of %s).", joined);
                }

                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Command verb '%s' required.", verb_strv[0]);
        }

        if (!name)
                left = 1;

        if (verb->min_args != VERB_ANY && left < verb->min_args)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Too few arguments.");

        if (verb->max_args != VERB_ANY && left > verb->max_args)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Too many arguments.");

        if ((verb->flags & VERB_ONLINE_ONLY) && running_in_chroot_or_offline()) {
                log_info("Running in chroot, ignoring command '%s'", name ?: verb->verb);
                return 0;
        }

        if (!name)
                return verb->dispatch(1, STRV_MAKE(verb->verb), verb->data, userdata);

        assert(left < INT_MAX);  /* args are derived from argc+argv, so their size must fit in an int. */
        return verb->dispatch(left, args, verb->data, userdata);
}

#define VERB_SYNOPSIS_WIDTH_SANE 25

static const char* find_point_to_break(const char *s, size_t max_width) {
        /* Locate the first space, preferably after max_width, or the last space otherwise.
         * Return the part after the space. */

        if (strlen(s) <= max_width)
                return NULL;

        const char *p = strchr(s + max_width, ' ') ?: strrchr(s, ' ');
        return p ? p + 1 : NULL;
}

static int verb_add_help_one(Table *table, const Verb *verb) {
        assert(table);
        assert(verb);

        bool is_default = FLAGS_SET(verb->flags, VERB_DEFAULT);
        int r;

        /* We indent the option string by two spaces. We could set the minimum cell width and
         * right-align for a similar result, but that'd be more work. This is only used for
         * display. */
        _cleanup_free_ char *s = strjoin("  ",
                                         is_default ? "[" : "",
                                         verb->verb,
                                         verb->argspec ? " " : "",
                                         strempty(verb->argspec),
                                         is_default ? "]" : "");
        if (!s)
                return log_oom();

        const char *ss = NULL;
        if (columns() < VERB_SYNOPSIS_WIDTH_SANE * 4) {
                /* If the synopsis is very wide, try to split it up. But do this only if the terminal
                 * is not very wide. If it _is_ wide, the broken up synopsis would look silly. */
                const char *p = find_point_to_break(s, VERB_SYNOPSIS_WIDTH_SANE), *p2 = NULL;
                if (p) {
                        const char *s1 = strndupa_safe(s, p - s), *s2 = NULL;

                        p2 = find_point_to_break(p, VERB_SYNOPSIS_WIDTH_SANE - 4); /* we indent by two spaces more */
                        if (p2)
                                s2 = strndupa_safe(p, p2 - p);

                        if (s2)
                                ss = strjoina(s1, "\n    ", s2, "\n    ", p2);
                        else
                                ss = strjoina(s1, "\n    ", p);
                }
        }

        r = table_add_cell(table, NULL, TABLE_STRING, ss ?: s);
        if (r < 0)
                return table_log_add_error(r);

        _cleanup_strv_free_ char **t = strv_split(verb->help, /* separators= */ NULL);
        if (!t)
                return log_oom();

        r = table_add_many(table, TABLE_STRV_WRAPPED, t);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static const Verb* verbs_get_command(const Verb verbs[], const Verb verbs_end[], const char *name) {
        assert(verbs);
        assert(verbs_end > verbs);
        assert((uintptr_t) verbs % sizeof(void*) == 0);
        assert(FLAGS_SET(verbs[0].flags, VERB_COMMAND_MARKER) || verbs[0].verb);
        assert(name);

        for (const Verb *verb = verbs; verb < verbs_end; verb++) {
                if (!FLAGS_SET(verb->flags, VERB_COMMAND_MARKER))
                        continue;

                const CommandDescription *cmd = (const CommandDescription*) ASSERT_PTR(verb->data);
                if (nulstr_contains(cmd->names, name))
                        return verb;
        }

        /* At the end of the list? */
        return NULL;
}

int _verbs_get_help_table(
                const Verb verbs[],
                const Verb verbs_end[],
                const char *group,
                Table **ret) {
        int r;

        assert(verbs);
        assert(verbs_end > verbs);
        assert((uintptr_t) verbs % sizeof(void*) == 0);
        assert(ret);

        _cleanup_(table_unrefp) Table *table = table_new("verb", "help");
        if (!table)
                return log_oom();

        bool in_group = group == NULL;  /* Are we currently in the section on the array that forms
                                         * group <group>? The first part is the default group, so
                                         * if the group was not specified, we are in. */

        const Verb *verb;
        for (verb = verbs; verb < verbs_end; verb++) {
                /* Binaries with one or more VERB_COMMAND entries call this function
                 * through print_verb_option_help() which provides a verbs slice that
                 * starts after the VERB_COMMAND entry.
                 *
                 * In unconverted binaries, this function is called directly. */
                // TODO: make this function static after everything has been converted.

                if (FLAGS_SET(verb->flags, VERB_COMMAND_MARKER))
                        break;

                assert(verb->verb);

                bool group_marker = FLAGS_SET(verb->flags, VERB_GROUP_MARKER);
                if (!in_group) {
                        in_group = group_marker && streq(group, verb->verb);
                        continue;
                }
                if (group_marker)
                        break;  /* End of group */

                if (!verb->help)
                        /* No help string — we do not show the verb */
                        continue;

                r = verb_add_help_one(table, verb);
                if (r < 0)
                        return r;
        }

        table_set_header(table, false);
        *ret = TAKE_PTR(table);

        assert(verb - verbs < INT_MAX);
        return verb - verbs; /* Return the count of verb entries "consumed". */
}

static void table_array_freep(Table ***tables) {
        assert(tables);

        for (Table **t = *tables; t && *t; t++)
                *t = table_unref(*t);
        free(*tables);
}

static int print_verb_option_help(
                const CommandDescription *cmd,
                const Verb verbs[],
                const Verb verbs_end[],
                const Option options[],
                const Option options_end[]) {

        assert(verbs);
        assert(verbs_end >= verbs);
        assert((uintptr_t) verbs % sizeof(void*) == 0);

        _cleanup_free_ const char **groups = NULL;
        _cleanup_(table_array_freep) Table **tables = NULL;
        size_t n_verbs = 0, n_opts = 0;
        int r;

        for (const Verb *verb = verbs; verb < verbs_end;) {
                if (FLAGS_SET(verb->flags, VERB_COMMAND_MARKER))
                        /* Start of entries for another command */
                        break;

                assert(verb->verb);

                /* What is the the first group? */
                const char *group = FLAGS_SET(verb->flags, VERB_GROUP_MARKER) ? verb->verb : NULL;

                _cleanup_(table_unrefp) Table *table = NULL;
                r = _verbs_get_help_table(verb, verbs_end, group, &table);
                if (r < 0)
                        return r;

                if (!GREEDY_REALLOC0(tables, n_verbs + 2))
                        return -ENOMEM;
                if (!GREEDY_REALLOC0(groups, n_verbs + 2))
                        return -ENOMEM;

                tables[n_verbs] = TAKE_PTR(table);
                groups[n_verbs++] = group ?: "Commands";

                verb += r; /* Skip over the whole verb group */
        }

        if (cmd->flags & COMMAND_HELP_SEPARATE)
                (void) table_sync_all_column_widths(0, tables);

        const Option *optns = options_find_namespace(options, options_end, cmd->option_namespace);
        if (!optns)
                return log_error_errno(SYNTHETIC_ERRNO(EUCLEAN),
                                       "Option namespace %s not found.",
                                       cmd->option_namespace ?: "(unnamed)");

        for (const Option *opt = optns; opt < options_end;) {
                _cleanup_(table_unrefp) Table *table = NULL;
                const char *group;

                if (FLAGS_SET(opt->flags, OPTION_NAMESPACE_MARKER))
                        /* End of our namespace */
                        break;

                r = options_get_help_table_group(opt, options_end, &table, &group);
                if (r < 0)
                        return r;

                if (!GREEDY_REALLOC0(tables, n_verbs + n_opts + 2))
                        return -ENOMEM;
                if (!GREEDY_REALLOC0(groups, n_verbs + n_opts + 2))
                        return -ENOMEM;

                tables[n_verbs + n_opts] = TAKE_PTR(table);
                groups[n_verbs + n_opts++] = group ?: "Options";

                opt += r; /* Skip over the whole option group */
        }

        if (cmd->flags & COMMAND_HELP_SEPARATE)
                (void) table_sync_all_column_widths(0, tables + n_verbs);
        else
                (void) table_sync_all_column_widths(0, tables);

        for (size_t i = 0; i < n_verbs + n_opts; i++) {
                if (table_isempty(tables[i]))
                        continue;

                help_section(groups[i]);

                r = table_print_or_warn(tables[i]);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int print_man_links(const char *pages) {
        int r;

        NULSTR_FOREACH(page, pages) {
                _cleanup_free_ char *link = NULL;

                r = terminal_urlify_man(page, /* section= */ NULL, &link);
                if (r < 0)
                        return r;

                printf("\nSee the %s for details.\n", link);
        }

        return 0;
}

static bool verbs_array_has_verbs(const Verb verbs[], const Verb verbs_end[]) {
        for (const Verb *verb = verbs; verb < verbs_end; verb++) {
                if (FLAGS_SET(verb->flags, VERB_COMMAND_MARKER))  /* start of another command section */
                        break;
                if (!verb->help)  /* a hidden verb */
                        continue;
                return true;
        }

        return false;
}

static int print_wrapped(const char *text, bool abstract) {

        /* Print the text wrapped at spaces to the specified width. Newlines embedded in the text
         * are preserved and each line is wrapped independently, so explicit line breaks (e.g.
         * before an example command line) can be used where needed. */

        if (!text)
                return 0;

        _cleanup_strv_free_ char **lines = NULL, **lines2 = NULL;
        int r;

        size_t width = MIN(columns(), 80U);  /* This is a reasonable default. */

        r = strv_split_full(&lines, text, "\n", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return r;

        r = strv_rebreak_lines(lines, width, &lines2);
        if (r < 0)
                return r;

        /* Seperate this block from the previous input. */
        putchar('\n');

        STRV_FOREACH(line, lines2)
                if (abstract)
                        printf("%s%s%s%s\n",
                               ansi_highlight(),
                               ansi_add_italics(),
                               *line,
                               ansi_normal());
                else
                        puts(*line);

        return 0;
}

int _command_print_help(
                const Verb verbs[],
                const Verb verbs_end[],
                const Option options[],
                const Option options_end[],
                const char *name) {
        int r;

        const Verb *cmdverb = verbs_get_command(verbs, verbs_end, name);
        if (!cmdverb)
                return log_error_errno(SYNTHETIC_ERRNO(ENODATA),
                                       "Command %s not known", name);

        const CommandDescription *cmd = (const CommandDescription*) ASSERT_PTR(cmdverb->data);

        if (cmd->pager_flags)
                pager_open(*cmd->pager_flags);

        if (cmd->argspec)
                NULSTR_FOREACH(spec, cmd->argspec) {
                        _cleanup_free_ char *line = strjoin("[OPTION…] ", spec);
                        if (!line)
                                return log_oom();
                        help_cmdline(line);
                }
        else {
                bool have_verbs = verbs_array_has_verbs(cmdverb + 1, verbs_end);
                help_cmdline(have_verbs ? "[OPTION…] COMMAND …" : "[OPTION…]");
        }

        r = print_wrapped(cmd->abstract, /* abstract= */ true);
        if (r < 0)
                return r;

        r = print_verb_option_help(cmd, cmdverb + 1, verbs_end, options, options_end);
        if (r < 0)
                return log_error_errno(r, "Failed to print verb&option help: %m");

        r = print_wrapped(cmd->footer, /* abstract= */ false);
        if (r < 0)
                return r;

        r = print_man_links(cmd->man_pages);
        if (r < 0)
                return log_error_errno(r, "Failed to print man page links: %m");

        return 0;
}

static int verb_build_json(const Verb *verb, sd_json_variant **ret) {
        int r;

        assert(verb);
        assert(verb->verb);
        assert(ret);

        /* Verbs are represented as command objects, as described in the CLI-Introspection
         * Specification (https://uapi-group.org/specifications/specs/cli_introspection/).
         *
         * The "minArguments", "maxArguments", "isDefault", and "isOnlineOnly" fields
         * are extensions not (yet) covered by the specification. Note that the argument
         * counts include the verb itself. */

        r = sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRV("names", STRV_MAKE(verb->verb)),
                        SD_JSON_BUILD_PAIR_CONDITION(
                                        !!verb->help,
                                        "abstract", SD_JSON_BUILD_STRV(STRV_MAKE(verb->help))),
                        SD_JSON_BUILD_PAIR_CONDITION(
                                        verb->min_args != VERB_ANY,
                                        "minArguments", SD_JSON_BUILD_UNSIGNED(verb->min_args)),
                        SD_JSON_BUILD_PAIR_CONDITION(
                                        verb->max_args != VERB_ANY,
                                        "maxArguments", SD_JSON_BUILD_UNSIGNED(verb->max_args)),
                        SD_JSON_BUILD_PAIR_CONDITION(
                                        FLAGS_SET(verb->flags, VERB_DEFAULT),
                                        "isDefault", SD_JSON_BUILD_BOOLEAN(true)),
                        SD_JSON_BUILD_PAIR_CONDITION(
                                        FLAGS_SET(verb->flags, VERB_ONLINE_ONLY),
                                        "isOnlineOnly", SD_JSON_BUILD_BOOLEAN(true)));
        if (r < 0)
                return log_error_errno(r, "Failed to build JSON object: %m");

        return 0;
}

static int command_build_json(
                const Verb *cmdverb,
                const Verb verbs_end[],
                const Option options[],
                const Option options_end[],
                sd_json_variant **ret) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *names = NULL, *opts = NULL, *cmds = NULL;
        int r;

        assert(cmdverb);
        assert(FLAGS_SET(cmdverb->flags, VERB_COMMAND_MARKER));
        assert(ret);

        const CommandDescription *cmd = (const CommandDescription*) ASSERT_PTR(cmdverb->data);

        NULSTR_FOREACH(name, cmd->names) {
                r = sd_json_variant_append_arrayb(&names, SD_JSON_BUILD_STRING(name));
                if (r < 0)
                        return log_error_errno(r, "Failed to append JSON string to array: %m");
        }
        assert(names);  /* At least the primary name must be defined */

        r = options_build_json(options, options_end, cmd->option_namespace, &opts);
        if (r < 0)
                return r;

        for (const Verb *verb = cmdverb + 1; verb < verbs_end; verb++) {
                if (FLAGS_SET(verb->flags, VERB_COMMAND_MARKER))
                        break;  /* Start of entries for another command */

                if (FLAGS_SET(verb->flags, VERB_GROUP_MARKER))
                        continue;

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *o = NULL;
                r = verb_build_json(verb, &o);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(&cmds, o);
                if (r < 0)
                        return log_error_errno(r, "Failed to append JSON object to array: %m");
        }

        _cleanup_strv_free_ char **features = strv_split(systemd_features, /* separators= */ NULL);
        if (!features)
                return log_oom();

        r = sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_VARIANT("names", names),
                        SD_JSON_BUILD_PAIR_STRING("version", PROJECT_VERSION_FULL),
                        SD_JSON_BUILD_PAIR_STRV("features", features),
                        SD_JSON_BUILD_PAIR_CONDITION(
                                        !!cmd->abstract,
                                        "abstract", SD_JSON_BUILD_STRV(STRV_MAKE(cmd->abstract))),
                        SD_JSON_BUILD_PAIR_CONDITION(
                                        !!cmd->footer,
                                        "footer", SD_JSON_BUILD_STRV(STRV_MAKE(cmd->footer))),
                        SD_JSON_BUILD_PAIR_CONDITION(!!opts, "options", SD_JSON_BUILD_VARIANT(opts)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!cmds, "verbs", SD_JSON_BUILD_VARIANT(cmds)));
        if (r < 0)
                return log_error_errno(r, "Failed to build JSON object: %m");

        return 0;
}

int _introspect_cli(
                const Verb verbs[],
                const Verb verbs_end[],
                const Option options[],
                const Option options_end[],
                sd_json_format_flags_t flags) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *commands = NULL, *w = NULL;
        int r;

        assert(verbs);
        assert(verbs_end > verbs);
        assert((uintptr_t) verbs % sizeof(void*) == 0);

        if (flags == SD_JSON_FORMAT_OFF)
                flags = SD_JSON_FORMAT_PRETTY_AUTO;

        for (const Verb *verb = verbs; verb < verbs_end; verb++) {
                if (!FLAGS_SET(verb->flags, VERB_COMMAND_MARKER))
                        continue;

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *c = NULL;
                r = command_build_json(verb, verbs_end, options, options_end, &c);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(&commands, c);
                if (r < 0)
                        return log_error_errno(r, "Failed to append JSON object to array: %m");
        }

        if (!commands)
                return log_error_errno(SYNTHETIC_ERRNO(ENODATA),
                                       "No command description defined, cannot introspect.");

        r = sd_json_buildo(
                        &w,
                        SD_JSON_BUILD_PAIR_STRING(
                                        "mediaType",
                                        "application/vnd.io.systemd.cli-introspection-0"),
                        SD_JSON_BUILD_PAIR_VARIANT("commands", commands));
        if (r < 0)
                return log_error_errno(r, "Failed to build JSON object: %m");

        r = sd_json_variant_dump(w, flags, stdout, /* prefix= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to print JSON object: %m");

        return 0;
}
