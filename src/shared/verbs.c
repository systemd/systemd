/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "env-util.h"
#include "format-table.h"
#include "log.h"
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
        /* A metadata entry that is not a real verb, like the group marker */
        return FLAGS_SET(ASSERT_PTR(verb)->flags, VERB_GROUP_MARKER);
}

const Verb* verbs_find_verb(const char *name, const Verb verbs[], const Verb verbs_end[]) {
        assert(verbs);

        for (const Verb *verb = verbs; verb < verbs_end; verb++) {
                if (verb_is_metadata(verb))
                        continue;

                if (name ? streq(name, verb->verb) : FLAGS_SET(verb->flags, VERB_DEFAULT))
                        return verb;
        }

        /* At the end of the list? */
        return NULL;
}

int _dispatch_verb_with_args(char **args, const Verb verbs[], const Verb verbs_end[], void *userdata) {
        int r;

        assert(verbs);
        assert(verbs_end > verbs);
        assert(verbs[0].verb);

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

int dispatch_verb(int argc, char *argv[], const Verb verbs[], void *userdata) {
        /* getopt wrapper for _dispatch_verb_with_args.
         * TBD: remove this function when all programs with verbs have been converted. */

        assert(argc >= 0);
        assert(argv);
        assert(argc >= optind);

        size_t n = 0;
        while (verbs[n].verb)
                n++;

        return _dispatch_verb_with_args(strv_skip(argv, optind), verbs, verbs + n, userdata);
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

int _verbs_get_help_table(
                const Verb verbs[],
                const Verb verbs_end[],
                const char *group,
                Table **ret) {
        int r;

        assert(ret);

        _cleanup_(table_unrefp) Table *table = table_new("verb", "help");
        if (!table)
                return log_oom();

        bool in_group = group == NULL;  /* Are we currently in the section on the array that forms
                                         * group <group>? The first part is the default group, so
                                         * if the group was not specified, we are in. */

        for (const Verb *verb = verbs; verb < verbs_end; verb++) {
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
        return 0;
}
