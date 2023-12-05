/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>

#include "env-util.h"
#include "log.h"
#include "macro.h"
#include "process-util.h"
#include "string-util.h"
#include "verbs.h"
#include "virt.h"

/* Wraps running_in_chroot() which is used in various places, but also adds an environment variable check so external
 * processes can reliably force this on.
 */
bool running_in_chroot_or_offline(void) {
        int r;

        /* Added to support use cases like rpm-ostree, where from %post scripts we only want to execute "preset", but
         * not "start"/"restart" for example.
         *
         * See docs/ENVIRONMENT.md for docs.
         */
        r = getenv_bool("SYSTEMD_OFFLINE");
        if (r < 0 && r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SYSTEMD_OFFLINE: %m");
        else if (r >= 0)
                return r > 0;

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
                log_debug_errno(r, "running_in_chroot(): %m");

        return r > 0;
}

const Verb* verbs_find_verb(const char *name, const Verb verbs[]) {
        assert(verbs);

        for (size_t i = 0; verbs[i].dispatch; i++)
                if (name ? streq(name, verbs[i].verb) : FLAGS_SET(verbs[i].flags, VERB_DEFAULT))
                        return verbs + i;

        /* At the end of the list? */
        return NULL;
}

static const Verb* verbs_find_prefix_verb(const char *name, const Verb verbs[]) {
        size_t best_distance = SIZE_MAX;
        const Verb *best = NULL;

        assert(verbs);

        if (!name)
                return NULL;

        for (size_t i = 0; verbs[i].dispatch; i++) {
                const char *e;
                size_t l;

                e = startswith(verbs[i].verb, name);
                if (!e)
                        continue;

                l = strlen(e);
                if (l < best_distance) {
                        best_distance = l;
                        best = verbs + i;
                }
        }

        return best;
}

static const Verb* verbs_find_closest_verb(const char *name, const Verb verbs[]) {
        ssize_t best_distance = SSIZE_MAX;
        const Verb *best = NULL;

        assert(verbs);

        if (!name)
                return NULL;

        for (size_t i = 0; verbs[i].dispatch; i++) {
                ssize_t distance;

                distance = strlevenshtein(verbs[i].verb, name);
                if (distance < 0) {
                        log_debug_errno(distance, "Failed to determine Levenshtein distance between %s and %s: %m", verbs[i].verb, name);
                        return NULL;
                }

                if (distance > 5) /* If the distance is just too far off, don't make a bad suggestion */
                        continue;

                if (distance < best_distance) {
                        best_distance = distance;
                        best = verbs + i;
                }
        }

        return best;
}

int dispatch_verb(int argc, char *argv[], const Verb verbs[], void *userdata) {
        const Verb *verb;
        const char *name;
        int left;

        assert(verbs);
        assert(verbs[0].dispatch);
        assert(argc >= 0);
        assert(argv);
        assert(argc >= optind);

        left = argc - optind;
        argv += optind;
        optind = 0;
        name = argv[0];

        verb = verbs_find_verb(name, verbs);
        if (!verb) {
                if (name) {
                        /* Be helperful to the user, and give a hint what the user might have wanted to
                         * type. We search with two mechanisms: a simple prefix match and – if that didn't
                         * yield results –, a Levenshtein word distance based match. */
                        verb = verbs_find_prefix_verb(name, verbs);
                        if (!verb)
                                verb = verbs_find_closest_verb(name, verbs);
                        if (verb)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unknown command verb '%s', did you mean '%s'?", name, verb->verb);

                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown command verb '%s'.", name);
                }

                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Command verb required.");
        }

        if (!name)
                left = 1;

        if (verb->min_args != VERB_ANY &&
            (unsigned) left < verb->min_args)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Too few arguments.");

        if (verb->max_args != VERB_ANY &&
            (unsigned) left > verb->max_args)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Too many arguments.");

        if ((verb->flags & VERB_ONLINE_ONLY) && running_in_chroot_or_offline()) {
                log_info("Running in chroot, ignoring command '%s'", name ?: verb->verb);
                return 0;
        }

        if (!name)
                return verb->dispatch(1, STRV_MAKE(verb->verb), userdata);

        return verb->dispatch(left, argv, userdata);
}
