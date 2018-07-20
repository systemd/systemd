/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "env-util.h"
#include "log.h"
#include "macro.h"
#include "process-util.h"
#include "string-util.h"
#include "verbs.h"
#include "virt.h"
#include "strv.h"

/* Wraps running_in_chroot() which is used in various places, but also adds an environment variable check so external
 * processes can reliably force this on.
 */
bool running_in_chroot_or_offline(void) {
        int r;

        /* Added to support use cases like rpm-ostree, where from %post scripts we only want to execute "preset", but
         * not "start"/"restart" for example.
         *
         * See doc/ENVIRONMENT.md for docs.
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

int dispatch_verb(int argc, char *argv[], const Verb verbs[], void *userdata) {
        const Verb *verb;
        const char *name;
        size_t namelen;
        unsigned verbslen;
        unsigned i;
        int left, r;

        assert(verbs);
        assert(verbs[0].dispatch);
        assert(argc >= 0);
        assert(argv);
        assert(argc >= optind);

        left = argc - optind;
        name = argv[optind];
        namelen = name ? strlen(name) : 0;

        for (unsigned n = 0;; ++n)
                if (!verbs[n].dispatch) {
                        verbslen = n;
                        break;
                }

        unsigned nfound = 0;
        const char *matches[verbslen];
        unsigned foundi;
        for (i = 0;; i++) {

                /* At the end of the list? */
                if (!verbs[i].dispatch) {
                        if (nfound == 1)
                                break;
                        else if (nfound > 1) {
                                const char *opts_list;
                                matches[nfound] = NULL;
                                opts_list = strv_join((char **)matches, ", "); // TODO: naughty!
                                log_error("Ambiguous parameter match: could be %s", opts_list);
                        } else if (name)
                                log_error("Unknown operation %s.", name);
                        else
                                log_error("Requires operation parameter.");
                        return -EINVAL;
                }

                if (name) {
                        if (strneq(name, verbs[i].verb, namelen)) {
                                matches[nfound] = verbs[i].verb;
                                foundi = i;
                                ++nfound;
                                /* if exact match, accept it immediately */
                                if (streq(name, verbs[i].verb))
                                        break;
                        }
                } else if (verbs[i].flags & VERB_DEFAULT) {
                        foundi = i;
                        ++nfound;
                }

        }
        verb = &verbs[foundi];

        if (!name)
                left = 1;

        if (verb->min_args != VERB_ANY &&
            (unsigned) left < verb->min_args) {
                log_error("Too few arguments.");
                return -EINVAL;
        }

        if (verb->max_args != VERB_ANY &&
            (unsigned) left > verb->max_args) {
                log_error("Too many arguments.");
                return -EINVAL;
        }

        if ((verb->flags & VERB_ONLINE_ONLY) && running_in_chroot_or_offline()) {
                if (name)
                        log_info("Running in chroot, ignoring request: %s", name);
                else
                        log_info("Running in chroot, ignoring request.");
                return 0;
        }

        if (verb->flags & VERB_MUST_BE_ROOT) {
                r = must_be_root();
                if (r < 0)
                        return r;
        }

        if (name)
                return verb->dispatch(left, argv + optind, userdata);
        else {
                char* fake[2] = {
                        (char*) verb->verb,
                        NULL
                };

                return verb->dispatch(1, fake, userdata);
        }
}
