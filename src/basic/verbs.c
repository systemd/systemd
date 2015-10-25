/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "string-util.h"
#include "util.h"
#include "verbs.h"

int dispatch_verb(int argc, char *argv[], const Verb verbs[], void *userdata) {
        const Verb *verb;
        const char *name;
        unsigned i;
        int left;

        assert(verbs);
        assert(verbs[0].dispatch);
        assert(argc >= 0);
        assert(argv);
        assert(argc >= optind);

        left = argc - optind;
        name = argv[optind];

        for (i = 0;; i++) {
                bool found;

                /* At the end of the list? */
                if (!verbs[i].dispatch) {
                        if (name)
                                log_error("Unknown operation %s.", name);
                        else
                                log_error("Requires operation parameter.");
                        return -EINVAL;
                }

                if (name)
                        found = streq(name, verbs[i].verb);
                else
                        found = !!(verbs[i].flags & VERB_DEFAULT);

                if (found) {
                        verb = &verbs[i];
                        break;
                }
        }

        assert(verb);

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
