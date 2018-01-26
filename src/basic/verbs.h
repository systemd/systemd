/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

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

#define VERB_ANY ((unsigned) -1)

typedef enum VerbFlags {
        VERB_DEFAULT      = 1 << 0,
        VERB_ONLINE_ONLY  = 1 << 1,
        VERB_MUST_BE_ROOT = 1 << 2,
} VerbFlags;

typedef struct {
        const char *verb;
        unsigned min_args, max_args;
        VerbFlags flags;
        int (* const dispatch)(int argc, char *argv[], void *userdata);
} Verb;

bool running_in_chroot_or_offline(void);

int dispatch_verb(int argc, char *argv[], const Verb verbs[], void *userdata);
