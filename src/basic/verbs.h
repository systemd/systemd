/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

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
