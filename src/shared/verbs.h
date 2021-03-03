/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#define VERB_ANY (UINT_MAX)

typedef enum VerbFlags {
        VERB_DEFAULT      = 1 << 0,  /* The verb to run if no verb is specified */
        VERB_ONLINE_ONLY  = 1 << 1,  /* Just do nothing when running in chroot or offline */
} VerbFlags;

typedef struct {
        const char *verb;
        unsigned min_args, max_args;
        VerbFlags flags;
        int (* const dispatch)(int argc, char *argv[], void *userdata);
} Verb;

bool running_in_chroot_or_offline(void);

const Verb* verbs_find_verb(const char *name, const Verb verbs[]);
int dispatch_verb(int argc, char *argv[], const Verb verbs[], void *userdata);
