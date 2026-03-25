/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

#define VERB_ANY (UINT_MAX)

typedef enum VerbFlags {
        VERB_DEFAULT      = 1 << 0,  /* The verb to run if no verb is specified */
        VERB_ONLINE_ONLY  = 1 << 1,  /* Just do nothing when running in chroot or offline */
} VerbFlags;

typedef struct {
        const char *verb;
        unsigned min_args, max_args;
        VerbFlags flags;
        int (* const dispatch)(int argc, char *argv[], uintptr_t data, void *userdata);
        uintptr_t data;
        const char *argspec;
        const char *help;
} Verb;

#define VERB_FULL(d, v, a, amin, amax, f, dat, h)                       \
        DISABLE_WARNING_REDUNDANT_DECLS                                 \
        static int d(int, char**, uintptr_t, void*);                    \
        REENABLE_WARNING                                                \
        _section_("SYSTEMD_VERBS")                                      \
        _alignptr_                                                      \
        _used_                                                          \
        _retain_                                                        \
        _variable_no_sanitize_address_                                  \
        static const Verb CONCATENATE3(d, _data_, __COUNTER__) = {      \
                .verb = v,                                              \
                .min_args = amin,                                       \
                .max_args = amax,                                       \
                .flags = f,                                             \
                .dispatch = d,                                          \
                .data = dat,                                            \
                .argspec = a,                                           \
                .help = h,                                              \
        }

/* The same as VERB_FULL, but without the data argument */
#define VERB(d, v, a, amin, amax, f, h)                                 \
        VERB_FULL(d, v, a, amin, amax, f, /* dat= */ 0, h)

/* Simplified VERB for parameters that take no argument */
#define VERB_NOARG(d, v, h)                                             \
        VERB(d, v, /* a= */ NULL, /* amin= */ VERB_ANY, /* amax= */ 1, /* f= */ 0, h)

/* This is magically mapped to the beginning and end of the section */
extern const Verb __start_SYSTEMD_VERBS[];
extern const Verb __stop_SYSTEMD_VERBS[];

bool running_in_chroot_or_offline(void);

bool should_bypass(const char *env_prefix);

const Verb* verbs_find_verb(const char *name, const Verb verbs[], const Verb verbs_end[]);

int _dispatch_verb_with_args(char **args, const Verb verbs[], const Verb verbs_end[], void *userdata);
#define dispatch_verb_with_args(args, userdata) \
        _dispatch_verb_with_args(args, ALIGN_PTR(__start_SYSTEMD_VERBS), __stop_SYSTEMD_VERBS, userdata)

int dispatch_verb(int argc, char *argv[], const Verb verbs[], void *userdata);

int _verbs_get_help_table(const Verb verbs[], const Verb verbs_end[], Table **ret);
#define verbs_get_help_table(ret) \
        _verbs_get_help_table(ALIGN_PTR(__start_SYSTEMD_VERBS), __stop_SYSTEMD_VERBS, ret)

#define _VERB_COMMON_HELP_IMPL(impl)                                    \
        static int verb_help(int argc, char **argv, uintptr_t data, void *userdata) { \
                return impl();                                          \
        }

#define VERB_COMMON_HELP(impl)                                          \
        VERB(verb_help, "help", NULL, VERB_ANY, VERB_ANY, 0, "Show this help"); \
        _VERB_COMMON_HELP_IMPL(impl)

#define VERB_COMMON_HELP_HIDDEN(impl)                                   \
        VERB(verb_help, "help", NULL, VERB_ANY, VERB_ANY, 0, NULL);     \
        _VERB_COMMON_HELP_IMPL(impl)
