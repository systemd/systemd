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
        int (* const dispatch)(int argc, char *argv[], void *userdata);
        const char *argspec;
        const char *help;
} Verb;

#define VERB(d, v, a, amin, amax, f, h)                                 \
        static int d(int, char**, void*);                               \
        _Pragma("GCC diagnostic ignored \"-Wattributes\"")              \
        _section_("SYSTEMD_VERBS")                                      \
        _alignptr_                                                      \
        _used_                                                          \
        _retain_                                                        \
        _variable_no_sanitize_address_                                  \
        static const Verb CONCATENATE(d, _data) = {                     \
                .verb = v,                                              \
                .min_args = amin,                                       \
                .max_args = amax,                                       \
                .flags = f,                                             \
                .dispatch = d,                                          \
                .argspec = a,                                           \
                .help = h,                                              \
        }

/* The same as VERB_FULL, but without the argument */
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

int _verbs_get_help_table(const Verb verbs[], const Verb verbs_end[], Table **ret, size_t *ret_width_of_first_column);
#define verbs_get_help_table(ret, ret_width_of_first_column)            \
        _verbs_get_help_table(ALIGN_PTR(__start_SYSTEMD_VERBS), __stop_SYSTEMD_VERBS, ret, ret_width_of_first_column)

#define VERB_COMMON_HELP(impl)                                          \
        VERB(verb_help, "help", NULL, VERB_ANY, VERB_ANY, 0, "Show this help"); \
        static int verb_help(int argc, char **argv, void *userdata) {   \
                return impl();                                          \
        }

int _introspect_verbs(const Verb verbs[], const Verb verbs_end[], sd_json_format_flags_t flags);
#define introspect_verbs(flags)                                         \
        _introspect_verbs(ALIGN_PTR(__start_SYSTEMD_VERBS), __stop_SYSTEMD_VERBS, flags)
#define introspect_verbs_dummy() _introspect_verbs(NULL, NULL, /* flags= */ 0)
