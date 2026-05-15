/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

#define VERB_ANY (UINT_MAX)

typedef enum VerbFlags {
        VERB_DEFAULT      = 1 << 0,  /* The verb to run if no verb is specified */
        VERB_ONLINE_ONLY  = 1 << 1,  /* Just do nothing when running in chroot or offline */
        VERB_GROUP_MARKER = 1 << 2,  /* Fake verb entry to separate groups */
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

#define _VERB_DATA(d, v, a, amin, amax, f, dat, h)                      \
        _section_("SYSTEMD_VERBS")                                      \
        _alignptr_                                                      \
        _used_                                                          \
        _retain_                                                        \
        _no_reorder_                                                    \
        _variable_no_sanitize_address_                                  \
        static const Verb CONCATENATE(verb_data_, __COUNTER__) = {      \
                .verb = v,                                              \
                .min_args = amin,                                       \
                .max_args = amax,                                       \
                .flags = f,                                             \
                .dispatch = d,                                          \
                .data = dat,                                            \
                .argspec = a,                                           \
                .help = h,                                              \
        }

/* Forward-define function d. scope specifies the scope, e.g. static. */
#define VERB_SCOPE_FULL(scope, d, v, a, amin, amax, f, dat, h)          \
        DISABLE_WARNING_REDUNDANT_DECLS                                 \
        scope int d(int, char**, uintptr_t, void*);                     \
        REENABLE_WARNING                                                \
        _VERB_DATA(d, v, a, amin, amax, f, dat, h)
/* The same as VERB_SCOPE_FULL with scope hardwired to 'static'. */
#define VERB_FULL(d, v, a, amin, amax, f, dat, h)                       \
        VERB_SCOPE_FULL(static, d, v, a, amin, amax, f, dat, h)

/* The same as VERB_SCOPE_FULL/VERB_FULL, but without the data argument. */
#define VERB_SCOPE(scope, d, v, a, amin, amax, f, h)                    \
        VERB_SCOPE_FULL(scope, d, v, a, amin, amax, f, /* dat= */ 0, h)
#define VERB(d, v, a, amin, amax, f, h)                                 \
        VERB_SCOPE(static, d, v, a, amin, amax, f, h)

/* Simplified VERB_SCOPE/VERB for verbs that take no argument. */
#define VERB_SCOPE_NOARG(scope, d, v, h)                                \
        VERB_SCOPE(scope, d, v, /* a= */ NULL, /* amin= */ VERB_ANY, /* amax= */ 1, /* f= */ 0, h)
#define VERB_NOARG(d, v, h)                                             \
        VERB_SCOPE_NOARG(static, d, v, h)
#define VERB_DEFAULT_NOARG(d, v, h)                                     \
        VERB_SCOPE(static, d, v, /* a= */ NULL, /* amin= */ VERB_ANY, /* amax= */ 1, /* f= */ VERB_DEFAULT, h)

/* Magic entry in the table (which will not be returned) that designates the start of the group <gr>.
 * The macro works as a separator between groups and must be between other VERB* stanzas. */
#define VERB_GROUP(gr)                                                  \
        _VERB_DATA(/* d= */ NULL, /* v= */ gr, /* a= */ NULL, /* amin= */ 0, /* amax= */ 0, \
                  /* f= */ VERB_GROUP_MARKER, /* dat= */ 0, /* h= */ NULL)

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

int _verbs_get_help_table(
                const Verb verbs[],
                const Verb verbs_end[],
                const char *group,
                Table **ret);
#define verbs_get_help_table_group(group, ret)                          \
        _verbs_get_help_table(ALIGN_PTR(__start_SYSTEMD_VERBS), __stop_SYSTEMD_VERBS, group, ret)
#define verbs_get_help_table(ret)                                       \
        verbs_get_help_table_group(/* group= */ NULL, ret)

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
