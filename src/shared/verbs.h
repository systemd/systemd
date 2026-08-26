/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "options.h"

#define VERB_ANY (UINT_MAX)

typedef enum CommandFlags {
        COMMAND_HELP_SEPARATE = 1 << 0,  /* Do not synchronize the width between verbs and options */
        COMMAND_VERBS_SHARED  = 1 << 1,  /* We have a group of COMMANDs with this flag set, and then
                                          * the VERB definitions below. The commands share the same
                                          * set of actual VERB definitions. This is useful for programs
                                          * which are registered under multiple names, but each one
                                          * behaves very similarly. */
} CommandFlags;

typedef struct CommandDescription {
        const char *names;             /* nulstr with the main command name and potentially aliases */
        const char *abstract;          /* concrete abstract */
        const char *argspec;           /* optional specification of positional args in synopsis */
        const char *footer;            /* optional footer to print right above man page links */
        const char *man_pages;         /* nulstr with man page names */
        const char *option_namespace;  /* optional option namespace for this command */
        const char *option_groups;     /* optional nulstr with option groups for this command */
        const PagerFlags *pager_flags; /* optional pointer to the runtime pager flags variable */
        CommandFlags flags;
} CommandDescription;

typedef enum VerbFlags {
        VERB_DEFAULT        = 1 << 0,  /* The verb to run if no verb is specified */
        VERB_ONLINE_ONLY    = 1 << 1,  /* Just do nothing when running in chroot or offline */
        VERB_COMMAND_MARKER = 1 << 2,  /* Header entry with command description */
        VERB_GROUP_MARKER   = 1 << 3,  /* Fake verb entry to separate groups */
} VerbFlags;

/* Note: see the comment on struct Option in options.h for why _alignptr_ is required here. */
typedef struct _alignptr_ Verb {
        const char *verb;
        unsigned min_args, max_args;
        VerbFlags flags;
        int (* const dispatch)(int argc, char *argv[], uintptr_t data, void *userdata);
        uintptr_t data;
        const char *argspec;
        const char *help;
        const char *option_namespace;  /* optional namespace with the verb's own options */
} Verb;
assert_cc(sizeof(Verb) % sizeof(void*) == 0);

#define _VERB_DATA(d, v, ns, a, amin, amax, f, dat, h)                  \
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
                .option_namespace = ns,                                 \
        }

/* Forward-define function d. scope specifies the scope, e.g. static. ns declares the option
 * namespace with the verb's own options, which are then shown in the verb's help (see
 * command_print_verb_help()) and reported in the CLI introspection. */
#define VERB_SCOPE_NS_FULL(scope, d, v, ns, a, amin, amax, f, dat, h)   \
        DISABLE_WARNING_REDUNDANT_DECLS                                 \
        scope int d(int, char**, uintptr_t, void*);                     \
        REENABLE_WARNING                                                \
        _VERB_DATA(d, v, ns, a, amin, amax, f, dat, h)
/* The same as VERB_SCOPE_NS_FULL, but for verbs without options of their own. */
#define VERB_SCOPE_FULL(scope, d, v, a, amin, amax, f, dat, h)          \
        VERB_SCOPE_NS_FULL(scope, d, v, /* ns= */ NULL, a, amin, amax, f, dat, h)
/* The same as VERB_SCOPE_NS_FULL/VERB_SCOPE_FULL with scope hardwired to 'static'. */
#define VERB_NS_FULL(d, v, ns, a, amin, amax, f, dat, h)                \
        VERB_SCOPE_NS_FULL(static, d, v, ns, a, amin, amax, f, dat, h)
#define VERB_FULL(d, v, a, amin, amax, f, dat, h)                       \
        VERB_SCOPE_FULL(static, d, v, a, amin, amax, f, dat, h)

/* The same as the macros above, but without the data argument. */
#define VERB_SCOPE_NS(scope, d, v, ns, a, amin, amax, f, h)             \
        VERB_SCOPE_NS_FULL(scope, d, v, ns, a, amin, amax, f, /* dat= */ 0, h)
#define VERB_SCOPE(scope, d, v, a, amin, amax, f, h)                    \
        VERB_SCOPE_FULL(scope, d, v, a, amin, amax, f, /* dat= */ 0, h)
#define VERB_NS(d, v, ns, a, amin, amax, f, h)                          \
        VERB_SCOPE_NS(static, d, v, ns, a, amin, amax, f, h)
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
        _VERB_DATA(/* d= */ NULL, /* v= */ gr, /* ns= */ NULL, /* a= */ NULL, \
                   /* amin= */ 0, /* amax= */ 0, /* f= */ VERB_GROUP_MARKER, /* dat= */ 0, /* h= */ NULL)

#define _COMMAND(u, ...)                                                \
        static const CommandDescription UNIQ_T(description, u) = { __VA_ARGS__ }; \
        _VERB_DATA(/* d= */ NULL, /* v= */ NULL, /* ns= */ NULL, /* a= */ NULL, \
                   /* amin= */ 0, /* amax= */ 0, /* f= */ VERB_COMMAND_MARKER, \
                   /* dat= */ (uintptr_t) &UNIQ_T(description, u), /* h= */ NULL)
#define COMMAND(...) _COMMAND(UNIQ, __VA_ARGS__)

/* This is magically mapped to the beginning and end of the section */
extern const Verb __start_SYSTEMD_VERBS[];
extern const Verb __stop_SYSTEMD_VERBS[];

bool running_in_chroot_or_offline(void);

bool should_bypass(const char *env_prefix);

const Verb* _verbs_find_command(const Verb verbs[], const Verb verbs_end[], const char *name, const CommandDescription **ret_cmd);
#define verbs_find_command(name, ret_cmd)                               \
        _verbs_find_command(__start_SYSTEMD_VERBS, __stop_SYSTEMD_VERBS, name, ret_cmd)

const Verb* _verbs_find_verb(const Verb verbs[], const Verb verbs_end[], const char *name);
#define verbs_find_verb(name) \
        _verbs_find_verb(__start_SYSTEMD_VERBS, __stop_SYSTEMD_VERBS, name)

int _dispatch_verb(char **args, const Verb verbs[], const Verb verbs_end[], void *userdata);
#define dispatch_verb(args, userdata) \
        _dispatch_verb(args, __start_SYSTEMD_VERBS, __stop_SYSTEMD_VERBS, userdata)

int _verbs_get_help_table(
                const Verb verbs[],
                const Verb verbs_end[],
                const char *group,
                Table **ret);
#define verbs_get_help_table_group(group, ret)                          \
        _verbs_get_help_table(__start_SYSTEMD_VERBS, __stop_SYSTEMD_VERBS, group, ret)
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

#define VERB_COMMON_HELP_AUTO_FULL(program, help)                       \
        VERB_FULL(verb_help_auto, "help", NULL, VERB_ANY, VERB_ANY, 0, /* dat= */ (uintptr_t) program, /* help= */ help)
#define VERB_COMMON_HELP_AUTO_PROGRAM(program) VERB_COMMON_HELP_AUTO_FULL(program, "Show this help")
#define VERB_COMMON_HELP_AUTO_PROGRAM_HIDDEN(program) VERB_COMMON_HELP_AUTO_FULL(program, /* help= */ NULL)
#define VERB_COMMON_HELP_AUTO() VERB_COMMON_HELP_AUTO_PROGRAM(/* program= */ NULL)
#define VERB_COMMON_HELP_AUTO_HIDDEN() VERB_COMMON_HELP_AUTO_PROGRAM_HIDDEN(/* program= */ NULL)

int _command_print_help_full(
                const Verb verbs[],
                const Verb verbs_end[],
                const Option options[],
                const Option options_end[],
                const char *name,
                const char *footer_ansi_seq);
#define command_print_help_full(name, footer_ansi_seq)                  \
        _command_print_help_full(                                       \
                __start_SYSTEMD_VERBS, __stop_SYSTEMD_VERBS,            \
                __start_SYSTEMD_OPTIONS, __stop_SYSTEMD_OPTIONS,        \
                name, footer_ansi_seq)
#define command_print_help_name(name) command_print_help_full(name, /* footer_ansi_seq= */ NULL)
#define command_print_help() command_print_help_name(/* name= */ NULL)

static inline int verb_help_auto(int argc, char **argv, uintptr_t data, void *userdata) {
        return command_print_help_name((const char*) data);
}

typedef enum CommandVerbHelpFlags {
        COMMAND_VERB_HELP_NO_MAN_PAGES = 1 << 0,  /* Do not print the command's man page links */
} CommandVerbHelpFlags;

/* Print the help for a single verb: the synopsis, the one-line help as abstract, the options from
 * the verb's option namespace (see VERB_SCOPE_NS*), and the man page links of the command the verb
 * belongs to. The verb is attributed to the closest preceding COMMAND() in the verbs section, so:
 * name must refer to an existing verb owned by such a command (asserted otherwise), verb names
 * must be unique across the whole binary, commands with COMMAND_VERBS_SHARED are not
 * disambiguated, and a declared option namespace must contain at least one non-hidden option. */
int _command_print_verb_help(
                const Verb verbs[],
                const Verb verbs_end[],
                const Option options[],
                const Option options_end[],
                const char *name);
#define command_print_verb_help(name)                                   \
        _command_print_verb_help(                                       \
                __start_SYSTEMD_VERBS, __stop_SYSTEMD_VERBS,            \
                __start_SYSTEMD_OPTIONS, __stop_SYSTEMD_OPTIONS,        \
                name)

/* Print a machine-readable description of the program's commands, verbs, and options in the format
 * defined by the CLI-Introspection Specification. One command object is emitted for each
 * VERB_COMMAND() in the verb table, so multicall binaries are described in full. */
int _introspect_cli(
                const Verb verbs[],
                const Verb verbs_end[],
                const Option options[],
                const Option options_end[],
                sd_json_format_flags_t flags);
#define introspect_cli(flags)                                           \
        _introspect_cli(                                                \
                __start_SYSTEMD_VERBS, __stop_SYSTEMD_VERBS,            \
                __start_SYSTEMD_OPTIONS, __stop_SYSTEMD_OPTIONS,        \
                flags)
