/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"
#include "verbs.h"

typedef enum OptionFlags {
        OPTION_OPTIONAL_ARG  = 1U << 0,  /* Same as optional_argument in getopt */
        OPTION_STOPS_PARSING = 1U << 1,  /* This option acts like "--" */
        OPTION_GROUP_MARKER  = 1U << 2,  /* Fake option entry to separate groups */
} OptionFlags;

typedef struct Option {
        int id;
        OptionFlags flags;
        char short_code;
        const char *long_code;
        const char *metavar;
        const char *help;
} Option;

#define _OPTION(counter, fl, sc, lc, mv, h)                             \
        _Pragma("GCC diagnostic ignored \"-Wattributes\"")              \
        _section_("SYSTEMD_OPTIONS")                                    \
        _alignptr_                                                      \
        _used_                                                          \
        _retain_                                                        \
        _variable_no_sanitize_address_                                  \
        static const Option CONCATENATE(option, counter) = {            \
                .id = 0x100 + counter,                                  \
                .flags = fl,                                            \
                .short_code = sc,                                       \
                .long_code = lc,                                        \
                .metavar = mv,                                          \
                .help = h,                                              \
        };                                                              \
        case (0x100 + counter)

/* Magic entry in the table (which will not be returned) that designates the start of the group <gr>.
 * The define is structured as 'case' so that it can be followed by ':' and indented appropriately.
 */
#define OPTION_GROUP(gr)                                                \
        _OPTION(__COUNTER__, OPTION_GROUP_MARKER, /* sc= */ 0, /* lc= */ gr, /* mv= */ NULL, /* h= */ NULL)

#define OPTION_FULL(fl, sc, lc, mv, h) _OPTION(__COUNTER__, fl, sc, lc, mv, h)
#define OPTION(sc, lc, mv, h) OPTION_FULL(/* fl= */ 0, sc, lc, mv, h)
#define OPTION_LONG(lc, mv, h) OPTION(/* sc= */ 0, lc, mv, h)
#define OPTION_SHORT(sc, mv, h) OPTION(sc, /* lc= */ NULL, mv, h)

#define OPTION_COMMON_HELP \
        OPTION('h', "help", NULL, "Show this help")
#define OPTION_COMMON_VERSION \
        OPTION_LONG("version", NULL, "Show package version")
#define OPTION_COMMON_INTROSPECT \
        /* This option is internal-only and not shown in --help */ \
        OPTION_LONG("introspect", "WHAT", /* help= */ NULL)
#define OPTION_COMMON_NO_PAGER \
        OPTION_LONG("no-pager", NULL, "Do not start a pager")
#define OPTION_COMMON_NO_LEGEND \
        OPTION_LONG("no-legend", NULL, "Do not show headers and footers")
#define OPTION_COMMON_JSON \
        OPTION_LONG("json", "FORMAT", "Generate JSON output (pretty, short, or off)")

/* This is magically mapped to the beginning and end of the section */
extern const Option __start_SYSTEMD_OPTIONS[];
extern const Option __stop_SYSTEMD_OPTIONS[];

typedef struct OptionParser {
        int optind;               /* Position of the parameter being handled.
                                   * 0 → option parsing hasn't been started yet. */
        int short_option_offset;  /* Set when we're parsing an argument with one or more short options.
                                   * 0 → we're not parsing short options. */
        int positional_offset;    /* Offset to where positional parameters are. After processing has been
                                   * finished, all options and their args are to the left of this offset. */
        bool parsing_stopped;     /* We processed "--" or an option that terminates option parsing. */
} OptionParser;

int option_parse(
                const Option options[],
                const Option options_end[],
                OptionParser *state,
                int argc, char *argv[],
                const Option **ret_option,
                const char **ret_arg);

/* Iterate over options. */
#define FOREACH_OPTION_FULL(parser, opt, argc, argv, ret_o, ret_a, on_error) \
        for (int opt; (opt = option_parse(ALIGN_PTR(__start_SYSTEMD_OPTIONS), __stop_SYSTEMD_OPTIONS, parser, argc, argv, ret_o, ret_a)) != 0; ) \
                if (opt < 0) {                                                  \
                        on_error;                                               \
                        break;                                                  \
                } else

#define FOREACH_OPTION(parser, opt, argc, argv, ret_a, on_error) \
        FOREACH_OPTION_FULL(parser, opt, argc, argv, /* ret_o= */ NULL, ret_a, on_error)

char** option_parser_get_args(OptionParser *state, int argc, char *argv[]);
int _option_parser_get_help_table(
                const Option options[],
                const Option options_end[],
                const char *group,
                Table **ret,
                size_t *ret_width_of_first_column);
#define option_parser_get_help_table_group(group, ret, ret_width_of_first_column) \
        _option_parser_get_help_table(ALIGN_PTR(__start_SYSTEMD_OPTIONS), __stop_SYSTEMD_OPTIONS, group, ret, ret_width_of_first_column)
#define option_parser_get_help_table(ret, ret_width_of_first_column)    \
        option_parser_get_help_table_group(/* group= */ NULL, ret, ret_width_of_first_column)

int _introspect_options(
                const Option options_start[],
                const Option options_end[],
                sd_json_format_flags_t flags);
#define introspect_options(flags)                                       \
        _introspect_options(ALIGN_PTR(__start_SYSTEMD_OPTIONS), __stop_SYSTEMD_OPTIONS, flags)

#define introspect_options_and_dummy_verbs(arg, flags)                  \
        streq(arg, "options") ? introspect_options(flags) :             \
                streq(arg, "verbs") ? introspect_verbs_dummy() :        \
                log_error_errno(SYNTHETIC_ERRNO(EINVAL),                \
                                "Unknown introspection argument: %s", arg)

#define introspect_options_and_verbs(arg, flags)                        \
        streq(arg, "options") ? introspect_options(flags) :             \
                streq(arg, "verbs") ? introspect_verbs(flags) :         \
                log_error_errno(SYNTHETIC_ERRNO(EINVAL),                \
                                "Unknown introspection argument: %s", arg)
