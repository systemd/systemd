/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "memory-util.h"
#include "shared-forward.h"

typedef enum OptionFlags {
        OPTION_OPTIONAL_ARG        = 1U << 0,  /* Same as optional_argument in getopt */
        OPTION_POSITIONAL_ENTRY    = 1U << 1,  /* The "option" to handle positional arguments */
        OPTION_STOPS_PARSING       = 1U << 2,  /* This option acts like "--" */
        OPTION_GROUP_MARKER        = 1U << 3,  /* Fake option entry to separate groups */
        OPTION_HELP_ENTRY          = 1U << 4,  /* Fake option entry to insert an additional help line */
        OPTION_HELP_ENTRY_VERBATIM = 1U << 5,  /* Same, but use the long_code in the first column as written */
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
        _section_("SYSTEMD_OPTIONS")                                    \
        _alignptr_                                                      \
        _used_                                                          \
        _retain_                                                        \
        _no_reorder_                                                    \
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
#define OPTION_LONG_FLAGS(fl, lc, mv, h) OPTION_FULL(fl, /* sc= */ 0, lc, mv, h)
#define OPTION_SHORT(sc, mv, h) OPTION(sc, /* lc= */ NULL, mv, h)
#define OPTION_SHORT_FLAGS(fl, sc, mv, h) OPTION_FULL(fl, sc, /* lc= */ NULL, mv, h)
#define OPTION_POSITIONAL OPTION_FULL(OPTION_POSITIONAL_ENTRY, /* sc= */ 0, "(positional)", /* mv= */ NULL, /* h= */ NULL)
#define OPTION_HELP_VERBATIM(lc, h) OPTION_FULL(OPTION_HELP_ENTRY_VERBATIM, /* sc= */ 0, lc, /* mv= */ NULL, h)

#define OPTION_COMMON_HELP \
        OPTION('h', "help", NULL, "Show this help")
#define OPTION_COMMON_VERSION \
        OPTION_LONG("version", NULL, "Show package version")
#define OPTION_COMMON_NO_PAGER \
        OPTION_LONG("no-pager", NULL, "Do not start a pager")
#define OPTION_COMMON_NO_LEGEND \
        OPTION_LONG("no-legend", NULL, "Do not show headers and footers")
#define OPTION_COMMON_LOG_LEVEL \
        OPTION_LONG("log-level", "LEVEL", \
                    "Set log level (debug, info, notice, warning, err, crit, alert, emerg)")
#define OPTION_COMMON_LOG_TARGET \
        OPTION_LONG("log-target", "TARGET", \
                    "Set log target (console, journal, journal-or-kmsg, kmsg, null)")
#define OPTION_COMMON_LOG_COLOR \
        OPTION_LONG("log-color", "BOOL", "Highlight important messages")
#define OPTION_COMMON_LOG_LOCATION \
        OPTION_LONG("log-location", "BOOL", "Include code location in messages")
#define OPTION_COMMON_LOG_TIME \
        OPTION_LONG("log-time", "BOOL", "Prefix messages with current time")
#define OPTION_COMMON_CAT_CONFIG \
        OPTION_LONG("cat-config", NULL, "Show configuration files")
#define OPTION_COMMON_TLDR \
        OPTION_LONG("tldr", NULL, "Show non-comment parts of configuration")
#define OPTION_COMMON_NO_ASK_PASSWORD \
        OPTION_LONG("no-ask-password", NULL, "Do not prompt for password")
#define OPTION_COMMON_HOST \
        OPTION('H', "host", "[USER@]HOST", "Operate on remote host")
#define OPTION_COMMON_MACHINE \
        OPTION('M', "machine", "CONTAINER", "Operate on local container")
#define OPTION_COMMON_JSON \
        OPTION_LONG("json", "FORMAT", "Generate JSON output (pretty, short, or off)")
#define OPTION_COMMON_LOWERCASE_J \
        OPTION_SHORT('j', NULL, \
                     "Equivalent to --json=pretty (on TTY) or --json=short (otherwise)")

/* This is magically mapped to the beginning and end of the section */
extern const Option __start_SYSTEMD_OPTIONS[];
extern const Option __stop_SYSTEMD_OPTIONS[];

typedef enum OptionParserMode {
        /* The default mode. This is the implicit default and doesn't have to be specified. */
        OPTION_PARSER_NORMAL = 0,

        /* Same as "+…" for getopt_long — only parse options before the first positional argument. */
        OPTION_PARSER_STOP_AT_FIRST_NONOPTION,

        /* Same as "-…" for getopt_long — return positional arguments as "options" to be handled by the
         * option handler specified with OPTION_POSITIONAL. */
        OPTION_PARSER_RETURN_POSITIONAL_ARGS,

        _OPTION_PARSER_MODE_MAX,
} OptionParserMode;

typedef struct OptionParser {
        /* Those three should stay first so that it's possible to initialize the struct as { argc, argv }
         * or { argc, argv, mode }. */
        int argc;                     /* The original argc. */
        char **argv;                  /* The argv array, possibly reordered. */
        OptionParserMode mode;

        bool parsing_stopped;         /* We processed "--" or an option that terminates option parsing. */
        int optind;                   /* Position of the parameter being handled.
                                       * 0 → option parsing hasn't been started yet. */
        int short_option_offset;      /* Set when we're parsing an argument with one or more short options.
                                       * 0 → we're not parsing short options. */
        int positional_offset;        /* Offset to where positional parameters are. After processing has been
                                       * finished, all options and their args are to the left of this offset. */
} OptionParser;

int option_parse(
                const Option options[],
                const Option options_end[],
                OptionParser *state,
                const Option **ret_option,
                const char **ret_arg);

/* Iterate over options. */
#define FOREACH_OPTION_FULL(parser, opt, ret_o, ret_a, on_error) \
        for (int opt; (opt = option_parse(ALIGN_PTR(__start_SYSTEMD_OPTIONS), __stop_SYSTEMD_OPTIONS, parser, ret_o, ret_a)) != 0; ) \
                if (opt < 0) {                                                  \
                        on_error;                                               \
                        break;                                                  \
                } else

#define FOREACH_OPTION(parser, opt, ret_a, on_error) \
        FOREACH_OPTION_FULL(parser, opt, /* ret_o= */ NULL, ret_a, on_error)

char* option_parser_next_arg(const OptionParser *state);
char* option_parser_consume_next_arg(OptionParser *state);

char** option_parser_get_args(const OptionParser *state);
size_t option_parser_get_n_args(const OptionParser *state);

int _option_parser_get_help_table(
                const Option options[],
                const Option options_end[],
                const char *group,
                Table **ret);
#define option_parser_get_help_table_group(group, ret)                  \
        _option_parser_get_help_table(ALIGN_PTR(__start_SYSTEMD_OPTIONS), __stop_SYSTEMD_OPTIONS, group, ret)
#define option_parser_get_help_table(ret)                               \
        option_parser_get_help_table_group(/* group= */ NULL, ret)
