/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

/* Option namespace/group explanation:
 * the list of options is split into namespaces, and a namespace is split into groups.
 * By default, options defined in a single program are all placed in a single (unnamed) namespace
 * and in a single (unnamed) group. OPTION_NAMESPACE() marks the beginning of a named namespace.
 * OPTION_GROUP() marks the beginning of a named group.
 *
 * Note: if multiple namespaces are used, they should all be named, i.e. each separate parse_argv
 * instance should have OPTION_NAMESPACE first, and then its set of OPTION()s. (This is because
 * clang reorders OPTIONs coming from different functions. So an unnamed group could end up being
 * merged with one of the earlier groups. It seems that reordering within a single function does
 * not happen.)
 *
 * When groups are used, the first group may be named (with OPTION_GROUP appearing before any
 * options), or it may be unnamed. Both variants should work fine.
 */

typedef enum OptionFlags {
        OPTION_OPTIONAL_ARG        = 1U << 0,  /* Same as optional_argument in getopt */
        OPTION_POSITIONAL_ENTRY    = 1U << 1,  /* The "option" to handle positional arguments */
        OPTION_STOPS_PARSING       = 1U << 2,  /* This option acts like "--" */
        OPTION_NAMESPACE_MARKER    = 1U << 3,  /* Fake option entry to separate namespaces */
        OPTION_GROUP_MARKER        = 1U << 4,  /* Fake option entry to separate groups */
        OPTION_HELP_ENTRY          = 1U << 5,  /* Fake option entry to insert an additional help line */
        OPTION_HELP_ENTRY_VERBATIM = 1U << 6,  /* Same, but use the long_code in the first column as written */
} OptionFlags;

typedef struct Option {
        int id;
        OptionFlags flags;
        char short_code;
        const char *long_code;
        const char *metavar;
        uintptr_t data;
        const char *help;
} Option;

#define _OPTION(counter, fl, sc, lc, mv, d, h)                          \
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
                .data = d,                                              \
                .help = h,                                              \
        };                                                              \
        case (0x100 + counter)

/* Magic entry in the table (which will not be returned) that designates the start of the namespace <ns>.
 * The define is structured as 'case' so that it can be followed by ':' and indented appropriately. */
#define OPTION_NAMESPACE(ns)                                            \
        _OPTION(__COUNTER__, OPTION_NAMESPACE_MARKER, /* sc= */ 0, /* lc= */ ns, /* mv= */ NULL, /* d= */ 0u, /* h= */ NULL)

/* Magic entry in the table (which will not be returned) that designates the start of the group <gr>.
 * The define is structured as 'case' so that it can be followed by ':' and indented appropriately. */
#define OPTION_GROUP(gr)                                                \
        _OPTION(__COUNTER__, OPTION_GROUP_MARKER, /* sc= */ 0, /* lc= */ gr, /* mv= */ NULL, /* d= */ 0u, /* h= */ NULL)

#define OPTION_FULL_DATA(fl, sc, lc, mv, d, h) _OPTION(__COUNTER__, fl, sc, lc, mv, d, h)
#define OPTION_FULL(fl, sc, lc, mv, h) OPTION_FULL_DATA(fl, sc, lc, mv, /* d= */ 0u, h)
#define OPTION(sc, lc, mv, h) OPTION_FULL(/* fl= */ 0, sc, lc, mv, h)
#define OPTION_LONG(lc, mv, h) OPTION(/* sc= */ 0, lc, mv, h)
#define OPTION_LONG_FLAGS(fl, lc, mv, h) OPTION_FULL(fl, /* sc= */ 0, lc, mv, h)
#define OPTION_LONG_DATA(lc, mv, d, h) OPTION_FULL_DATA(/* fl= */ 0, /* sc= */ 0, lc, mv, d, h)
#define OPTION_SHORT(sc, mv, h) OPTION(sc, /* lc= */ NULL, mv, h)
#define OPTION_SHORT_FLAGS(fl, sc, mv, h) OPTION_FULL(fl, sc, /* lc= */ NULL, mv, h)
#define OPTION_SHORT_DATA(sc, mv, d, h) OPTION_FULL_DATA(/* fl= */ 0, sc, /* lc= */ NULL, mv, d, h)
#define OPTION_POSITIONAL OPTION_FULL(OPTION_POSITIONAL_ENTRY, /* sc= */ 0, "(positional)", /* mv= */ NULL, /* h= */ NULL)
#define OPTION_HELP_VERBATIM(lc, h) OPTION_FULL(OPTION_HELP_ENTRY_VERBATIM, /* sc= */ 0, lc, /* mv= */ NULL, h)

/* This can be used when custom error handling is needed. */
#define OPTION_ERROR                                                    \
        case INT_MIN ... -1

#define OPTION_COMMON_HELP                                              \
        OPTION('h', "help", NULL, "Show this help")

#define OPTION_COMMON_VERSION                                           \
        OPTION_LONG("version", NULL, "Show package version")

#define OPTION_COMMON_NO_PAGER                                          \
        OPTION_LONG("no-pager", NULL, "Do not start a pager")

#define OPTION_COMMON_NO_LEGEND                                         \
        OPTION_LONG("no-legend", NULL, "Do not show headers and footers")

#define OPTION_COMMON_LOG_LEVEL                                         \
        OPTION_LONG("log-level", "LEVEL",                               \
                    "Set log level (debug, info, notice, warning, err, crit, alert, emerg)")

#define OPTION_COMMON_LOG_TARGET                                        \
        OPTION_LONG("log-target", "TARGET",                             \
                    "Set log target (console, journal, journal-or-kmsg, kmsg, null)")

#define OPTION_COMMON_LOG_COLOR                                         \
        OPTION_LONG("log-color", "BOOL", "Highlight important messages")

#define OPTION_COMMON_LOG_LOCATION                                      \
        OPTION_LONG("log-location", "BOOL", "Include code location in messages")

#define OPTION_COMMON_LOG_TIME                                          \
        OPTION_LONG("log-time", "BOOL", "Prefix messages with current time")

#define OPTION_COMMON_CAT_CONFIG                                        \
        OPTION_LONG("cat-config", NULL, "Show configuration files")

#define OPTION_COMMON_TLDR                                              \
        OPTION_LONG("tldr", NULL, "Show non-comment parts of configuration")

#define OPTION_COMMON_NO_ASK_PASSWORD                                   \
        OPTION_LONG("no-ask-password", NULL, "Do not prompt for password")

#define OPTION_COMMON_HOST                                              \
        OPTION('H', "host", "[USER@]HOST", "Operate on remote host")

#define OPTION_COMMON_MACHINE                                           \
        OPTION('M', "machine", "CONTAINER", "Operate on local container")

#define OPTION_COMMON_SYSTEM                                            \
        OPTION_LONG("system", NULL, "Operate in system mode")

#define OPTION_COMMON_USER                                              \
        OPTION_LONG("user", NULL, "Operate in per-user mode")

#define OPTION_COMMON_JSON                                              \
        OPTION_LONG("json", "FORMAT", "Generate JSON output (pretty, short, or off)")

#define OPTION_COMMON_LOWERCASE_J                                       \
        OPTION_SHORT('j', NULL,                                         \
                     "Equivalent to --json=pretty (on TTY) or --json=short (otherwise)")

#define OPTION_COMMON_ENTRY_TOKEN                                       \
        OPTION_LONG("entry-token", "TOKEN",                             \
                    "Entry token to use for this installation "         \
                    "(machine-id, os-id, os-image-id, auto, literal:…)")

#define OPTION_COMMON_MAKE_ENTRY_DIRECTORY                              \
        OPTION_LONG("make-entry-directory",                             \
                    "BOOL|auto", "Create $BOOT/ENTRY-TOKEN/ directory")

#define OPTION_COMMON_PRIVATE_KEY(purpose)                              \
        OPTION_LONG("private-key", "PATH|URI", purpose)

#define OPTION_COMMON_PRIVATE_KEY_SOURCE                                \
        OPTION_LONG("private-key-source", "SOURCE",                     \
                    "Specify how to use the private key "               \
                    "(file, provider:PROVIDER, engine:ENGINE)")

#define OPTION_COMMON_CERTIFICATE(purpose)                              \
        OPTION_LONG("certificate", "PATH|URI", purpose                  \
                    ", or a provider-specific designation if --certificate-source= is used")

#define OPTION_COMMON_CERTIFICATE_SOURCE                                \
        OPTION_LONG("certificate-source", "SOURCE",                     \
                    "Specify how to interpret the certificate from --certificate=. " \
                    "Allows the certificate to be loaded from an OpenSSL provider " \
                    "(file, provider:PROVIDER)")

/* A form used in udev code for compatibility. -V is accepted but not documented. */
#define OPTION_COMMON_VERSION_WITH_HIDDEN_V                             \
        OPTION_COMMON_VERSION: {}                                       \
        OPTION_SHORT('V', NULL, /* help= */ NULL)

#define OPTION_COMMON_RESOLVE_NAMES                                     \
        OPTION('N', "resolve-names", "MODE",                            \
               "When to resolve users and groups (early, late, or never)")

/* This is magically mapped to the beginning and end of the section */
extern const Option __start_SYSTEMD_OPTIONS[];
extern const Option __stop_SYSTEMD_OPTIONS[];

typedef enum OptionParserMode {
        /* The default mode. This is the implicit default and doesn't have to be specified. */
        OPTION_PARSER_NORMAL,

        /* Same as "+…" for getopt_long — only parse options before the first positional argument. */
        OPTION_PARSER_STOP_AT_FIRST_NONOPTION,

        /* Same as "-…" for getopt_long — return positional arguments as "options" to be handled by the
         * option handler specified with OPTION_POSITIONAL. */
        OPTION_PARSER_RETURN_POSITIONAL_ARGS,

        _OPTION_PARSER_MODE_MAX,
} OptionParserMode;

typedef enum OptionParserState {
        OPTION_PARSER_INIT,
        OPTION_PARSER_RUNNING,
        OPTION_PARSER_STOPPING, /* We processed an option with OPTION_STOPS_PARSING, and will eat up one
                                 * more "--", but nothing else. */
        OPTION_PARSER_DONE,     /* Option parsing completed (could be because we reached the end, or because
                                 * "--" was fully processed, or because we hit a terminating option). */
        OPTION_PARSER_FAILED,   /* We encountered a parse error, and terminated option parsing. */
        _OPTION_PARSER_MAX,
} OptionParserState;

typedef struct OptionParser {
        /* Those four should stay first so that it's possible to initialize the struct as { argc, argv }
         * or { argc, argv, mode } or { argc, argv, mode, namespace }. */
        int argc;                     /* The original argc. */
        char **argv;                  /* The argv array, possibly reordered. */
        OptionParserMode mode;
        const char *namespace;        /* The namespace, may be NULL. */
        int log_level_shift;          /* The log level difference from the default of LOG_ERR.
                                       * Allowed values are -3..4.
                                       * Use 4 == LOG_DEBUG - LOG_ERR to log at debug level. */

        const Option *namespace_start, *namespace_end; /* The range of options that are part of our namespace. */

        OptionParserState state;
        int optind;                   /* Position of the parameter being handled.
                                       * 0 → option parsing hasn't been started yet. */
        int short_option_offset;      /* Set when we're parsing an argument with one or more short options.
                                       * 0 → we're not parsing short options. */
        int positional_offset;        /* Offset to where positional parameters are. After processing has been
                                       * finished, all options and their args are to the left of this offset. */

        /* The two variables below encompass the state of the last option_parse() call.
         * Before parsing has commenced, and after it has finished, they will be NULL. */
        const Option *opt;            /* … the matched option or NULL */
        const char *arg;              /* … the argument or NULL */
} OptionParser;

int option_parse(
                const Option options[],
                const Option options_end[],
                OptionParser *state);

/* Iterate over options. Don't forget to handle errors (negative c)! */
#define FOREACH_OPTION(c, state)                                        \
        for (int c; (c = option_parse(__start_SYSTEMD_OPTIONS, __stop_SYSTEMD_OPTIONS, state)) != 0; )

#define FOREACH_OPTION_OR_RETURN(c, state)                              \
        for (int c; (c = option_parse(__start_SYSTEMD_OPTIONS, __stop_SYSTEMD_OPTIONS, state)) != 0; ) \
                if (c < 0)                                              \
                        return c;                                       \
                else

/* Those helpers are used *during* option parsing and allow looking at or taking the next item in
 * the argv array, either an option or a positional parameter. */
char* option_parser_peek_next_arg(const OptionParser *state);
char* option_parser_consume_next_arg(OptionParser *state);

/* Those helpers are used *after* option parsing and return the positional arguments (and unparsed
 * options in case option parsing was stopped early, e.g. via "--"). */
char** option_parser_get_args(const OptionParser *state);
size_t option_parser_get_n_args(const OptionParser *state);
char* option_parser_get_arg(const OptionParser *state, size_t i);

char* option_get_synopsis(const Option *opt, const char *joiner, bool show_metavar);

int _option_parser_get_help_table_full(
                const Option options[],
                const Option options_end[],
                const char *namespace,
                const char *group,
                Table **ret);
#define option_parser_get_help_table_full(namespace, group, ret)        \
        _option_parser_get_help_table_full(__start_SYSTEMD_OPTIONS, __stop_SYSTEMD_OPTIONS, namespace, group, ret)
#define option_parser_get_help_table_ns(ns, ret)                        \
        option_parser_get_help_table_full(ns, /* group= */ NULL, ret)
#define option_parser_get_help_table_group(group, ret)                  \
        option_parser_get_help_table_full(/* namespace= */ NULL, group, ret)
#define option_parser_get_help_table(ret)                               \
        option_parser_get_help_table_group(/* group= */ NULL, ret)
