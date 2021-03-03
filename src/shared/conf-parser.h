/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <syslog.h>

#include "alloc-util.h"
#include "log.h"
#include "macro.h"
#include "time-util.h"

/* An abstract parser for simple, line based, shallow configuration files consisting of variable assignments only. */

typedef enum ConfigParseFlags {
        CONFIG_PARSE_RELAXED       = 1 << 0, /* Do not warn about unknown non-extension fields */
        CONFIG_PARSE_WARN          = 1 << 1, /* Emit non-debug messages */
} ConfigParseFlags;

/* Argument list for parsers of specific configuration settings. */
#define CONFIG_PARSER_ARGUMENTS                 \
        const char *unit,                       \
        const char *filename,                   \
        unsigned line,                          \
        const char *section,                    \
        unsigned section_line,                  \
        const char *lvalue,                     \
        int ltype,                              \
        const char *rvalue,                     \
        void *data,                             \
        void *userdata

/* Prototype for a parser for a specific configuration setting */
typedef int (*ConfigParserCallback)(CONFIG_PARSER_ARGUMENTS);

/* A macro declaring a function prototype, following the typedef above, simply because it's so cumbersomely long
 * otherwise. (And current emacs gets irritatingly slow when editing files that contain lots of very long function
 * prototypes on the same screen…) */
#define CONFIG_PARSER_PROTOTYPE(name) int name(CONFIG_PARSER_ARGUMENTS)

/* Wraps information for parsing a specific configuration variable, to
 * be stored in a simple array */
typedef struct ConfigTableItem {
        const char *section;            /* Section */
        const char *lvalue;             /* Name of the variable */
        ConfigParserCallback parse;     /* Function that is called to parse the variable's value */
        int ltype;                      /* Distinguish different variables passed to the same callback */
        void *data;                     /* Where to store the variable's data */
} ConfigTableItem;

/* Wraps information for parsing a specific configuration variable, to
 * be stored in a gperf perfect hashtable */
typedef struct ConfigPerfItem {
        const char *section_and_lvalue; /* Section + "." + name of the variable */
        ConfigParserCallback parse;     /* Function that is called to parse the variable's value */
        int ltype;                      /* Distinguish different variables passed to the same callback */
        size_t offset;                  /* Offset where to store data, from the beginning of userdata */
} ConfigPerfItem;

/* Prototype for a low-level gperf lookup function */
typedef const ConfigPerfItem* (*ConfigPerfItemLookup)(const char *section_and_lvalue, unsigned length);

/* Prototype for a generic high-level lookup function */
typedef int (*ConfigItemLookup)(
                const void *table,
                const char *section,
                const char *lvalue,
                ConfigParserCallback *func,
                int *ltype,
                void **data,
                void *userdata);

/* Linear table search implementation of ConfigItemLookup, based on
 * ConfigTableItem arrays */
int config_item_table_lookup(const void *table, const char *section, const char *lvalue, ConfigParserCallback *func, int *ltype, void **data, void *userdata);

/* gperf implementation of ConfigItemLookup, based on gperf
 * ConfigPerfItem tables */
int config_item_perf_lookup(const void *table, const char *section, const char *lvalue, ConfigParserCallback *func, int *ltype, void **data, void *userdata);

int config_parse(
                const char *unit,
                const char *filename,
                FILE *f,
                const char *sections,       /* nulstr */
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata,
                usec_t *latest_mtime);      /* input/output, possibly NULL */

int config_parse_many_nulstr(
                const char *conf_file,      /* possibly NULL */
                const char *conf_file_dirs, /* nulstr */
                const char *sections,       /* nulstr */
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata,
                usec_t *ret_mtime);         /* possibly NULL */

int config_parse_many(
                const char* const* conf_files,  /* possibly empty */
                const char* const* conf_file_dirs,
                const char *dropin_dirname,
                const char *sections,       /* nulstr */
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata,
                usec_t *ret_mtime);         /* possibly NULL */

CONFIG_PARSER_PROTOTYPE(config_parse_int);
CONFIG_PARSER_PROTOTYPE(config_parse_unsigned);
CONFIG_PARSER_PROTOTYPE(config_parse_long);
CONFIG_PARSER_PROTOTYPE(config_parse_uint8);
CONFIG_PARSER_PROTOTYPE(config_parse_uint16);
CONFIG_PARSER_PROTOTYPE(config_parse_uint32);
CONFIG_PARSER_PROTOTYPE(config_parse_int32);
CONFIG_PARSER_PROTOTYPE(config_parse_uint64);
CONFIG_PARSER_PROTOTYPE(config_parse_double);
CONFIG_PARSER_PROTOTYPE(config_parse_iec_size);
CONFIG_PARSER_PROTOTYPE(config_parse_si_uint64);
CONFIG_PARSER_PROTOTYPE(config_parse_iec_uint64);
CONFIG_PARSER_PROTOTYPE(config_parse_bool);
CONFIG_PARSER_PROTOTYPE(config_parse_id128);
CONFIG_PARSER_PROTOTYPE(config_parse_tristate);
CONFIG_PARSER_PROTOTYPE(config_parse_string);
CONFIG_PARSER_PROTOTYPE(config_parse_path);
CONFIG_PARSER_PROTOTYPE(config_parse_strv);
CONFIG_PARSER_PROTOTYPE(config_parse_sec);
CONFIG_PARSER_PROTOTYPE(config_parse_sec_def_infinity);
CONFIG_PARSER_PROTOTYPE(config_parse_sec_def_unset);
CONFIG_PARSER_PROTOTYPE(config_parse_nsec);
CONFIG_PARSER_PROTOTYPE(config_parse_mode);
CONFIG_PARSER_PROTOTYPE(config_parse_warn_compat);
CONFIG_PARSER_PROTOTYPE(config_parse_log_facility);
CONFIG_PARSER_PROTOTYPE(config_parse_log_level);
CONFIG_PARSER_PROTOTYPE(config_parse_signal);
CONFIG_PARSER_PROTOTYPE(config_parse_personality);
CONFIG_PARSER_PROTOTYPE(config_parse_permille);
CONFIG_PARSER_PROTOTYPE(config_parse_ifname);
CONFIG_PARSER_PROTOTYPE(config_parse_ifnames);
CONFIG_PARSER_PROTOTYPE(config_parse_ip_port);
CONFIG_PARSER_PROTOTYPE(config_parse_mtu);
CONFIG_PARSER_PROTOTYPE(config_parse_rlimit);
CONFIG_PARSER_PROTOTYPE(config_parse_vlanprotocol);
CONFIG_PARSER_PROTOTYPE(config_parse_hwaddr);
CONFIG_PARSER_PROTOTYPE(config_parse_hwaddrs);
CONFIG_PARSER_PROTOTYPE(config_parse_percent);
CONFIG_PARSER_PROTOTYPE(config_parse_permyriad);

typedef enum Disabled {
        DISABLED_CONFIGURATION,
        DISABLED_LEGACY,
        DISABLED_EXPERIMENTAL,
} Disabled;

#define DEFINE_CONFIG_PARSE(function, parser, msg)                      \
        CONFIG_PARSER_PROTOTYPE(function) {                             \
                int *i = data, r;                                       \
                                                                        \
                assert(filename);                                       \
                assert(lvalue);                                         \
                assert(rvalue);                                         \
                assert(data);                                           \
                                                                        \
                r = parser(rvalue);                                     \
                if (r < 0) {                                            \
                        log_syntax(unit, LOG_WARNING, filename, line, r, \
                                   msg ", ignoring: %s", rvalue);       \
                        return 0;                                       \
                }                                                       \
                                                                        \
                *i = r;                                                 \
                return 0;                                               \
        }

#define DEFINE_CONFIG_PARSE_PTR(function, parser, type, msg)            \
        CONFIG_PARSER_PROTOTYPE(function) {                             \
                type *i = data;                                         \
                int r;                                                  \
                                                                        \
                assert(filename);                                       \
                assert(lvalue);                                         \
                assert(rvalue);                                         \
                assert(data);                                           \
                                                                        \
                r = parser(rvalue, i);                                  \
                if (r < 0)                                              \
                        log_syntax(unit, LOG_WARNING, filename, line, r, \
                                   msg ", ignoring: %s", rvalue);       \
                                                                        \
                return 0;                                               \
        }

#define DEFINE_CONFIG_PARSE_ENUM_FULL(function, from_string, type, msg) \
        CONFIG_PARSER_PROTOTYPE(function) {                             \
                type *i = data, x;                                      \
                                                                        \
                assert(filename);                                       \
                assert(lvalue);                                         \
                assert(rvalue);                                         \
                assert(data);                                           \
                                                                        \
                x = from_string(rvalue);                                \
                if (x < 0) {                                            \
                        log_syntax(unit, LOG_WARNING, filename, line, x, \
                                   msg ", ignoring: %s", rvalue);       \
                        return 0;                                       \
                }                                                       \
                                                                        \
                *i = x;                                                 \
                return 0;                                               \
        }

#define DEFINE_CONFIG_PARSE_ENUM(function, name, type, msg)             \
        DEFINE_CONFIG_PARSE_ENUM_FULL(function, name##_from_string, type, msg)

#define DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(function, name, type, default_value, msg) \
        CONFIG_PARSER_PROTOTYPE(function) {                             \
                type *i = data, x;                                      \
                                                                        \
                assert(filename);                                       \
                assert(lvalue);                                         \
                assert(rvalue);                                         \
                assert(data);                                           \
                                                                        \
                if (isempty(rvalue)) {                                  \
                        *i = default_value;                             \
                        return 0;                                       \
                }                                                       \
                                                                        \
                x = name##_from_string(rvalue);                         \
                if (x < 0) {                                            \
                        log_syntax(unit, LOG_WARNING, filename, line, x, \
                                   msg ", ignoring: %s", rvalue);       \
                        return 0;                                       \
                }                                                       \
                                                                        \
                *i = x;                                                 \
                return 0;                                               \
        }

#define DEFINE_CONFIG_PARSE_ENUMV(function, name, type, invalid, msg)          \
        CONFIG_PARSER_PROTOTYPE(function) {                                    \
                type **enums = data;                                           \
                _cleanup_free_ type *xs = NULL;                                \
                size_t i = 0;                                                  \
                int r;                                                         \
                                                                               \
                assert(filename);                                              \
                assert(lvalue);                                                \
                assert(rvalue);                                                \
                assert(data);                                                  \
                                                                               \
                xs = new0(type, 1);                                            \
                if (!xs)                                                       \
                        return -ENOMEM;                                        \
                                                                               \
                *xs = invalid;                                                 \
                                                                               \
                for (const char *p = rvalue;;) {                               \
                        _cleanup_free_ char *en = NULL;                        \
                        type x, *new_xs;                                       \
                                                                               \
                        r = extract_first_word(&p, &en, NULL, 0);              \
                        if (r == -ENOMEM)                                      \
                                return log_oom();                              \
                        if (r < 0) {                                           \
                                log_syntax(unit, LOG_WARNING, filename, line, r, \
                                           msg ", ignoring: %s", en);          \
                                return 0;                                      \
                        }                                                      \
                        if (r == 0)                                            \
                                break;                                         \
                                                                               \
                        x = name##_from_string(en);                            \
                        if (x < 0) {                                           \
                                log_syntax(unit, LOG_WARNING, filename, line, x, \
                                           msg ", ignoring: %s", en);          \
                                continue;                                      \
                        }                                                      \
                                                                               \
                        for (type *ys = xs; x != invalid && *ys != invalid; ys++)       \
                                if (*ys == x) {                                         \
                                        log_syntax(unit, LOG_NOTICE, filename, line, 0, \
                                                   "Duplicate entry, ignoring: %s",     \
                                                   en);                        \
                                        x = invalid;                           \
                                }                                              \
                                                                               \
                        if (x == invalid)                                      \
                                continue;                                      \
                                                                               \
                        *(xs + i) = x;                                         \
                        new_xs = realloc(xs, (++i + 1) * sizeof(type));        \
                        if (new_xs)                                            \
                                xs = new_xs;                                   \
                        else                                                   \
                                return log_oom();                              \
                                                                               \
                        *(xs + i) = invalid;                                   \
                }                                                              \
                                                                               \
                return free_and_replace(*enums, xs);                           \
        }
