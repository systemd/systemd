/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <syslog.h>

#include "alloc-util.h"
#include "log.h"
#include "macro.h"

/* An abstract parser for simple, line based, shallow configuration files consisting of variable assignments only. */

typedef enum ConfigParseFlags {
        CONFIG_PARSE_RELAXED       = 1U << 0,
        CONFIG_PARSE_ALLOW_INCLUDE = 1U << 1,
        CONFIG_PARSE_WARN          = 1U << 2,
        CONFIG_PARSE_REFUSE_BOM    = 1U << 3,
} ConfigParseFlags;

/* Prototype for a parser for a specific configuration setting */
typedef int (*ConfigParserCallback)(const char *unit,
                                    const char *filename,
                                    unsigned line,
                                    const char *section,
                                    unsigned section_line,
                                    const char *lvalue,
                                    int ltype,
                                    const char *rvalue,
                                    void *data,
                                    void *userdata);

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
                const char *sections,  /* nulstr */
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata);

int config_parse_many_nulstr(
                const char *conf_file,      /* possibly NULL */
                const char *conf_file_dirs, /* nulstr */
                const char *sections,       /* nulstr */
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata);

int config_parse_many(
                const char *conf_file,      /* possibly NULL */
                const char* const* conf_file_dirs,
                const char *dropin_dirname,
                const char *sections,       /* nulstr */
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata);

/* Generic parsers */
#define GENERIC_PARSER_ARGS \
                const char *unit,                                       \
                const char *filename,                                   \
                unsigned line,                                          \
                const char *section,                                    \
                unsigned section_line,                                  \
                const char *lvalue,                                     \
                int ltype,                                              \
                const char *rvalue,                                     \
                void *data,                                             \
                void *userdata
int config_parse_int(GENERIC_PARSER_ARGS);
int config_parse_unsigned(GENERIC_PARSER_ARGS);
int config_parse_long(GENERIC_PARSER_ARGS);
int config_parse_uint8(GENERIC_PARSER_ARGS);
int config_parse_uint16(GENERIC_PARSER_ARGS);
int config_parse_uint32(GENERIC_PARSER_ARGS);
int config_parse_uint64(GENERIC_PARSER_ARGS);
int config_parse_double(GENERIC_PARSER_ARGS);
int config_parse_iec_size(GENERIC_PARSER_ARGS);
int config_parse_si_size(GENERIC_PARSER_ARGS);
int config_parse_iec_uint64(GENERIC_PARSER_ARGS);
int config_parse_bool(GENERIC_PARSER_ARGS);
int config_parse_tristate(GENERIC_PARSER_ARGS);
int config_parse_string(GENERIC_PARSER_ARGS);
int config_parse_path(GENERIC_PARSER_ARGS);
int config_parse_strv(GENERIC_PARSER_ARGS);
int config_parse_sec(GENERIC_PARSER_ARGS);
int config_parse_nsec(GENERIC_PARSER_ARGS);
int config_parse_mode(GENERIC_PARSER_ARGS);
int config_parse_warn_compat(GENERIC_PARSER_ARGS);
int config_parse_log_facility(GENERIC_PARSER_ARGS);
int config_parse_log_level(GENERIC_PARSER_ARGS);
int config_parse_signal(GENERIC_PARSER_ARGS);
int config_parse_personality(GENERIC_PARSER_ARGS);
int config_parse_ifname(GENERIC_PARSER_ARGS);
int config_parse_ip_port(GENERIC_PARSER_ARGS);
int config_parse_join_controllers(GENERIC_PARSER_ARGS);

typedef enum Disabled {
        DISABLED_CONFIGURATION,
        DISABLED_LEGACY,
        DISABLED_EXPERIMENTAL,
} Disabled;

#define DEFINE_CONFIG_PARSE_ENUM(function,name,type,msg)                \
        int function(GENERIC_PARSER_ARGS) {                             \
                type *i = data, x;                                      \
                                                                        \
                assert(filename);                                       \
                assert(lvalue);                                         \
                assert(rvalue);                                         \
                assert(data);                                           \
                                                                        \
                if ((x = name##_from_string(rvalue)) < 0) {             \
                        log_syntax(unit, LOG_ERR, filename, line, -x,   \
                                   msg ", ignoring: %s", rvalue);       \
                        return 0;                                       \
                }                                                       \
                                                                        \
                *i = x;                                                 \
                return 0;                                               \
        }

#define DEFINE_CONFIG_PARSE_ENUMV(function,name,type,invalid,msg)              \
        int function(GENERIC_PARSER_ARGS) {                                    \
                type **enums = data, x, *ys;                                   \
                _cleanup_free_ type *xs = NULL;                                \
                const char *word, *state;                                      \
                size_t l, i = 0;                                               \
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
                FOREACH_WORD(word, l, rvalue, state) {                         \
                        _cleanup_free_ char *en = NULL;                        \
                        type *new_xs;                                          \
                                                                               \
                        en = strndup(word, l);                                 \
                        if (!en)                                               \
                                return -ENOMEM;                                \
                                                                               \
                        if ((x = name##_from_string(en)) < 0) {                \
                                log_syntax(unit, LOG_ERR, filename, line,      \
                                       -x, msg ", ignoring: %s", en);          \
                                continue;                                      \
                        }                                                      \
                                                                               \
                        for (ys = xs; x != invalid && *ys != invalid; ys++) {  \
                                if (*ys == x) {                                \
                                        log_syntax(unit, LOG_ERR, filename,    \
                                              line, -x,                        \
                                              "Duplicate entry, ignoring: %s", \
                                              en);                             \
                                        x = invalid;                           \
                                }                                              \
                        }                                                      \
                                                                               \
                        if (x == invalid)                                      \
                                continue;                                      \
                                                                               \
                        *(xs + i) = x;                                         \
                        new_xs = realloc(xs, (++i + 1) * sizeof(type));        \
                        if (new_xs)                                            \
                                xs = new_xs;                                   \
                        else                                                   \
                                return -ENOMEM;                                \
                                                                               \
                        *(xs + i) = invalid;                                   \
                }                                                              \
                                                                               \
                free(*enums);                                                  \
                *enums = xs;                                                   \
                xs = NULL;                                                     \
                                                                               \
                return 0;                                                      \
        }
