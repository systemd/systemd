/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <stdio.h>
#include <stdbool.h>

#include "macro.h"

/* An abstract parser for simple, line based, shallow configuration
 * files consisting of variable assignments only. */

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

int config_parse(const char *unit,
                 const char *filename,
                 FILE *f,
                 const char *sections,  /* nulstr */
                 ConfigItemLookup lookup,
                 const void *table,
                 bool relaxed,
                 bool allow_include,
                 bool warn,
                 void *userdata);

int config_parse_many(const char *conf_file,      /* possibly NULL */
                      const char *conf_file_dirs, /* nulstr */
                      const char *sections,       /* nulstr */
                      ConfigItemLookup lookup,
                      const void *table,
                      bool relaxed,
                      void *userdata);

/* Generic parsers */
int config_parse_int(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_unsigned(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_long(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_uint64(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_double(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line,  const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_iec_size(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_si_size(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_iec_off(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_bool(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_string(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_path(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_strv(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_sec(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_nsec(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_mode(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_log_facility(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_log_level(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);

#define log_invalid_utf8(unit, level, config_file, config_line, error, rvalue) \
        do {                                                            \
                _cleanup_free_ char *_p = utf8_escape_invalid(rvalue);  \
                log_syntax(unit, level, config_file, config_line, error, \
                           "String is not UTF-8 clean, ignoring assignment: %s", strna(_p)); \
        } while(false)

#define DEFINE_CONFIG_PARSE_ENUM(function,name,type,msg)                \
        int function(const char *unit,                                  \
                     const char *filename,                              \
                     unsigned line,                                     \
                     const char *section,                               \
                     unsigned section_line,                             \
                     const char *lvalue,                                \
                     int ltype,                                         \
                     const char *rvalue,                                \
                     void *data,                                        \
                     void *userdata) {                                  \
                                                                        \
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
        int function(const char *unit,                                         \
                     const char *filename,                                     \
                     unsigned line,                                            \
                     const char *section,                                      \
                     unsigned section_line,                                    \
                     const char *lvalue,                                       \
                     int ltype,                                                \
                     const char *rvalue,                                       \
                     void *data,                                               \
                     void *userdata) {                                         \
                                                                               \
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
                if(!xs)                                                        \
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
