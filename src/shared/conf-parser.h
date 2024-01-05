/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "hashmap.h"
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
typedef const ConfigPerfItem* (*ConfigPerfItemLookup)(const char *section_and_lvalue, GPERF_LEN_TYPE length);

/* Prototype for a generic high-level lookup function */
typedef int (*ConfigItemLookup)(
                const void *table,
                const char *section,
                const char *lvalue,
                ConfigParserCallback *ret_func,
                int *ret_ltype,
                void **ret_data,
                void *userdata);

/* Linear table search implementation of ConfigItemLookup, based on
 * ConfigTableItem arrays */
int config_item_table_lookup(const void *table, const char *section, const char *lvalue, ConfigParserCallback *ret_func, int *ret_ltype, void **ret_data, void *userdata);

/* gperf implementation of ConfigItemLookup, based on gperf
 * ConfigPerfItem tables */
int config_item_perf_lookup(const void *table, const char *section, const char *lvalue, ConfigParserCallback *ret_func, int *ret_ltype, void **ret_data, void *userdata);

int config_parse(
                const char *unit,
                const char *filename,
                FILE *f,
                const char *sections,       /* nulstr */
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata,
                struct stat *ret_stat);     /* possibly NULL */

int config_parse_config_file_full(
                const char *conf_file,
                const char *domain,
                const char *sections,       /* nulstr */
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata);

static inline int config_parse_config_file(
                const char *conf_file,
                const char *sections,       /* nulstr */
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata) {
        return config_parse_config_file_full(conf_file, "systemd", sections, lookup, table, flags, userdata);
}

int config_parse_many(
                const char* const* conf_files,  /* possibly empty */
                const char* const* conf_file_dirs,
                const char *dropin_dirname,
                const char *root,
                const char *sections,       /* nulstr */
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata,
                Hashmap **ret_stats_by_path,  /* possibly NULL */
                char ***ret_drop_in_files);   /* possibly NULL */

int config_get_stats_by_path(
                const char *suffix,
                const char *root,
                unsigned flags,
                const char* const* dirs,
                bool check_dropins,
                Hashmap **ret);

int hashmap_put_stats_by_path(Hashmap **stats_by_path, const char *path, const struct stat *st);
bool stats_by_path_equal(Hashmap *a, Hashmap *b);

typedef struct ConfigSection {
        unsigned line;
        bool invalid;
        char filename[];
} ConfigSection;

static inline ConfigSection* config_section_free(ConfigSection *cs) {
        return mfree(cs);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(ConfigSection*, config_section_free);

int config_section_new(const char *filename, unsigned line, ConfigSection **ret);
extern const struct hash_ops config_section_hash_ops;
int _hashmap_by_section_find_unused_line(
                HashmapBase *entries_by_section,
                const char *filename,
                unsigned *ret);
static inline int hashmap_by_section_find_unused_line(
                Hashmap *entries_by_section,
                const char *filename,
                unsigned *ret) {
        return _hashmap_by_section_find_unused_line(HASHMAP_BASE(entries_by_section), filename, ret);
}
static inline int ordered_hashmap_by_section_find_unused_line(
                OrderedHashmap *entries_by_section,
                const char *filename,
                unsigned *ret) {
        return _hashmap_by_section_find_unused_line(HASHMAP_BASE(entries_by_section), filename, ret);
}

static inline bool section_is_invalid(ConfigSection *section) {
        /* If this returns false, then it does _not_ mean the section is valid. */

        if (!section)
                return false;

        return section->invalid;
}

#define DEFINE_SECTION_CLEANUP_FUNCTIONS(type, free_func)               \
        static inline type* free_func##_or_set_invalid(type *p) {       \
                assert(p);                                              \
                                                                        \
                if (p->section)                                         \
                        p->section->invalid = true;                     \
                else                                                    \
                        free_func(p);                                   \
                return NULL;                                            \
        }                                                               \
        DEFINE_TRIVIAL_CLEANUP_FUNC(type*, free_func);                  \
        DEFINE_TRIVIAL_CLEANUP_FUNC(type*, free_func##_or_set_invalid);

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
CONFIG_PARSER_PROTOTYPE(config_parse_iec_uint64_infinity);
CONFIG_PARSER_PROTOTYPE(config_parse_bool);
CONFIG_PARSER_PROTOTYPE(config_parse_id128);
CONFIG_PARSER_PROTOTYPE(config_parse_tristate);
CONFIG_PARSER_PROTOTYPE(config_parse_string);
CONFIG_PARSER_PROTOTYPE(config_parse_dns_name);
CONFIG_PARSER_PROTOTYPE(config_parse_hostname);
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
CONFIG_PARSER_PROTOTYPE(config_parse_hw_addr);
CONFIG_PARSER_PROTOTYPE(config_parse_hw_addrs);
CONFIG_PARSER_PROTOTYPE(config_parse_ether_addr);
CONFIG_PARSER_PROTOTYPE(config_parse_ether_addrs);
CONFIG_PARSER_PROTOTYPE(config_parse_in_addr_non_null);
CONFIG_PARSER_PROTOTYPE(config_parse_percent);
CONFIG_PARSER_PROTOTYPE(config_parse_permyriad);
CONFIG_PARSER_PROTOTYPE(config_parse_pid);
CONFIG_PARSER_PROTOTYPE(config_parse_sec_fix_0);

typedef enum Disabled {
        DISABLED_CONFIGURATION,
        DISABLED_LEGACY,
        DISABLED_EXPERIMENTAL,
} Disabled;

typedef enum ConfigParseStringFlags {
        CONFIG_PARSE_STRING_SAFE  = 1 << 0,
        CONFIG_PARSE_STRING_ASCII = 1 << 1,

        CONFIG_PARSE_STRING_SAFE_AND_ASCII = CONFIG_PARSE_STRING_SAFE | CONFIG_PARSE_STRING_ASCII,
} ConfigParseStringFlags;

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
                type *i = ASSERT_PTR(data);                             \
                int r;                                                  \
                                                                        \
                assert(filename);                                       \
                assert(lvalue);                                         \
                assert(rvalue);                                         \
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
                type **enums = ASSERT_PTR(data);                               \
                _cleanup_free_ type *xs = NULL;                                \
                size_t i = 0;                                                  \
                int r;                                                         \
                                                                               \
                assert(filename);                                              \
                assert(lvalue);                                                \
                assert(rvalue);                                                \
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

int config_parse_unsigned_bounded(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *name,
                const char *value,
                unsigned min,
                unsigned max,
                bool ignoring,
                unsigned *ret);

static inline int config_parse_uint32_bounded(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *name,
                const char *value,
                uint32_t min,
                uint32_t max,
                bool ignoring,
                uint32_t *ret) {

        unsigned t;
        int r;

        r = config_parse_unsigned_bounded(
                        unit, filename, line, section, section_line, name, value,
                        min, max, ignoring,
                        &t);
        if (r <= 0)
                return r;
        assert(t <= UINT32_MAX);
        *ret = t;
        return 1;
}

static inline int config_parse_uint16_bounded(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *name,
                const char *value,
                uint16_t min,
                uint16_t max,
                bool ignoring,
                uint16_t *ret) {

        unsigned t;
        int r;

        r = config_parse_unsigned_bounded(
                        unit, filename, line, section, section_line, name, value,
                        min, max, ignoring,
                        &t);
        if (r <= 0)
                return r;
        assert(t <= UINT16_MAX);
        *ret = t;
        return 1;
}

static inline int config_parse_uint8_bounded(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *name,
                const char *value,
                uint8_t min,
                uint8_t max,
                bool ignoring,
                uint8_t *ret) {

        unsigned t;
        int r;

        r = config_parse_unsigned_bounded(
                        unit, filename, line, section, section_line, name, value,
                        min, max, ignoring,
                        &t);
        if (r <= 0)
                return r;
        assert(t <= UINT8_MAX);
        *ret = t;
        return 1;
}
