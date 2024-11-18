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

int config_parse_many(
                const char* const* conf_files,  /* possibly empty */
                const char* const* conf_file_dirs,
                const char *dropin_dirname,
                const char *root,
                const char *sections,         /* nulstr */
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata,
                Hashmap **ret_stats_by_path,  /* possibly NULL */
                char ***ret_drop_in_files);   /* possibly NULL */

int config_parse_standard_file_with_dropins_full(
                const char *root,
                const char *main_file,        /* A path like "systemd/frobnicator.conf" */
                const char *sections,
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata,
                Hashmap **ret_stats_by_path,  /* possibly NULL */
                char ***ret_dropin_files);    /* possibly NULL */

static inline int config_parse_standard_file_with_dropins(
                const char *main_file,        /* A path like "systemd/frobnicator.conf" */
                const char *sections,         /* nulstr */
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata) {
        return config_parse_standard_file_with_dropins_full(
                        /* root= */ NULL,
                        main_file,
                        sections,
                        lookup,
                        table,
                        flags,
                        userdata,
                        /* ret_stats_by_path= */ NULL,
                        /* ret_dropin_files= */ NULL);
}

int config_get_stats_by_path(
                const char *suffix,
                const char *root,
                unsigned flags,
                const char* const* dirs,
                bool check_dropins,
                Hashmap **ret);

int hashmap_put_stats_by_path(Hashmap **stats_by_path, const char *path, const struct stat *st);
bool stats_by_path_equal(Hashmap *a, Hashmap *b);

typedef struct ConfigSectionParser {
        ConfigParserCallback parser;
        int ltype;
        size_t offset;
} ConfigSectionParser;

int config_section_parse(
                const ConfigSectionParser *parsers,
                size_t n_parsers,
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *userdata);

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

void config_section_hash_func(const ConfigSection *c, struct siphash *state);
int config_section_compare_func(const ConfigSection *x, const ConfigSection *y);
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

#define log_section_full_errno_zerook(section, level, error, ...)       \
        ({                                                              \
                const ConfigSection *_s = (section);                    \
                log_syntax(/* unit = */ NULL,                           \
                           level,                                       \
                           _s ? _s->filename : NULL,                    \
                           _s ? _s->line : 0,                           \
                           error,                                       \
                           __VA_ARGS__);                                \
        })

#define log_section_full_errno(section, level, error, ...)              \
        ({                                                              \
                int _error = (error);                                   \
                ASSERT_NON_ZERO(_error);                                \
                log_section_full_errno_zerook(section, level, _error, __VA_ARGS__); \
        })

#define log_section_full(section, level, fmt, ...)                      \
        ({                                                              \
                if (BUILD_MODE_DEVELOPER)                               \
                        assert(!strstr(fmt, "%m"));                     \
                (void) log_section_full_errno_zerook(section, level, 0, fmt, ##__VA_ARGS__); \
        })

#define log_section_debug(section, ...)                  log_section_full(section, LOG_DEBUG,   __VA_ARGS__)
#define log_section_info(section, ...)                   log_section_full(section, LOG_INFO,    __VA_ARGS__)
#define log_section_notice(section, ...)                 log_section_full(section, LOG_NOTICE,  __VA_ARGS__)
#define log_section_warning(section, ...)                log_section_full(section, LOG_WARNING, __VA_ARGS__)
#define log_section_error(section, ...)                  log_section_full(section, LOG_ERR,     __VA_ARGS__)

#define log_section_debug_errno(section, error, ...)     log_section_full_errno(section, LOG_DEBUG,   error, __VA_ARGS__)
#define log_section_info_errno(section, error, ...)      log_section_full_errno(section, LOG_INFO,    error, __VA_ARGS__)
#define log_section_notice_errno(section, error, ...)    log_section_full_errno(section, LOG_NOTICE,  error, __VA_ARGS__)
#define log_section_warning_errno(section, error, ...)   log_section_full_errno(section, LOG_WARNING, error, __VA_ARGS__)
#define log_section_error_errno(section, error, ...)     log_section_full_errno(section, LOG_ERR,     error, __VA_ARGS__)

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
CONFIG_PARSER_PROTOTYPE(config_parse_uint32_flag);
CONFIG_PARSER_PROTOTYPE(config_parse_uint32_invert_flag);
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
CONFIG_PARSER_PROTOTYPE(config_parse_in_addr_data);
CONFIG_PARSER_PROTOTYPE(config_parse_in_addr_prefix);
CONFIG_PARSER_PROTOTYPE(config_parse_percent);
CONFIG_PARSER_PROTOTYPE(config_parse_permyriad);
CONFIG_PARSER_PROTOTYPE(config_parse_pid);
CONFIG_PARSER_PROTOTYPE(config_parse_sec_fix_0);
CONFIG_PARSER_PROTOTYPE(config_parse_timezone);
CONFIG_PARSER_PROTOTYPE(config_parse_calendar);
CONFIG_PARSER_PROTOTYPE(config_parse_ip_protocol);
CONFIG_PARSER_PROTOTYPE(config_parse_loadavg);

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

#define DEFINE_CONFIG_PARSE(function, parser)                           \
        CONFIG_PARSER_PROTOTYPE(function) {                             \
                int *i = data, r;                                       \
                                                                        \
                assert(filename);                                       \
                assert(lvalue);                                         \
                assert(rvalue);                                         \
                assert(data);                                           \
                                                                        \
                r = parser(rvalue);                                     \
                if (r < 0)                                              \
                        return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue); \
                                                                        \
                *i = r;                                                 \
                return 1;                                               \
        }

#define DEFINE_CONFIG_PARSE_PTR(function, parser, type)                 \
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
                        return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue); \
                                                                        \
                return 1;                                               \
        }

#define DEFINE_CONFIG_PARSE_ENUM_FULL(function, from_string, type)      \
        CONFIG_PARSER_PROTOTYPE(function) {                             \
                type *i = data, x;                                      \
                                                                        \
                assert(filename);                                       \
                assert(lvalue);                                         \
                assert(rvalue);                                         \
                assert(data);                                           \
                                                                        \
                x = from_string(rvalue);                                \
                if (x < 0)                                              \
                        return log_syntax_parse_error(unit, filename, line, x, lvalue, rvalue); \
                                                                        \
                *i = x;                                                 \
                return 1;                                               \
        }

#define DEFINE_CONFIG_PARSE_ENUM(function, name, type)                  \
        DEFINE_CONFIG_PARSE_ENUM_FULL(function, name##_from_string, type)

#define DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(function, name, type, default_value) \
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
                        return 1;                                       \
                }                                                       \
                                                                        \
                x = name##_from_string(rvalue);                         \
                if (x < 0)                                              \
                        return log_syntax_parse_error(unit, filename, line, x, lvalue, rvalue); \
                                                                        \
                *i = x;                                                 \
                return 1;                                               \
        }

#define DEFINE_CONFIG_PARSE_ENUMV(function, name, type, invalid)               \
        CONFIG_PARSER_PROTOTYPE(function) {                                    \
                type **enums = ASSERT_PTR(data);                               \
                _cleanup_free_ type *xs = NULL;                                \
                size_t n = 0;                                                  \
                int r;                                                         \
                                                                               \
                assert(lvalue);                                                \
                                                                               \
                for (const char *p = rvalue;;) {                               \
                        _cleanup_free_ char *en = NULL;                        \
                        type x;                                                \
                                                                               \
                        r = extract_first_word(&p, &en, NULL, 0);              \
                        if (r < 0)                                             \
                                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue); \
                        if (r == 0)                                            \
                                break;                                         \
                                                                               \
                        x = name##_from_string(en);                            \
                        if (x < 0) {                                           \
                                log_syntax(unit, LOG_WARNING, filename, line, x, \
                                           "Failed to parse %s in %s=, ignoring.", \
                                           en, lvalue);                        \
                                continue;                                      \
                        }                                                      \
                                                                               \
                        FOREACH_ARRAY(i, xs, n)                                \
                                if (*i == x) {                                 \
                                        log_syntax(unit, LOG_NOTICE, filename, line, 0, \
                                                   "Duplicate entry %s in %s=, ignoring.", \
                                                   en, lvalue);                \
                                        x = invalid;                           \
                                        break;                                 \
                                }                                              \
                                                                               \
                        if (x == invalid)                                      \
                                continue;                                      \
                                                                               \
                        /* Allocate one more for the trailing 'invalid'. */    \
                        if (!GREEDY_REALLOC(xs, n + 2))                        \
                                return log_oom();                              \
                                                                               \
                        xs[n++] = x;                                           \
                }                                                              \
                                                                               \
                if (n <= 0) {                                                  \
                        /* An empty string, or invalid values only. */         \
                        *enums = mfree(*enums);                                \
                        return 1;                                              \
                }                                                              \
                                                                               \
                /* Terminate with 'invalid' */                                 \
                xs[n] = invalid;                                               \
                free_and_replace(*enums, xs);                                  \
                return 1;                                                      \
        }

int config_parse_unsigned_bounded(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                const char *rvalue,
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
                const char *lvalue,
                const char *rvalue,
                uint32_t min,
                uint32_t max,
                bool ignoring,
                uint32_t *ret) {

        unsigned t;
        int r;

        r = config_parse_unsigned_bounded(
                        unit, filename, line, section, section_line, lvalue, rvalue,
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
                const char *lvalue,
                const char *rvalue,
                uint16_t min,
                uint16_t max,
                bool ignoring,
                uint16_t *ret) {

        unsigned t;
        int r;

        r = config_parse_unsigned_bounded(
                        unit, filename, line, section, section_line, lvalue, rvalue,
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
                const char *lvalue,
                const char *rvalue,
                uint8_t min,
                uint8_t max,
                bool ignoring,
                uint8_t *ret) {

        unsigned t;
        int r;

        r = config_parse_unsigned_bounded(
                        unit, filename, line, section, section_line, lvalue, rvalue,
                        min, max, ignoring,
                        &t);
        if (r <= 0)
                return r;
        assert(t <= UINT8_MAX);
        *ret = t;
        return 1;
}
