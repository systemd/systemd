/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "fd-util.h"
#include "fs-util.h"
#include "log.h"
#include "macro.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "strv.h"
#include "syslog-util.h"
#include "utf8.h"
#include "util.h"

int config_item_table_lookup(
                const void *table,
                const char *section,
                const char *lvalue,
                ConfigParserCallback *func,
                int *ltype,
                void **data,
                void *userdata) {

        const ConfigTableItem *t;

        assert(table);
        assert(lvalue);
        assert(func);
        assert(ltype);
        assert(data);

        for (t = table; t->lvalue; t++) {

                if (!streq(lvalue, t->lvalue))
                        continue;

                if (!streq_ptr(section, t->section))
                        continue;

                *func = t->parse;
                *ltype = t->ltype;
                *data = t->data;
                return 1;
        }

        return 0;
}

int config_item_perf_lookup(
                const void *table,
                const char *section,
                const char *lvalue,
                ConfigParserCallback *func,
                int *ltype,
                void **data,
                void *userdata) {

        ConfigPerfItemLookup lookup = (ConfigPerfItemLookup) table;
        const ConfigPerfItem *p;

        assert(table);
        assert(lvalue);
        assert(func);
        assert(ltype);
        assert(data);

        if (!section)
                p = lookup(lvalue, strlen(lvalue));
        else {
                char *key;

                key = strjoin(section, ".", lvalue, NULL);
                if (!key)
                        return -ENOMEM;

                p = lookup(key, strlen(key));
                free(key);
        }

        if (!p)
                return 0;

        *func = p->parse;
        *ltype = p->ltype;
        *data = (uint8_t*) userdata + p->offset;
        return 1;
}

/* Run the user supplied parser for an assignment */
static int next_assignment(const char *unit,
                           const char *filename,
                           unsigned line,
                           ConfigItemLookup lookup,
                           const void *table,
                           const char *section,
                           unsigned section_line,
                           const char *lvalue,
                           const char *rvalue,
                           bool relaxed,
                           void *userdata) {

        ConfigParserCallback func = NULL;
        int ltype = 0;
        void *data = NULL;
        int r;

        assert(filename);
        assert(line > 0);
        assert(lookup);
        assert(lvalue);
        assert(rvalue);

        r = lookup(table, section, lvalue, &func, &ltype, &data, userdata);
        if (r < 0)
                return r;

        if (r > 0) {
                if (func)
                        return func(unit, filename, line, section, section_line,
                                    lvalue, ltype, rvalue, data, userdata);

                return 0;
        }

        /* Warn about unknown non-extension fields. */
        if (!relaxed && !startswith(lvalue, "X-"))
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Unknown lvalue '%s' in section '%s'", lvalue, section);

        return 0;
}

/* Parse a variable assignment line */
static int parse_line(const char* unit,
                      const char *filename,
                      unsigned line,
                      const char *sections,
                      ConfigItemLookup lookup,
                      const void *table,
                      bool relaxed,
                      bool allow_include,
                      char **section,
                      unsigned *section_line,
                      bool *section_ignored,
                      char *l,
                      void *userdata) {

        char *e;

        assert(filename);
        assert(line > 0);
        assert(lookup);
        assert(l);

        l = strstrip(l);

        if (!*l)
                return 0;

        if (strchr(COMMENTS "\n", *l))
                return 0;

        if (startswith(l, ".include ")) {
                _cleanup_free_ char *fn = NULL;

                /* .includes are a bad idea, we only support them here
                 * for historical reasons. They create cyclic include
                 * problems and make it difficult to detect
                 * configuration file changes with an easy
                 * stat(). Better approaches, such as .d/ drop-in
                 * snippets exist.
                 *
                 * Support for them should be eventually removed. */

                if (!allow_include) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, ".include not allowed here. Ignoring.");
                        return 0;
                }

                fn = file_in_same_dir(filename, strstrip(l+9));
                if (!fn)
                        return -ENOMEM;

                return config_parse(unit, fn, NULL, sections, lookup, table, relaxed, false, false, userdata);
        }

        if (*l == '[') {
                size_t k;
                char *n;

                k = strlen(l);
                assert(k > 0);

                if (l[k-1] != ']') {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid section header '%s'", l);
                        return -EBADMSG;
                }

                n = strndup(l+1, k-2);
                if (!n)
                        return -ENOMEM;

                if (sections && !nulstr_contains(sections, n)) {

                        if (!relaxed && !startswith(n, "X-"))
                                log_syntax(unit, LOG_WARNING, filename, line, 0, "Unknown section '%s'. Ignoring.", n);

                        free(n);
                        *section = mfree(*section);
                        *section_line = 0;
                        *section_ignored = true;
                } else {
                        free(*section);
                        *section = n;
                        *section_line = line;
                        *section_ignored = false;
                }

                return 0;
        }

        if (sections && !*section) {

                if (!relaxed && !*section_ignored)
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Assignment outside of section. Ignoring.");

                return 0;
        }

        e = strchr(l, '=');
        if (!e) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Missing '='.");
                return -EINVAL;
        }

        *e = 0;
        e++;

        return next_assignment(unit,
                               filename,
                               line,
                               lookup,
                               table,
                               *section,
                               *section_line,
                               strstrip(l),
                               strstrip(e),
                               relaxed,
                               userdata);
}

/* Go through the file and parse each line */
int config_parse(const char *unit,
                 const char *filename,
                 FILE *f,
                 const char *sections,
                 ConfigItemLookup lookup,
                 const void *table,
                 bool relaxed,
                 bool allow_include,
                 bool warn,
                 void *userdata) {

        _cleanup_free_ char *section = NULL, *continuation = NULL;
        _cleanup_fclose_ FILE *ours = NULL;
        unsigned line = 0, section_line = 0;
        bool section_ignored = false;
        int r;

        assert(filename);
        assert(lookup);

        if (!f) {
                f = ours = fopen(filename, "re");
                if (!f) {
                        /* Only log on request, except for ENOENT,
                         * since we return 0 to the caller. */
                        if (warn || errno == ENOENT)
                                log_full(errno == ENOENT ? LOG_DEBUG : LOG_ERR,
                                         "Failed to open configuration file '%s': %m", filename);
                        return errno == ENOENT ? 0 : -errno;
                }
        }

        fd_warn_permissions(filename, fileno(f));

        while (!feof(f)) {
                char l[LINE_MAX], *p, *c = NULL, *e;
                bool escaped = false;

                if (!fgets(l, sizeof(l), f)) {
                        if (feof(f))
                                break;

                        log_error_errno(errno, "Failed to read configuration file '%s': %m", filename);
                        return -errno;
                }

                truncate_nl(l);

                if (continuation) {
                        c = strappend(continuation, l);
                        if (!c) {
                                if (warn)
                                        log_oom();
                                return -ENOMEM;
                        }

                        continuation = mfree(continuation);
                        p = c;
                } else
                        p = l;

                for (e = p; *e; e++) {
                        if (escaped)
                                escaped = false;
                        else if (*e == '\\')
                                escaped = true;
                }

                if (escaped) {
                        *(e-1) = ' ';

                        if (c)
                                continuation = c;
                        else {
                                continuation = strdup(l);
                                if (!continuation) {
                                        if (warn)
                                                log_oom();
                                        return -ENOMEM;
                                }
                        }

                        continue;
                }

                r = parse_line(unit,
                               filename,
                               ++line,
                               sections,
                               lookup,
                               table,
                               relaxed,
                               allow_include,
                               &section,
                               &section_line,
                               &section_ignored,
                               p,
                               userdata);
                free(c);

                if (r < 0) {
                        if (warn)
                                log_warning_errno(r, "Failed to parse file '%s': %m",
                                                  filename);
                        return r;
                }
        }

        return 0;
}

/* Parse each config file in the specified directories. */
int config_parse_many(const char *conf_file,
                      const char *conf_file_dirs,
                      const char *sections,
                      ConfigItemLookup lookup,
                      const void *table,
                      bool relaxed,
                      void *userdata) {
        _cleanup_strv_free_ char **files = NULL;
        char **fn;
        int r;

        r = conf_files_list_nulstr(&files, ".conf", NULL, conf_file_dirs);
        if (r < 0)
                return r;

        if (conf_file) {
                r = config_parse(NULL, conf_file, NULL, sections, lookup, table, relaxed, false, true, userdata);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(fn, files) {
                r = config_parse(NULL, *fn, NULL, sections, lookup, table, relaxed, false, true, userdata);
                if (r < 0)
                        return r;
        }

        return 0;
}

#define DEFINE_PARSER(type, vartype, conv_func)                         \
        int config_parse_##type(                                        \
                        const char *unit,                               \
                        const char *filename,                           \
                        unsigned line,                                  \
                        const char *section,                            \
                        unsigned section_line,                          \
                        const char *lvalue,                             \
                        int ltype,                                      \
                        const char *rvalue,                             \
                        void *data,                                     \
                        void *userdata) {                               \
                                                                        \
                vartype *i = data;                                      \
                int r;                                                  \
                                                                        \
                assert(filename);                                       \
                assert(lvalue);                                         \
                assert(rvalue);                                         \
                assert(data);                                           \
                                                                        \
                r = conv_func(rvalue, i);                               \
                if (r < 0)                                              \
                        log_syntax(unit, LOG_ERR, filename, line, r,    \
                                   "Failed to parse %s value, ignoring: %s", \
                                   #type, rvalue);                      \
                                                                        \
                return 0;                                               \
        }                                                               \
        struct __useless_struct_to_allow_trailing_semicolon__

DEFINE_PARSER(int, int, safe_atoi);
DEFINE_PARSER(long, long, safe_atoli);
DEFINE_PARSER(uint32, uint32_t, safe_atou32);
DEFINE_PARSER(uint64, uint64_t, safe_atou64);
DEFINE_PARSER(unsigned, unsigned, safe_atou);
DEFINE_PARSER(double, double, safe_atod);
DEFINE_PARSER(nsec, nsec_t, parse_nsec);
DEFINE_PARSER(sec, usec_t, parse_sec);
DEFINE_PARSER(mode, mode_t, parse_mode);

int config_parse_iec_size(const char* unit,
                            const char *filename,
                            unsigned line,
                            const char *section,
                            unsigned section_line,
                            const char *lvalue,
                            int ltype,
                            const char *rvalue,
                            void *data,
                            void *userdata) {

        size_t *sz = data;
        uint64_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = parse_size(rvalue, 1024, &v);
        if (r < 0 || (uint64_t) (size_t) v != v) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse size value, ignoring: %s", rvalue);
                return 0;
        }

        *sz = (size_t) v;
        return 0;
}

int config_parse_si_size(const char* unit,
                            const char *filename,
                            unsigned line,
                            const char *section,
                            unsigned section_line,
                            const char *lvalue,
                            int ltype,
                            const char *rvalue,
                            void *data,
                            void *userdata) {

        size_t *sz = data;
        uint64_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = parse_size(rvalue, 1000, &v);
        if (r < 0 || (uint64_t) (size_t) v != v) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse size value, ignoring: %s", rvalue);
                return 0;
        }

        *sz = (size_t) v;
        return 0;
}

int config_parse_iec_uint64(const char* unit,
                           const char *filename,
                           unsigned line,
                           const char *section,
                           unsigned section_line,
                           const char *lvalue,
                           int ltype,
                           const char *rvalue,
                           void *data,
                           void *userdata) {

        uint64_t *bytes = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = parse_size(rvalue, 1024, bytes);
        if (r < 0)
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse size value, ignoring: %s", rvalue);

        return 0;
}

int config_parse_bool(const char* unit,
                      const char *filename,
                      unsigned line,
                      const char *section,
                      unsigned section_line,
                      const char *lvalue,
                      int ltype,
                      const char *rvalue,
                      void *data,
                      void *userdata) {

        int k;
        bool *b = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        k = parse_boolean(rvalue);
        if (k < 0) {
                log_syntax(unit, LOG_ERR, filename, line, k, "Failed to parse boolean value, ignoring: %s", rvalue);
                return 0;
        }

        *b = !!k;
        return 0;
}

int config_parse_tristate(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        int k, *t = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        /* A tristate is pretty much a boolean, except that it can
         * also take the special value -1, indicating "uninitialized",
         * much like NULL is for a pointer type. */

        k = parse_boolean(rvalue);
        if (k < 0) {
                log_syntax(unit, LOG_ERR, filename, line, k, "Failed to parse boolean value, ignoring: %s", rvalue);
                return 0;
        }

        *t = !!k;
        return 0;
}

int config_parse_string(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char **s = data, *n;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (!utf8_is_valid(rvalue)) {
                log_syntax_invalid_utf8(unit, LOG_ERR, filename, line, rvalue);
                return 0;
        }

        if (isempty(rvalue))
                n = NULL;
        else {
                n = strdup(rvalue);
                if (!n)
                        return log_oom();
        }

        free(*s);
        *s = n;

        return 0;
}

int config_parse_path(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char **s = data, *n;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (!utf8_is_valid(rvalue)) {
                log_syntax_invalid_utf8(unit, LOG_ERR, filename, line, rvalue);
                return 0;
        }

        if (!path_is_absolute(rvalue)) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Not an absolute path, ignoring: %s", rvalue);
                return 0;
        }

        n = strdup(rvalue);
        if (!n)
                return log_oom();

        path_kill_slashes(n);

        free(*s);
        *s = n;

        return 0;
}

int config_parse_strv(const char *unit,
                      const char *filename,
                      unsigned line,
                      const char *section,
                      unsigned section_line,
                      const char *lvalue,
                      int ltype,
                      const char *rvalue,
                      void *data,
                      void *userdata) {

        char ***sv = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                char **empty;

                /* Empty assignment resets the list. As a special rule
                 * we actually fill in a real empty array here rather
                 * than NULL, since some code wants to know if
                 * something was set at all... */
                empty = strv_new(NULL, NULL);
                if (!empty)
                        return log_oom();

                strv_free(*sv);
                *sv = empty;
                return 0;
        }

        for (;;) {
                char *word = NULL;
                int r;
                r = extract_first_word(&rvalue, &word, WHITESPACE, EXTRACT_QUOTES);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                        break;
                }

                if (!utf8_is_valid(word)) {
                        log_syntax_invalid_utf8(unit, LOG_ERR, filename, line, rvalue);
                        free(word);
                        continue;
                }
                r = strv_consume(sv, word);
                if (r < 0)
                        return log_oom();
        }

        return 0;
}

int config_parse_log_facility(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {


        int *o = data, x;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        x = log_facility_unshifted_from_string(rvalue);
        if (x < 0) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse log facility, ignoring: %s", rvalue);
                return 0;
        }

        *o = (x << 3) | LOG_PRI(*o);

        return 0;
}

int config_parse_log_level(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {


        int *o = data, x;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        x = log_level_from_string(rvalue);
        if (x < 0) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse log level, ignoring: %s", rvalue);
                return 0;
        }

        *o = (*o & LOG_FACMASK) | x;
        return 0;
}

int config_parse_signal(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        int *sig = data, r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(sig);

        r = signal_from_string_try_harder(rvalue);
        if (r <= 0) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse signal name, ignoring: %s", rvalue);
                return 0;
        }

        *sig = r;
        return 0;
}

int config_parse_personality(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        unsigned long *personality = data, p;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(personality);

        p = personality_from_string(rvalue);
        if (p == PERSONALITY_INVALID) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse personality, ignoring: %s", rvalue);
                return 0;
        }

        *personality = p;
        return 0;
}
