/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "def.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "macro.h"
#include "missing.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "syslog-util.h"
#include "time-util.h"
#include "utf8.h"

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

        if (section) {
                const char *key;

                key = strjoina(section, ".", lvalue);
                p = lookup(key, strlen(key));
        } else
                p = lookup(lvalue, strlen(lvalue));
        if (!p)
                return 0;

        *func = p->parse;
        *ltype = p->ltype;
        *data = (uint8_t*) userdata + p->offset;
        return 1;
}

/* Run the user supplied parser for an assignment */
static int next_assignment(
                const char *unit,
                const char *filename,
                unsigned line,
                ConfigItemLookup lookup,
                const void *table,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                const char *rvalue,
                ConfigParseFlags flags,
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
        if (!(flags & CONFIG_PARSE_RELAXED) && !startswith(lvalue, "X-"))
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Unknown key name '%s' in section '%s', ignoring.", lvalue, section);

        return 0;
}

/* Parse a single logical line */
static int parse_line(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *sections,
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                char **section,
                unsigned *section_line,
                bool *section_ignored,
                char *l,
                void *userdata) {

        char *e, *include;

        assert(filename);
        assert(line > 0);
        assert(lookup);
        assert(l);

        l = strstrip(l);
        if (!*l)
                return 0;

        if (*l == '\n')
                return 0;

        include = first_word(l, ".include");
        if (include) {
                _cleanup_free_ char *fn = NULL;

                /* .includes are a bad idea, we only support them here
                 * for historical reasons. They create cyclic include
                 * problems and make it difficult to detect
                 * configuration file changes with an easy
                 * stat(). Better approaches, such as .d/ drop-in
                 * snippets exist.
                 *
                 * Support for them should be eventually removed. */

                if (!(flags & CONFIG_PARSE_ALLOW_INCLUDE)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, ".include not allowed here. Ignoring.");
                        return 0;
                }

                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           ".include directives are deprecated, and support for them will be removed in a future version of systemd. "
                           "Please use drop-in files instead.");

                fn = file_in_same_dir(filename, strstrip(include));
                if (!fn)
                        return -ENOMEM;

                return config_parse(unit, fn, NULL, sections, lookup, table, flags, userdata);
        }

        if (!utf8_is_valid(l))
                return log_syntax_invalid_utf8(unit, LOG_WARNING, filename, line, l);

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

                        if (!(flags & CONFIG_PARSE_RELAXED) && !startswith(n, "X-"))
                                log_syntax(unit, LOG_WARNING, filename, line, 0, "Unknown section '%s'. Ignoring.", n);

                        free(n);
                        *section = mfree(*section);
                        *section_line = 0;
                        *section_ignored = true;
                } else {
                        free_and_replace(*section, n);
                        *section_line = line;
                        *section_ignored = false;
                }

                return 0;
        }

        if (sections && !*section) {
                if (!(flags & CONFIG_PARSE_RELAXED) && !*section_ignored)
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Assignment outside of section. Ignoring.");

                return 0;
        }

        e = strchr(l, '=');
        if (!e)
                return log_syntax(unit, LOG_WARNING, filename, line, 0,
                                  "Missing '=', ignoring line.");
        if (e == l)
                return log_syntax(unit, LOG_WARNING, filename, line, 0,
                                  "Missing key name before '=', ignoring line.");

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
                               flags,
                               userdata);
}

/* Go through the file and parse each line */
int config_parse(const char *unit,
                 const char *filename,
                 FILE *f,
                 const char *sections,
                 ConfigItemLookup lookup,
                 const void *table,
                 ConfigParseFlags flags,
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
                        if ((flags & CONFIG_PARSE_WARN) || errno == ENOENT)
                                log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_ERR, errno,
                                               "Failed to open configuration file '%s': %m", filename);
                        return errno == ENOENT ? 0 : -errno;
                }
        }

        fd_warn_permissions(filename, fileno(f));

        for (;;) {
                _cleanup_free_ char *buf = NULL;
                bool escaped = false;
                char *l, *p, *e;

                r = read_line(f, LONG_LINE_MAX, &buf);
                if (r == 0)
                        break;
                if (r == -ENOBUFS) {
                        if (flags & CONFIG_PARSE_WARN)
                                log_error_errno(r, "%s:%u: Line too long", filename, line);

                        return r;
                }
                if (r < 0) {
                        if (CONFIG_PARSE_WARN)
                                log_error_errno(r, "%s:%u: Error while reading configuration file: %m", filename, line);

                        return r;
                }

                l = skip_leading_chars(buf, WHITESPACE);
                if (*l != '\0' && strchr(COMMENTS, *l))
                        continue;

                l = buf;
                if (!(flags & CONFIG_PARSE_REFUSE_BOM)) {
                        char *q;

                        q = startswith(buf, UTF8_BYTE_ORDER_MARK);
                        if (q) {
                                l = q;
                                flags |= CONFIG_PARSE_REFUSE_BOM;
                        }
                }

                if (continuation) {
                        if (strlen(continuation) + strlen(l) > LONG_LINE_MAX) {
                                if (flags & CONFIG_PARSE_WARN)
                                        log_error("%s:%u: Continuation line too long", filename, line);
                                return -ENOBUFS;
                        }

                        if (!strextend(&continuation, l, NULL)) {
                                if (flags & CONFIG_PARSE_WARN)
                                        log_oom();
                                return -ENOMEM;
                        }

                        p = continuation;
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

                        if (!continuation) {
                                continuation = strdup(l);
                                if (!continuation) {
                                        if (flags & CONFIG_PARSE_WARN)
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
                               flags,
                               &section,
                               &section_line,
                               &section_ignored,
                               p,
                               userdata);
                if (r < 0) {
                        if (flags & CONFIG_PARSE_WARN)
                                log_warning_errno(r, "%s:%u: Failed to parse file: %m", filename, line);
                        return r;
                }

                continuation = mfree(continuation);
        }

        if (continuation) {
                r = parse_line(unit,
                               filename,
                               ++line,
                               sections,
                               lookup,
                               table,
                               flags,
                               &section,
                               &section_line,
                               &section_ignored,
                               continuation,
                               userdata);
                if (r < 0) {
                        if (flags & CONFIG_PARSE_WARN)
                                log_warning_errno(r, "%s:%u: Failed to parse file: %m", filename, line);
                        return r;
                }
        }

        return 0;
}

static int config_parse_many_files(
                const char *conf_file,
                char **files,
                const char *sections,
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata) {

        char **fn;
        int r;

        if (conf_file) {
                r = config_parse(NULL, conf_file, NULL, sections, lookup, table, flags, userdata);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(fn, files) {
                r = config_parse(NULL, *fn, NULL, sections, lookup, table, flags, userdata);
                if (r < 0)
                        return r;
        }

        return 0;
}

/* Parse each config file in the directories specified as nulstr. */
int config_parse_many_nulstr(
                const char *conf_file,
                const char *conf_file_dirs,
                const char *sections,
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata) {

        _cleanup_strv_free_ char **files = NULL;
        int r;

        r = conf_files_list_nulstr(&files, ".conf", NULL, 0, conf_file_dirs);
        if (r < 0)
                return r;

        return config_parse_many_files(conf_file, files, sections, lookup, table, flags, userdata);
}

/* Parse each config file in the directories specified as strv. */
int config_parse_many(
                const char *conf_file,
                const char* const* conf_file_dirs,
                const char *dropin_dirname,
                const char *sections,
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata) {

        _cleanup_strv_free_ char **dropin_dirs = NULL;
        _cleanup_strv_free_ char **files = NULL;
        const char *suffix;
        int r;

        suffix = strjoina("/", dropin_dirname);
        r = strv_extend_strv_concat(&dropin_dirs, (char**) conf_file_dirs, suffix);
        if (r < 0)
                return r;

        r = conf_files_list_strv(&files, ".conf", NULL, 0, (const char* const*) dropin_dirs);
        if (r < 0)
                return r;

        return config_parse_many_files(conf_file, files, sections, lookup, table, flags, userdata);
}

#define DEFINE_PARSER(type, vartype, conv_func)                         \
        DEFINE_CONFIG_PARSE_PTR(config_parse_##type, conv_func, vartype, "Failed to parse " #type " value")

DEFINE_PARSER(int, int, safe_atoi);
DEFINE_PARSER(long, long, safe_atoli);
DEFINE_PARSER(uint8, uint8_t, safe_atou8);
DEFINE_PARSER(uint16, uint16_t, safe_atou16);
DEFINE_PARSER(uint32, uint32_t, safe_atou32);
DEFINE_PARSER(uint64, uint64_t, safe_atou64);
DEFINE_PARSER(unsigned, unsigned, safe_atou);
DEFINE_PARSER(double, double, safe_atod);
DEFINE_PARSER(nsec, nsec_t, parse_nsec);
DEFINE_PARSER(sec, usec_t, parse_sec);
DEFINE_PARSER(sec_def_infinity, usec_t, parse_sec_def_infinity);
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
        if (r >= 0 && (uint64_t) (size_t) v != v)
                r = -ERANGE;
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse size value '%s', ignoring: %m", rvalue);
                return 0;
        }

        *sz = (size_t) v;
        return 0;
}

int config_parse_si_size(
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

        size_t *sz = data;
        uint64_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = parse_size(rvalue, 1000, &v);
        if (r >= 0 && (uint64_t) (size_t) v != v)
                r = -ERANGE;
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse size value '%s', ignoring: %m", rvalue);
                return 0;
        }

        *sz = (size_t) v;
        return 0;
}

int config_parse_iec_uint64(
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
        bool fatal = ltype;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        k = parse_boolean(rvalue);
        if (k < 0) {
                log_syntax(unit, LOG_ERR, filename, line, k,
                           "Failed to parse boolean value%s: %s",
                           fatal ? "" : ", ignoring", rvalue);
                return fatal ? -ENOEXEC : 0;
        }

        *b = k;
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

        char **s = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (free_and_strdup(s, empty_to_null(rvalue)) < 0)
                return log_oom();

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

        _cleanup_free_ char *n = NULL;
        bool fatal = ltype;
        char **s = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue))
                goto finalize;

        n = strdup(rvalue);
        if (!n)
                return log_oom();

        r = path_simplify_and_warn(n, PATH_CHECK_ABSOLUTE | (fatal ? PATH_CHECK_FATAL : 0), unit, filename, line, lvalue);
        if (r < 0)
                return fatal ? -ENOEXEC : 0;

finalize:
        return free_and_replace(*s, n);
}

int config_parse_strv(
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

        char ***sv = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                *sv = strv_free(*sv);
                return 0;
        }

        for (;;) {
                char *word = NULL;

                r = extract_first_word(&rvalue, &word, NULL, EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                        break;
                }

                r = strv_consume(sv, word);
                if (r < 0)
                        return log_oom();
        }

        return 0;
}

int config_parse_warn_compat(
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

        Disabled reason = ltype;

        switch(reason) {

        case DISABLED_CONFIGURATION:
                log_syntax(unit, LOG_DEBUG, filename, line, 0,
                           "Support for option %s= has been disabled at compile time and it is ignored", lvalue);
                break;

        case DISABLED_LEGACY:
                log_syntax(unit, LOG_INFO, filename, line, 0,
                           "Support for option %s= has been removed and it is ignored", lvalue);
                break;

        case DISABLED_EXPERIMENTAL:
                log_syntax(unit, LOG_INFO, filename, line, 0,
                           "Support for option %s= has not yet been enabled and it is ignored", lvalue);
                break;
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

        if (*o < 0) /* if it wasn't initialized so far, assume zero facility */
                *o = x;
        else
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

        r = signal_from_string(rvalue);
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

        if (isempty(rvalue))
                p = PERSONALITY_INVALID;
        else {
                p = personality_from_string(rvalue);
                if (p == PERSONALITY_INVALID) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse personality, ignoring: %s", rvalue);
                        return 0;
                }
        }

        *personality = p;
        return 0;
}

int config_parse_ifname(
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

        char **s = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                *s = mfree(*s);
                return 0;
        }

        if (!ifname_valid(rvalue)) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Interface name is not valid or too long, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = free_and_strdup(s, rvalue);
        if (r < 0)
                return log_oom();

        return 0;
}

int config_parse_ip_port(
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

        uint16_t *s = data;
        uint16_t port;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                *s = 0;
                return 0;
        }

        r = parse_ip_port(rvalue, &port);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse port '%s'.", rvalue);
                return 0;
        }

        *s = port;

        return 0;
}

int config_parse_mtu(
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

        uint32_t *mtu = data;
        int r;

        assert(rvalue);
        assert(mtu);

        r = parse_mtu(ltype, rvalue, mtu);
        if (r == -ERANGE) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Maximum transfer unit (MTU) value out of range. Permitted range is %" PRIu32 "…%" PRIu32 ", ignoring: %s",
                           (uint32_t) (ltype == AF_INET6 ? IPV6_MIN_MTU : IPV4_MIN_MTU), (uint32_t) UINT32_MAX,
                           rvalue);
                return 0;
        }
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse MTU value '%s', ignoring: %m", rvalue);
                return 0;
        }

        return 0;
}

int config_parse_rlimit(
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

        struct rlimit **rl = data, d = {};
        int r;

        assert(rvalue);
        assert(rl);

        r = rlimit_parse(ltype, rvalue, &d);
        if (r == -EILSEQ) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Soft resource limit chosen higher than hard limit, ignoring: %s", rvalue);
                return 0;
        }
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse resource value, ignoring: %s", rvalue);
                return 0;
        }

        if (rl[ltype])
                *rl[ltype] = d;
        else {
                rl[ltype] = newdup(struct rlimit, &d, 1);
                if (!rl[ltype])
                        return log_oom();
        }

        return 0;
}

int config_parse_permille(const char* unit,
                          const char *filename,
                          unsigned line,
                          const char *section,
                          unsigned section_line,
                          const char *lvalue,
                          int ltype,
                          const char *rvalue,
                          void *data,
                          void *userdata) {

        unsigned *permille = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(permille);

        r = parse_permille(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse permille value, ignoring: %s", rvalue);
                return 0;
        }

        *permille = (unsigned) r;

        return 0;
}
