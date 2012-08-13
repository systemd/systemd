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

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>

#include "conf-parser.h"
#include "util.h"
#include "macro.h"
#include "strv.h"
#include "log.h"
#include "utf8.h"
#include "path-util.h"
#include "set.h"
#include "exit-status.h"

int config_item_table_lookup(
                void *table,
                const char *section,
                const char *lvalue,
                ConfigParserCallback *func,
                int *ltype,
                void **data,
                void *userdata) {

        ConfigTableItem *t;

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
                void *table,
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
static int next_assignment(
                const char *filename,
                unsigned line,
                ConfigItemLookup lookup,
                void *table,
                const char *section,
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
                        return func(filename, line, section, lvalue, ltype, rvalue, data, userdata);

                return 0;
        }

        /* Warn about unknown non-extension fields. */
        if (!relaxed && !startswith(lvalue, "X-"))
                log_info("[%s:%u] Unknown lvalue '%s' in section '%s'. Ignoring.", filename, line, lvalue, section);

        return 0;
}

/* Parse a variable assignment line */
static int parse_line(
                const char *filename,
                unsigned line,
                const char *sections,
                ConfigItemLookup lookup,
                void *table,
                bool relaxed,
                char **section,
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

        if (strchr(COMMENTS, *l))
                return 0;

        if (startswith(l, ".include ")) {
                char *fn;
                int r;

                fn = file_in_same_dir(filename, strstrip(l+9));
                if (!fn)
                        return -ENOMEM;

                r = config_parse(fn, NULL, sections, lookup, table, relaxed, userdata);
                free(fn);

                return r;
        }

        if (*l == '[') {
                size_t k;
                char *n;

                k = strlen(l);
                assert(k > 0);

                if (l[k-1] != ']') {
                        log_error("[%s:%u] Invalid section header.", filename, line);
                        return -EBADMSG;
                }

                n = strndup(l+1, k-2);
                if (!n)
                        return -ENOMEM;

                if (sections && !nulstr_contains(sections, n)) {

                        if (!relaxed)
                                log_info("[%s:%u] Unknown section '%s'. Ignoring.", filename, line, n);

                        free(n);
                        *section = NULL;
                } else {
                        free(*section);
                        *section = n;
                }

                return 0;
        }

        if (sections && !*section) {

                if (!relaxed)
                        log_info("[%s:%u] Assignment outside of section. Ignoring.", filename, line);

                return 0;
        }

        e = strchr(l, '=');
        if (!e) {
                log_error("[%s:%u] Missing '='.", filename, line);
                return -EBADMSG;
        }

        *e = 0;
        e++;

        return next_assignment(
                        filename,
                        line,
                        lookup,
                        table,
                        *section,
                        strstrip(l),
                        strstrip(e),
                        relaxed,
                        userdata);
}

/* Go through the file and parse each line */
int config_parse(
                const char *filename,
                FILE *f,
                const char *sections,
                ConfigItemLookup lookup,
                void *table,
                bool relaxed,
                void *userdata) {

        unsigned line = 0;
        char *section = NULL;
        int r;
        bool ours = false;
        char *continuation = NULL;

        assert(filename);
        assert(lookup);

        if (!f) {
                f = fopen(filename, "re");
                if (!f) {
                        r = -errno;
                        log_error("Failed to open configuration file '%s': %s", filename, strerror(-r));
                        goto finish;
                }

                ours = true;
        }

        while (!feof(f)) {
                char l[LINE_MAX], *p, *c = NULL, *e;
                bool escaped = false;

                if (!fgets(l, sizeof(l), f)) {
                        if (feof(f))
                                break;

                        r = -errno;
                        log_error("Failed to read configuration file '%s': %s", filename, strerror(-r));
                        goto finish;
                }

                truncate_nl(l);

                if (continuation) {
                        c = strappend(continuation, l);
                        if (!c) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        free(continuation);
                        continuation = NULL;
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
                                        r = -ENOMEM;
                                        goto finish;
                                }
                        }

                        continue;
                }

                r = parse_line(filename,
                                ++line,
                                sections,
                                lookup,
                                table,
                                relaxed,
                                &section,
                                p,
                                userdata);
                free(c);

                if (r < 0)
                        goto finish;
        }

        r = 0;

finish:
        free(section);
        free(continuation);

        if (f && ours)
                fclose(f);

        return r;
}

int config_parse_int(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        int *i = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((r = safe_atoi(rvalue, i)) < 0) {
                log_error("[%s:%u] Failed to parse numeric value, ingoring: %s", filename, line, rvalue);
                return 0;
        }

        return 0;
}

int config_parse_long(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        long *i = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((r = safe_atoli(rvalue, i)) < 0) {
                log_error("[%s:%u] Failed to parse numeric value, ignoring: %s", filename, line, rvalue);
                return 0;
        }

        return 0;
}

int config_parse_uint64(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint64_t *u = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((r = safe_atou64(rvalue, u)) < 0) {
                log_error("[%s:%u] Failed to parse numeric value, ignoring: %s", filename, line, rvalue);
                return 0;
        }

        return 0;
}

int config_parse_unsigned(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        unsigned *u = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((r = safe_atou(rvalue, u)) < 0) {
                log_error("[%s:%u] Failed to parse numeric value: %s", filename, line, rvalue);
                return r;
        }

        return 0;
}

int config_parse_bytes_size(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        size_t *sz = data;
        off_t o;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (parse_bytes(rvalue, &o) < 0 || (off_t) (size_t) o != o) {
                log_error("[%s:%u] Failed to parse byte value, ignoring: %s", filename, line, rvalue);
                return 0;
        }

        *sz = (size_t) o;
        return 0;
}


int config_parse_bytes_off(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        off_t *bytes = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        assert_cc(sizeof(off_t) == sizeof(uint64_t));

        if (parse_bytes(rvalue, bytes) < 0) {
                log_error("[%s:%u] Failed to parse bytes value, ignoring: %s", filename, line, rvalue);
                return 0;
        }

        return 0;
}

int config_parse_bool(
                const char *filename,
                unsigned line,
                const char *section,
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

        if ((k = parse_boolean(rvalue)) < 0) {
                log_error("[%s:%u] Failed to parse boolean value, ignoring: %s", filename, line, rvalue);
                return 0;
        }

        *b = !!k;
        return 0;
}

int config_parse_tristate(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        int k;
        int *b = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        /* Tristates are like booleans, but can also take the 'default' value, i.e. "-1" */

        k = parse_boolean(rvalue);
        if (k < 0) {
                log_error("[%s:%u] Failed to parse boolean value, ignoring: %s", filename, line, rvalue);
                return 0;
        }

        *b = !!k;
        return 0;
}

int config_parse_string(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char **s = data;
        char *n;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        n = cunescape(rvalue);
        if (!n)
                return -ENOMEM;

        if (!utf8_is_valid(n)) {
                log_error("[%s:%u] String is not UTF-8 clean, ignoring assignment: %s", filename, line, rvalue);
                free(n);
                return 0;
        }

        free(*s);
        if (*n)
                *s = n;
        else {
                free(n);
                *s = NULL;
        }

        return 0;
}

int config_parse_path(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char **s = data;
        char *n;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (!utf8_is_valid(rvalue)) {
                log_error("[%s:%u] Path is not UTF-8 clean, ignoring assignment: %s", filename, line, rvalue);
                return 0;
        }

        if (!path_is_absolute(rvalue)) {
                log_error("[%s:%u] Not an absolute path, ignoring: %s", filename, line, rvalue);
                return 0;
        }

        n = strdup(rvalue);
        if (!n)
                return -ENOMEM;

        path_kill_slashes(n);

        free(*s);
        *s = n;

        return 0;
}

int config_parse_strv(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char*** sv = data;
        char **n;
        char *w;
        unsigned k;
        size_t l;
        char *state;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        k = strv_length(*sv);
        FOREACH_WORD_QUOTED(w, l, rvalue, state)
                k++;

        n = new(char*, k+1);
        if (!n)
                return -ENOMEM;

        if (*sv)
                for (k = 0; (*sv)[k]; k++)
                        n[k] = (*sv)[k];
        else
                k = 0;

        FOREACH_WORD_QUOTED(w, l, rvalue, state) {
                n[k] = cunescape_length(w, l);
                if (!n[k]) {
                        r = -ENOMEM;
                        goto fail;
                }

                if (!utf8_is_valid(n[k])) {
                        log_error("[%s:%u] String is not UTF-8 clean, ignoring assignment: %s", filename, line, rvalue);
                        free(n[k]);
                        continue;
                }

                k++;
        }

        n[k] = NULL;
        free(*sv);
        *sv = n;

        return 0;

fail:
        for (; k > 0; k--)
                free(n[k-1]);
        free(n);

        return r;
}

int config_parse_path_strv(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char*** sv = data;
        char **n;
        char *w;
        unsigned k;
        size_t l;
        char *state;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        k = strv_length(*sv);
        FOREACH_WORD_QUOTED(w, l, rvalue, state)
                k++;

        n = new(char*, k+1);
        if (!n)
                return -ENOMEM;

        k = 0;
        if (*sv)
                for (; (*sv)[k]; k++)
                        n[k] = (*sv)[k];

        FOREACH_WORD_QUOTED(w, l, rvalue, state) {
                n[k] = strndup(w, l);
                if (!n[k]) {
                        r = -ENOMEM;
                        goto fail;
                }

                if (!utf8_is_valid(n[k])) {
                        log_error("[%s:%u] Path is not UTF-8 clean, ignoring assignment: %s", filename, line, rvalue);
                        free(n[k]);
                        continue;
                }

                if (!path_is_absolute(n[k])) {
                        log_error("[%s:%u] Not an absolute path, ignoring: %s", filename, line, rvalue);
                        free(n[k]);
                        continue;
                }

                path_kill_slashes(n[k]);
                k++;
        }

        n[k] = NULL;
        free(*sv);
        *sv = n;

        return 0;

fail:
        for (; k > 0; k--)
                free(n[k-1]);
        free(n);

        return r;
}

int config_parse_usec(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        usec_t *usec = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (parse_usec(rvalue, usec) < 0) {
                log_error("[%s:%u] Failed to parse time value, ignoring: %s", filename, line, rvalue);
                return 0;
        }

        return 0;
}

int config_parse_nsec(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        nsec_t *nsec = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (parse_nsec(rvalue, nsec) < 0) {
                log_error("[%s:%u] Failed to parse time value, ignoring: %s", filename, line, rvalue);
                return 0;
        }

        return 0;
}

int config_parse_mode(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        mode_t *m = data;
        long l;
        char *x = NULL;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        errno = 0;
        l = strtol(rvalue, &x, 8);
        if (!x || *x || errno) {
                log_error("[%s:%u] Failed to parse mode value, ignoring: %s", filename, line, rvalue);
                return 0;
        }

        if (l < 0000 || l > 07777) {
                log_error("[%s:%u] mode value out of range, ignoring: %s", filename, line, rvalue);
                return 0;
        }

        *m = (mode_t) l;
        return 0;
}

int config_parse_facility(
                const char *filename,
                unsigned line,
                const char *section,
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
                log_error("[%s:%u] Failed to parse log facility, ignoring: %s", filename, line, rvalue);
                return 0;
        }

        *o = (x << 3) | LOG_PRI(*o);

        return 0;
}

int config_parse_level(
                const char *filename,
                unsigned line,
                const char *section,
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
                log_error("[%s:%u] Failed to parse log level, ignoring: %s", filename, line, rvalue);
                return 0;
        }

        *o = (*o & LOG_FACMASK) | x;
        return 0;
}

int config_parse_set_status(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char *w;
        size_t l;
        char *state;
        int r;
        ExitStatusSet *status_set = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        FOREACH_WORD(w, l, rvalue, state) {
                int val;
                char *temp = strndup(w, l);
                if (!temp)
                        return log_oom();

                r = safe_atoi(temp, &val);
                if (r < 0) {
                        val = signal_from_string_try_harder(temp);
                        free(temp);
                        if (val > 0) {
                                if (!status_set->signal) {
                                        status_set->signal = set_new(trivial_hash_func, trivial_compare_func);
                                        if (!status_set->signal)
                                                return log_oom();
                                }
                                r = set_put(status_set->signal, INT_TO_PTR(val));
                                if (r < 0) {
                                        log_error("[%s:%u] Unable to store: %s", filename, line, w);
                                        return r;
                                }
                        } else {
                                log_error("[%s:%u] Failed to parse value: %s", filename, line, w);
                                return r;
                        }
                } else {
                        free(temp);
                        if(val < 0 || val > 255)
                                log_warning("[%s:%u] Value %d is outside range 0-255, ignoring", filename, line, val);
                        else {
                                if (!status_set->code) {
                                        status_set->code = set_new(trivial_hash_func, trivial_compare_func);
                                        if (!status_set->code)
                                                return log_oom();
                                }
                                r = set_put(status_set->code, INT_TO_PTR(val));
                                if (r < 0) {
                                        log_error("[%s:%u] Unable to store: %s", filename, line, w);
                                        return r;
                                }
                        }
                }

        }
        return 0;
}
