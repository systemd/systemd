/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
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

#define COMMENTS "#;\n"
#define NEWLINES "\n\r"
#define LINE_MAX 4096

/* Run the user supplied parser for an assignment */
static int next_assignment(
                const char *filename,
                unsigned line,
                const char *section,
                const ConfigItem *t,
                const char *lvalue,
                const char *rvalue,
                void *userdata) {

        assert(filename);
        assert(t);
        assert(lvalue);
        assert(rvalue);

        for (; t->parse; t++) {

                if (t->lvalue && !streq(lvalue, t->lvalue))
                        continue;

                if (t->section && !section)
                        continue;

                if (t->section && !streq(section, t->section))
                        continue;

                return t->parse(filename, line, section, lvalue, rvalue, t->data, userdata);
        }

        log_info("[%s:%u] Unknown lvalue '%s' in section '%s'. Ignoring.", filename, line, lvalue, strna(section));
        return 0;
}

/* Parse a variable assignment line */
static int parse_line(const char *filename, unsigned line, char **section, const char* const * sections, const ConfigItem *t, char *l, void *userdata) {
        char *e;

        l = strstrip(l);

        if (!*l)
                return 0;

        if (strchr(COMMENTS, *l))
                return 0;

        if (startswith(l, ".include ")) {
                char *fn;
                int r;

                if (!(fn = file_in_same_dir(filename, strstrip(l+9))))
                        return -ENOMEM;

                r = config_parse(fn, NULL, sections, t, userdata);
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

                if (!(n = strndup(l+1, k-2)))
                        return -ENOMEM;

                if (sections && !strv_contains((char**) sections, n)) {
                        free(n);
                        return -EBADMSG;
                }

                free(*section);
                *section = n;

                return 0;
        }

        if (!(e = strchr(l, '='))) {
                log_error("[%s:%u] Missing '='.", filename, line);
                return -EBADMSG;
        }

        *e = 0;
        e++;

        return next_assignment(filename, line, *section, t, strstrip(l), strstrip(e), userdata);
}

/* Go through the file and parse each line */
int config_parse(const char *filename, FILE *f, const char* const * sections, const ConfigItem *t, void *userdata) {
        unsigned line = 0;
        char *section = NULL;
        int r;
        bool ours = false;

        assert(filename);
        assert(t);

        if (!f) {
                if (!(f = fopen(filename, "re"))) {
                        r = -errno;
                        log_error("Failed to open configuration file '%s': %s", filename, strerror(-r));
                        goto finish;
                }

                ours = true;
        }

        while (!feof(f)) {
                char l[LINE_MAX];

                if (!fgets(l, sizeof(l), f)) {
                        if (feof(f))
                                break;

                        r = -errno;
                        log_error("Failed to read configuration file '%s': %s", filename, strerror(-r));
                        goto finish;
                }

                if ((r = parse_line(filename, ++line, &section, sections, t, l, userdata)) < 0)
                        goto finish;
        }

        r = 0;

finish:
        free(section);

        if (f && ours)
                fclose(f);

        return r;
}

int config_parse_int(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
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
                log_error("[%s:%u] Failed to parse numeric value: %s", filename, line, rvalue);
                return r;
        }

        return 0;
}

int config_parse_unsigned(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
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

int config_parse_size(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        size_t *sz = data;
        unsigned u;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((r = safe_atou(rvalue, &u)) < 0) {
                log_error("[%s:%u] Failed to parse numeric value: %s", filename, line, rvalue);
                return r;
        }

        *sz = (size_t) u;
        return 0;
}

int config_parse_bool(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
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
                log_error("[%s:%u] Failed to parse boolean value: %s", filename, line, rvalue);
                return k;
        }

        *b = !!k;
        return 0;
}

int config_parse_string(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        char **s = data;
        char *n;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (*rvalue) {
                if (!(n = strdup(rvalue)))
                        return -ENOMEM;
        } else
                n = NULL;

        free(*s);
        *s = n;

        return 0;
}

int config_parse_path(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        char **s = data;
        char *n;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (*rvalue != '/') {
                log_error("[%s:%u] Not an absolute path: %s", filename, line, rvalue);
                return -EINVAL;
        }

        if (!(n = strdup(rvalue)))
                return -ENOMEM;

        free(*s);
        *s = n;

        return 0;
}

int config_parse_strv(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        char*** sv = data;
        char **n;
        char *w;
        unsigned k;
        size_t l;
        char *state;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        k = strv_length(*sv);
        FOREACH_WORD_QUOTED(w, l, rvalue, state)
                k++;

        if (!(n = new(char*, k+1)))
                return -ENOMEM;

        for (k = 0; (*sv)[k]; k++)
                n[k] = (*sv)[k];
        FOREACH_WORD_QUOTED(w, l, rvalue, state)
                if (!(n[k++] = strndup(w, l)))
                        goto fail;

        n[k] = NULL;
        free(*sv);
        *sv = n;

        return 0;

fail:
        for (; k > 0; k--)
                free(n[k-1]);
        free(n);

        return -ENOMEM;
}
