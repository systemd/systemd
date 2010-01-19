/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>

#include "conf-parser.h"
#include "util.h"
#include "macro.h"
#include "strv.h"

#define WHITESPACE " \t\n"
#define COMMENTS "#;\n"
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

        fprintf(stderr, "[%s:%u] Unknown lvalue '%s' in section '%s'.\n", filename, line, lvalue, strna(section));
        return -EBADMSG;
}

/* Returns non-zero when c is contained in s */
static int in_string(char c, const char *s) {
        assert(s);

        for (; *s; s++)
                if (*s == c)
                        return 1;

        return 0;
}

/* Remove all whitepsapce from the beginning and the end of *s. *s may
 * be modified. */
static char *strip(char *s) {
        char *b = s+strspn(s, WHITESPACE);
        char *e, *l = NULL;

        for (e = b; *e; e++)
                if (!in_string(*e, WHITESPACE))
                        l = e;

        if (l)
                *(l+1) = 0;

        return b;
}

/* Parse a variable assignment line */
static int parse_line(const char *filename, unsigned line, char **section, const char* const * sections, const ConfigItem *t, char *l, void *userdata) {
        char *e, *c, *b;

        b = l+strspn(l, WHITESPACE);

        if ((c = strpbrk(b, COMMENTS)))
                *c = 0;

        if (!*b)
                return 0;

        if (startswith(b, ".include ")) {
                char *path = NULL, *fn;
                int r;

                fn = strip(b+9);
                if (!is_path_absolute(fn)) {
                        const char *k;

                        if ((k = strrchr(filename, '/'))) {
                                char *dir;

                                if (!(dir = strndup(filename, k-filename)))
                                        return -ENOMEM;

                                if (asprintf(&path, "%s/%s", dir, fn) < 0)
                                        return -errno;

                                fn = path;
                                free(dir);
                        }
                }

                r = config_parse(fn, sections, t, userdata);
                free(path);
                return r;
        }

        if (*b == '[') {
                size_t k;
                char *n;

                k = strlen(b);
                assert(k > 0);

                if (b[k-1] != ']') {
                        fprintf(stderr, "[%s:%u] Invalid section header.\n", filename, line);
                        return -EBADMSG;
                }

                if (!(n = strndup(b+1, k-2)))
                        return -ENOMEM;

                if (sections) {
                        const char * const * i;
                        bool good = false;
                        STRV_FOREACH(i, sections)
                                if (streq(*i, n)) {
                                        good = true;
                                        break;
                                }

                        if (!good) {
                                free(n);
                                return -EBADMSG;
                        }
                }

                free(*section);
                *section = n;

                return 0;
        }

        if (!(e = strchr(b, '='))) {
                fprintf(stderr, "[%s:%u] Missing '='.\n", filename, line);
                return -EBADMSG;
        }

        *e = 0;
        e++;

        return next_assignment(filename, line, *section, t, strip(b), strip(e), userdata);
}

/* Go through the file and parse each line */
int config_parse(const char *filename, const char* const * sections, const ConfigItem *t, void *userdata) {
        unsigned line = 0;
        char *section = NULL;
        FILE *f;
        int r;

        assert(filename);
        assert(t);

        if (!(f = fopen(filename, "re"))) {
                r = -errno;
                fprintf(stderr, "Failed to open configuration file '%s': %s\n", filename, strerror(-r));
                goto finish;
        }

        while (!feof(f)) {
                char l[LINE_MAX];

                if (!fgets(l, sizeof(l), f)) {
                        if (feof(f))
                                break;

                        r = -errno;
                        fprintf(stderr, "Failed to read configuration file '%s': %s\n", filename, strerror(-r));
                        goto finish;
                }

                if ((r = parse_line(filename, ++line, &section, sections, t, l, userdata)) < 0)
                        goto finish;
        }

        r = 0;

finish:
        free(section);

        if (f)
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
                fprintf(stderr, "[%s:%u] Failed to parse numeric value: %s\n", filename, line, rvalue);
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
                fprintf(stderr, "[%s:%u] Failed to parse numeric value: %s\n", filename, line, rvalue);
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
                fprintf(stderr, "[%s:%u] Failed to parse numeric value: %s\n", filename, line, rvalue);
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
                fprintf(stderr, "[%s:%u] Failed to parse boolean value: %s\n", filename, line, rvalue);
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
        FOREACH_WORD(w, &l, rvalue, state)
                k++;

        if (!(n = new(char*, k+1)))
                return -ENOMEM;

        for (k = 0; (*sv)[k]; k++)
                n[k] = (*sv)[k];
        FOREACH_WORD(w, &l, rvalue, state)
                if (!(n[k++] = strndup(w, l)))
                        goto fail;

        n[k] = NULL;
        free(*sv);
        *sv = n;

        return 0;

fail:
        for (; k > 0; k--)
                free(n[k-1]);

        return -ENOMEM;
}
