/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "util.h"
#include "strv.h"

char *strv_find(char **l, const char *name) {
        assert(l);
        assert(name);

        for (; *l; l++)
                if (streq(*l, name))
                        return *l;

        return NULL;
}

void strv_free(char **l) {
        char **k;

        if (!l)
                return;

        for (k = l; *k; k++)
                free(*k);

        free(l);
}

char **strv_copy(char **l) {
        char **r, **k;

        if (!(r = new(char*, strv_length(l)+1)))
                return NULL;

        for (k = r; *l; k++, l++)
                if (!(*k = strdup(*l)))
                        goto fail;

        *k = NULL;
        return r;

fail:
        for (k--, l--; k >= r; k--, l--)
                free(*k);

        return NULL;
}

unsigned strv_length(char **l) {
        unsigned n = 0;

        if (!l)
                return 0;

        for (; *l; l++)
                n++;

        return n;
}

char **strv_new(const char *x, ...) {
        const char *s;
        char **a;
        unsigned n = 0, i = 0;
        va_list ap;

        if (x) {
                n = 1;

                va_start(ap, x);

                while (va_arg(ap, const char*))
                        n++;

                va_end(ap);
        }

        if (!(a = new(char*, n+1)))
                return NULL;

        if (x) {
                if (!(a[i] = strdup(x))) {
                        free(a);
                        return NULL;
                }

                i++;

                va_start(ap, x);

                while ((s = va_arg(ap, const char*))) {
                        if (!(a[i] = strdup(s)))
                                goto fail;

                        i++;
                }

                va_end(ap);
        }

        a[i] = NULL;
        return a;

fail:

        for (; i > 0; i--)
                if (a[i-1])
                        free(a[i-1]);

        free(a);
        return NULL;
}
