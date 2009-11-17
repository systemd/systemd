/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foostrvhfoo
#define foostrvhfoo

#include "macro.h"

char *strv_find(char **l, const char *name);
void strv_free(char **l);
char **strv_copy(char **l);
unsigned strv_length(char **l);

char **strv_new(const char *x, ...) __sentinel;

#define STRV_FOREACH(s, l)                      \
        for ((s) = (l); (l) && *(s); (s)++)

#define STRV_FOREACH_BACKWARDS(s, l)            \
        for (; (l) && ((s) >= (l)); (s)--)

#endif
