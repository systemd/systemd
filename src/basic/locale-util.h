/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <locale.h>     /* IWYU pragma: export */

#include "forward.h"

typedef enum LocaleVariable {
        /* We don't list LC_ALL here on purpose. People should be
         * using LANG instead. */

        VARIABLE_LANG,
        VARIABLE_LANGUAGE,
        VARIABLE_LC_CTYPE,
        VARIABLE_LC_NUMERIC,
        VARIABLE_LC_TIME,
        VARIABLE_LC_COLLATE,
        VARIABLE_LC_MONETARY,
        VARIABLE_LC_MESSAGES,
        VARIABLE_LC_PAPER,
        VARIABLE_LC_NAME,
        VARIABLE_LC_ADDRESS,
        VARIABLE_LC_TELEPHONE,
        VARIABLE_LC_MEASUREMENT,
        VARIABLE_LC_IDENTIFICATION,
        _VARIABLE_LC_MAX,
        _VARIABLE_LC_INVALID = -EINVAL,
} LocaleVariable;

int get_locales(char ***l);
bool locale_is_valid(const char *name);
int locale_is_installed(const char *name);

#define _(String) dgettext(GETTEXT_PACKAGE, String)
#define N_(String) String

bool is_locale_utf8(void);

const char* locale_variable_to_string(LocaleVariable i) _const_;
LocaleVariable locale_variable_from_string(const char *s) _pure_;

static inline void freelocalep(locale_t *p) {
        if (*p == (locale_t) 0)
                return;

        freelocale(*p);
}

void locale_variables_free(char* l[_VARIABLE_LC_MAX]);
static inline void locale_variables_freep(char*(*l)[_VARIABLE_LC_MAX]) {
        locale_variables_free(*l);
}
void locale_variables_simplify(char *l[_VARIABLE_LC_MAX]);
