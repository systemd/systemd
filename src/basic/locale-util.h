/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <libintl.h>    /* IWYU pragma: export */
#include <locale.h>     /* IWYU pragma: export */

#include "sd-dlopen.h"  /* IWYU pragma: export */

#include "basic-forward.h"
#include "dlfcn-util.h"

/* format_arg(2) propagates the format-string nature of the second argument to the return value, so that
 * printf(_("Hello %s"), name) still gets checked. It survives both DLSYM_PROTOTYPE's typeof() and the
 * ternary in _() below — verified on gcc and clang. */
extern DLSYM_PROTOTYPE(dgettext) __attribute__((format_arg(2)));

int dlopen_libintl(int log_level);

#ifdef __GLIBC__
#define DLOPEN_LIBINTL(log_level, priority) dlopen_libintl(log_level)
#else
#define LIBINTL_NOTE(priority)                                          \
        SD_ELF_NOTE_DLOPEN("intl",                                      \
                           "Support for message translation via gettext", \
                           priority,                                    \
                           "libintl.so.8")

#define DLOPEN_LIBINTL(log_level, priority)                             \
        ({                                                              \
                LIBINTL_NOTE(priority);                                 \
                dlopen_libintl(log_level);                              \
        })
#endif

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

int get_locales(char ***ret);
bool locale_is_valid(const char *name);
int locale_is_installed(const char *name);

/* Falls back to the untranslated string if dlopen_libintl() hasn't run or has failed, so callers don't have
 * to gate every translatable message on a runtime check. */
#define _(String) (sym_dgettext ? sym_dgettext(GETTEXT_PACKAGE, (String)) : (String))
#define N_(String) String

bool is_locale_utf8(void);

DECLARE_STRING_TABLE_LOOKUP(locale_variable, LocaleVariable);

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
