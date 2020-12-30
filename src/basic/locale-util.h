/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <libintl.h>
#include <stdbool.h>
#include <locale.h>

#include "macro.h"

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

#define _(String) gettext(String)
#define N_(String) String
void init_gettext(void);

bool is_locale_utf8(void);

typedef enum {
        SPECIAL_GLYPH_TREE_VERTICAL,
        SPECIAL_GLYPH_TREE_BRANCH,
        SPECIAL_GLYPH_TREE_RIGHT,
        SPECIAL_GLYPH_TREE_SPACE,
        SPECIAL_GLYPH_TRIANGULAR_BULLET,
        SPECIAL_GLYPH_BLACK_CIRCLE,
        SPECIAL_GLYPH_WHITE_CIRCLE,
        SPECIAL_GLYPH_MULTIPLICATION_SIGN,
        SPECIAL_GLYPH_CIRCLE_ARROW,
        SPECIAL_GLYPH_BULLET,
        SPECIAL_GLYPH_MU,
        SPECIAL_GLYPH_CHECK_MARK,
        SPECIAL_GLYPH_CROSS_MARK,
        SPECIAL_GLYPH_ARROW,
        SPECIAL_GLYPH_ELLIPSIS,
        SPECIAL_GLYPH_LIGHT_SHADE,
        SPECIAL_GLYPH_DARK_SHADE,
        SPECIAL_GLYPH_SIGMA,
        SPECIAL_GLYPH_EXTERNAL_LINK,
        _SPECIAL_GLYPH_FIRST_EMOJI,
        SPECIAL_GLYPH_ECSTATIC_SMILEY = _SPECIAL_GLYPH_FIRST_EMOJI,
        SPECIAL_GLYPH_HAPPY_SMILEY,
        SPECIAL_GLYPH_SLIGHTLY_HAPPY_SMILEY,
        SPECIAL_GLYPH_NEUTRAL_SMILEY,
        SPECIAL_GLYPH_SLIGHTLY_UNHAPPY_SMILEY,
        SPECIAL_GLYPH_UNHAPPY_SMILEY,
        SPECIAL_GLYPH_DEPRESSED_SMILEY,
        SPECIAL_GLYPH_LOCK_AND_KEY,
        SPECIAL_GLYPH_TOUCH,
        _SPECIAL_GLYPH_MAX,
} SpecialGlyph;

const char *special_glyph(SpecialGlyph code) _const_;

bool emoji_enabled(void);

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

static inline const char *special_glyph_check_mark(bool b) {
        return b ? special_glyph(SPECIAL_GLYPH_CHECK_MARK) : special_glyph(SPECIAL_GLYPH_CROSS_MARK);
}
