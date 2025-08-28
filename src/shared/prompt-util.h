/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdbool.h>

#include "forward.h"

typedef enum PromptFlags {
        PROMPT_MAY_SKIP       = 1 << 0, /* Question may be skipped */
        PROMPT_SHOW_MENU      = 1 << 1, /* Show menu list on "list" */
        PROMPT_SHOW_MENU_NOW  = 1 << 2, /* Show menu list right away, rather than only on request */
        PROMPT_HIDE_MENU_HINT = 1 << 3, /* Don't show hint regarding "list" */
        PROMPT_HIDE_SKIP_HINT = 1 << 4, /* Don't show hint regarding skipping */
} PromptFlags;

int prompt_loop(
                const char *text,
                Glyph emoji,
                char **menu,
                char **accepted,
                unsigned ellipsize_percentage,
                size_t n_columns,
                size_t column_width,
                bool (*is_valid)(const char *name, void *userdata),
                void *userdata,
                PromptFlags flags,
                char **ret);
