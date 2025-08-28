/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "glyph-util.h"
#include "log.h"
#include "macro.h"
#include "parse-util.h"
#include "prompt-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"

static int get_completions(
                const char *key,
                char ***ret_list,
                void *userdata) {

        int r;

        if (!userdata) {
                *ret_list = NULL;
                return 0;
        }

        _cleanup_strv_free_ char **copy = strv_copy(userdata);
        if (!copy)
                return -ENOMEM;

        r = strv_extend(&copy, "list");
        if (r < 0)
                return r;

        *ret_list = TAKE_PTR(copy);
        return 0;
}

int prompt_loop(
                const char *text,
                Glyph emoji,
                char **menu,        /* if non-NULL: choices to suggest */
                char **accepted,    /* if non-NULL: choices to accept (should be a superset of 'menu') */
                unsigned ellipsize_percentage,
                size_t n_columns,
                size_t column_width,
                bool (*is_valid)(const char *name, void *userdata),
                int (*refresh)(char ***ret_menu, char ***ret_accepted, void *userdata),
                void *userdata,
                PromptFlags flags,
                char **ret) {

        _cleanup_strv_free_ char **refreshed_menu = NULL, **refreshed_accepted = NULL;
        int r;

        assert(text);
        assert(ret);

        /* If requested show menu right-away */
        if (FLAGS_SET(flags, PROMPT_SHOW_MENU_NOW) && !strv_isempty(menu)) {
                r = show_menu(menu,
                              n_columns,
                              column_width,
                              ellipsize_percentage,
                              /* grey_prefix= */ NULL,
                              /* with_numbers= */ true);
                if (r < 0)
                        return log_error_errno(r, "Failed to show menu: %m");

                putchar('\n');
        }

        for (;;) {
                _cleanup_free_ char *a = NULL;

                if (!FLAGS_SET(flags, PROMPT_HIDE_MENU_HINT) && !strv_isempty(menu))
                        if (!strextend_with_separator(&a, ", ", "\"list\" to list options"))
                                return log_oom();
                if (!FLAGS_SET(flags, PROMPT_HIDE_SKIP_HINT) && FLAGS_SET(flags, PROMPT_MAY_SKIP))
                        if (!strextend_with_separator(&a, ", ", "empty to skip"))
                                return log_oom();

                if (a) {
                        char *b;

                        b = strjoin(" (", a, ")");
                        if (!b)
                                return log_oom();

                        free_and_replace(a, b);
                }

                _cleanup_free_ char *p = NULL;
                r = ask_string_full(
                                &p,
                                get_completions,
                                accepted ?: menu,
                                "%s%s%s%s: ",
                                emoji >= 0 ? glyph(emoji) : "",
                                emoji >= 0 ? " " : "",
                                text,
                                strempty(a));
                if (r < 0)
                        return log_error_errno(r, "Failed to query user: %m");

                if (isempty(p)) {
                        if (FLAGS_SET(flags, PROMPT_MAY_SKIP)) {
                                log_info("No data entered, skipping.");
                                *ret = NULL;
                                return 0;
                        }

                        log_info("No data entered, try again.");
                        continue;
                }

                /* NB: here we treat non-NULL but empty list different from NULL list. In the former case we
                 * support the "list" command, in the latter we don't. */
                if (FLAGS_SET(flags, PROMPT_SHOW_MENU) && streq(p, "list")) {
                        putchar('\n');

                        if (refresh) {
                                _cleanup_strv_free_ char **rm = NULL, **ra = NULL;

                                /* If a refresh method is provided, then use it now to refresh the menu
                                 * before redisplaying it. */
                                r = refresh(&rm, &ra, userdata);
                                if (r < 0)
                                        return r;

                                strv_free_and_replace(refreshed_menu, rm);
                                strv_free_and_replace(refreshed_accepted, ra);

                                menu = refreshed_menu;
                                accepted = refreshed_accepted;
                        }

                        if (strv_isempty(menu)) {
                                log_warning("No entries known.");
                                continue;
                        }

                        r = show_menu(menu,
                                      n_columns,
                                      column_width,
                                      ellipsize_percentage,
                                      /* grey_prefix= */ NULL,
                                      /* with_numbers= */ true);
                        if (r < 0)
                                return log_error_errno(r, "Failed to show menu: %m");

                        putchar('\n');
                        continue;
                }

                unsigned u;
                r = safe_atou(p, &u);
                if (r >= 0) {
                        if (u <= 0 || u > strv_length(menu)) {
                                log_error("Specified entry number out of range.");
                                continue;
                        }

                        log_info("Selected '%s'.", menu[u-1]);
                        r = strdup_to(ret, menu[u-1]);
                        if (r < 0)
                                return r;
                        return 1;
                }
                bool good =
                        (!accepted || strv_find(accepted, p)) &&
                        (!is_valid || is_valid(p, userdata));

                if (good) {
                        *ret = TAKE_PTR(p);
                        return 1;
                }

                /* Be more helpful to the user, and give a hint what the user might have wanted to type. */
                const char *best_match = strv_find_closest(accepted ?: menu, p);
                if (best_match)
                        log_error("Invalid input '%s', did you mean '%s'?", p, best_match);
                else
                        log_error("Invalid input '%s'.", p);
        }
}
