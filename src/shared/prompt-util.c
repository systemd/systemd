/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "glyph-util.h"
#include "log.h"
#include "macro.h"
#include "os-util.h"
#include "parse-util.h"
#include "pretty-print.h"
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
                void *userdata,
                PromptFlags flags,
                char **ret) {

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
                                "%s %s%s%s%s: ",
                                glyph(GLYPH_TRIANGULAR_BULLET),
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
                        (accepted && strv_find(accepted, p)) &&
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

/* Bright white on blue background */
#define ANSI_COLOR_CHROME "\x1B[0;44;1;37m"

static unsigned chrome_visible = 0; /* if non-zero chrome is visible and value is saved number of lines */

int chrome_show(
                const char *top,
                const char *bottom) {
        int r;

        assert(top);

        /* Shows our "chrome", i.e. a blue bar at top and bottom. Reduces the scrolling area to the area in
         * between */

        if (terminal_is_dumb())
                return 0;

        unsigned n = lines();
        if (n < 12)
                return 0;

        _cleanup_free_ char *b = NULL;
        if (!bottom) {
                _cleanup_free_ char *pretty_name = NULL, *os_name = NULL, *ansi_color = NULL, *documentation_url = NULL;

                r = parse_os_release(
                                /* root= */ NULL,
                                "PRETTY_NAME",       &pretty_name,
                                "NAME",              &os_name,
                                "ANSI_COLOR",        &ansi_color,
                                "DOCUMENTATION_URL", &documentation_url);
                if (r < 0)
                        log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                                       "Failed to read os-release file, ignoring: %m");

                const char *m = os_release_pretty_name(pretty_name, os_name);
                const char *c = ansi_color ?: "0";

                if (asprintf(&b, "\x1B[0;%sm %s " ANSI_COLOR_CHROME, c, m) < 0)
                        return log_oom_debug();

                if (documentation_url) {
                        _cleanup_free_ char *u = NULL;
                        if (terminal_urlify(documentation_url, "documentation", &u) < 0)
                                return log_oom_debug();

                        if (!strextend(&b, " - See ", u, " for more information."))
                                return log_oom_debug();
                }

                bottom = b;
        }

        WITH_BUFFERED_STDOUT;

        /* Add three empty lines to the end, but go back */
        fputs("\n\n\n\x1B[3F", stdout);
        fflush(stdout);

        /* Remember where we are right now */
        unsigned saved_row = 0;
        r = terminal_get_cursor_position(STDIN_FILENO, STDOUT_FILENO, &saved_row, /* ret_column= */ NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to get terminal cursor position, skipping chrome generation: %m");

        /* Blue bar on top (followed by one empty regular one) */
        printf("\x1B[1;1H"
               ANSI_COLOR_CHROME ANSI_ERASE_TO_END_OF_LINE "\n"
               ANSI_COLOR_CHROME "    %s" ANSI_ERASE_TO_END_OF_LINE "\n"
               ANSI_COLOR_CHROME ANSI_ERASE_TO_END_OF_LINE "\n"
               ANSI_NORMAL ANSI_ERASE_TO_END_OF_LINE,
               top);

        /* Blue bar on bottom (with one empty regular one before) */
        printf("\x1B[%u;1H"
               ANSI_NORMAL ANSI_ERASE_TO_END_OF_LINE "\n"
               ANSI_COLOR_CHROME ANSI_ERASE_TO_END_OF_LINE "\n"
               ANSI_COLOR_CHROME "    %s" ANSI_ERASE_TO_END_OF_LINE "\n"
               ANSI_COLOR_CHROME ANSI_ERASE_TO_END_OF_LINE ANSI_NORMAL,
               n - 3,
               bottom);

        /* Reduce scrolling area, cutting off top and bottom bars */
        printf("\x1B[5;%ur\n", n - 4);
        fflush(stdout);

        /* Place cursor again where it was, but keep it out of the blue bars. */
        unsigned k = CLAMP(saved_row, 5U, n - 4);
        (void) terminal_set_cursor_position(STDOUT_FILENO, k, 1);

        chrome_visible = n;
        return 1;
}

void chrome_hide(void) {
        int r;

        if (chrome_visible == 0)
                return;

        unsigned n = chrome_visible;
        chrome_visible = 0;

        WITH_BUFFERED_STDOUT;

        unsigned saved_row = 0;
        r = terminal_get_cursor_position(STDIN_FILENO, STDOUT_FILENO, &saved_row, /* ret_column= */ NULL);
        if (r < 0)
                return (void) log_debug_errno(r, "Failed to get terminal cursor position, skipping chrome hiding: %m");

        /* Erase Blue bar on top */
        fputs("\x1B[1;1H"
              ANSI_NORMAL ANSI_ERASE_TO_END_OF_LINE "\n"
              ANSI_NORMAL ANSI_ERASE_TO_END_OF_LINE "\n"
              ANSI_NORMAL ANSI_ERASE_TO_END_OF_LINE ANSI_NORMAL,
              stdout);

        /* Erase Blue bar on bottom */
        printf("\x1B[%u;1H"
               ANSI_NORMAL ANSI_ERASE_TO_END_OF_LINE "\n"
               ANSI_NORMAL ANSI_ERASE_TO_END_OF_LINE "\n"
               ANSI_NORMAL ANSI_ERASE_TO_END_OF_LINE ANSI_NORMAL,
               n - 2);

        /* Reset scrolling area*/
        fputs("\x1B[r\n", stdout);
        fflush(stdout);

        /* Place the cursor where it was again, but not in the (former blue bars) */
        unsigned k = CLAMP(saved_row, 5U, n - 4);
        (void) terminal_set_cursor_position(STDOUT_FILENO, k, 1);
}
