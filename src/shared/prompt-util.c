/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include <sd-varlink.h>

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

        assert(ret_list);

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
                int (*is_valid)(const char *name, void *userdata),
                int (*refresh)(char ***ret_menu, char ***ret_accepted, void *userdata),
                void *userdata,
                PromptFlags flags,
                char **ret) {

        _cleanup_strv_free_ char **refreshed_menu = NULL, **refreshed_accepted = NULL;
        int r;

        assert(text);
        assert(ret);

        if (!emoji_enabled()) /* If emojis aren't available, simpler unicode chars might still be around,
                               * hence try to downgrade. (Consider the Linux Console!) */
                emoji = GLYPH_TRIANGULAR_BULLET;

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
                        char *b = strjoin(" (", a, ")");
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
                if (safe_atou(p, &u) >= 0) {
                        if (u <= 0 || u > strv_length(menu)) {
                                log_error("Specified entry number out of range.");
                                continue;
                        }

                        log_info("Selected '%s'.", menu[u-1]);
                        return strdup_to_full(ret, menu[u-1]);
                }

                bool good = accepted ? strv_contains(accepted, p) : true;
                if (good && is_valid) {
                        r = is_valid(p, userdata);
                        if (r < 0)
                                return r;

                        good = good && r;
                }
                if (good) {
                        *ret = TAKE_PTR(p);
                        return 1;
                }

                if (!FLAGS_SET(flags, PROMPT_SILENT_VALIDATE)) {
                        /* Be more helpful to the user, and give a hint what the user might have wanted to type. */
                        const char *best_match = strv_find_closest(accepted ?: menu, p);
                        if (best_match)
                                log_error("Invalid input '%s', did you mean '%s'?", p, best_match);
                        else
                                log_error("Invalid input '%s'.", p);
                }
        }
}

/* Default: bright white on blue background */
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
        if (n < 12) /* Do not bother with the chrome on tiny screens */
                return 0;

        _cleanup_free_ char *b = NULL, *ansi_color_reverse = NULL;
        if (!bottom) {
                _cleanup_free_ char *pretty_name = NULL, *os_name = NULL, *ansi_color = NULL, *documentation_url = NULL;

                r = parse_os_release(
                                /* root= */ NULL,
                                "PRETTY_NAME",        &pretty_name,
                                "NAME",               &os_name,
                                "ANSI_COLOR",         &ansi_color,
                                "ANSI_COLOR_REVERSE", &ansi_color_reverse,
                                "DOCUMENTATION_URL",  &documentation_url);
                if (r < 0)
                        log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                                       "Failed to read os-release file, ignoring: %m");

                const char *m = os_release_pretty_name(pretty_name, os_name);
                const char *c = ansi_color ?: "0";

                if (ansi_color_reverse) {
                        _cleanup_free_ char *j = strjoin("\x1B[0;", ansi_color_reverse, "m");
                        if (!j)
                                return log_oom_debug();

                        free_and_replace(ansi_color_reverse, j);
                }

                if (asprintf(&b, "\x1B[0;%sm %s %s", c, m, ansi_color_reverse ?: ANSI_COLOR_CHROME) < 0)
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

        const char *chrome_color = ansi_color_reverse ?: ANSI_COLOR_CHROME;

        WITH_BUFFERED_STDOUT;

        fputs("\033[H"    /* move home */
              "\033[2J",  /* clear screen */
              stdout);

        /* Blue bar on top (followed by one empty regular one) */
        printf("\x1B[1;1H" /* jump to top left */
               "%1$s" ANSI_ERASE_TO_END_OF_LINE "\n"
               "%1$s     %2$s" ANSI_ERASE_TO_END_OF_LINE "\n"
               "%1$s" ANSI_ERASE_TO_END_OF_LINE "\n"
               ANSI_NORMAL ANSI_ERASE_TO_END_OF_LINE,
               chrome_color,
               top);

        /* Blue bar on bottom (with one empty regular one before) */
        printf("\x1B[%1$u;1H" /* jump to bottom left, above the blue bar */
               ANSI_NORMAL ANSI_ERASE_TO_END_OF_LINE "\n"
               "%2$s" ANSI_ERASE_TO_END_OF_LINE "\n"
               "%2$s    %3$s" ANSI_ERASE_TO_END_OF_LINE "\n"
               "%2$s" ANSI_ERASE_TO_END_OF_LINE ANSI_NORMAL,
               n - 3,
               chrome_color,
               bottom);

        /* Reduce scrolling area (DECSTBM), cutting off top and bottom bars */
        printf("\x1B[5;%ur", n - 4);

        /* Position cursor in fifth line */
        fputs("\x1B[5;1H", stdout);

        fflush(stdout);

        chrome_visible = n;
        return 1;
}

void chrome_hide(void) {
        int r;

        if (chrome_visible == 0)
                return;

        unsigned n = chrome_visible;
        chrome_visible = 0;

        unsigned saved_row = 0;
        r = terminal_get_cursor_position(STDIN_FILENO, STDOUT_FILENO, &saved_row, /* ret_column= */ NULL);
        if (r < 0)
                return (void) log_debug_errno(r, "Failed to get terminal cursor position, skipping chrome hiding: %m");

        WITH_BUFFERED_STDOUT;

        /* Erase Blue bar on bottom */
        assert(n >= 2);
        printf("\x1B[%u;1H"
               ANSI_NORMAL ANSI_ERASE_TO_END_OF_LINE "\n"
               ANSI_NORMAL ANSI_ERASE_TO_END_OF_LINE "\n"
               ANSI_NORMAL ANSI_ERASE_TO_END_OF_LINE,
               n - 2);

        /* Reset scrolling area (DECSTBM) */
        fputs("\x1B[r\n", stdout);

        /* Place the cursor where it was again, but not in the former blue bars */
        assert(n >= 9);
        unsigned k = CLAMP(saved_row, 5U, n - 4);
        printf("\x1B[%u;1H", k);

        fflush(stdout);
}

static int vl_on_reply(sd_varlink *link, sd_json_variant *parameters, const char *error_id, sd_varlink_reply_flags_t flags, void *userdata) {
        assert(link);

        /* We want to keep the link around (since its lifetime defines the lifetime of the console muting),
         * hence let's detach it from the event loop now, and then exit the event loop. */

        _cleanup_(sd_event_unrefp) sd_event *e = sd_event_ref(ASSERT_PTR(sd_varlink_get_event(link)));
        sd_varlink_detach_event(link);
        (void) sd_event_exit(e, (error_id || !FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES)) ? -EBADR : 0);

        return 0;
}

int mute_console(sd_varlink **ret_link) {
        int r;

        assert(ret_link);

        /* Talks to the MuteConsole service, and asks for output to the console to be muted, as long as the
         * connection is retained */

        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *link = NULL;
        r = sd_varlink_connect_address(&link, "/run/systemd/io.systemd.MuteConsole");
        if (r < 0)
                return log_debug_errno(r, "Failed to connect to console muting service: %m");

        _cleanup_(sd_event_unrefp) sd_event* event = NULL;
        r = sd_event_new(&event);
        if (r < 0)
                return r;

        r = sd_varlink_attach_event(link, event, /* priority= */ 0);
        if (r < 0)
                return r;

        r = sd_varlink_bind_reply(link, vl_on_reply);
        if (r < 0)
                return r;

        r = sd_varlink_set_relative_timeout(link, UINT64_MAX);
        if (r < 0)
                return log_debug_errno(r, "Failed to disable method call time-out: %m");

        r = sd_varlink_observe(link, "io.systemd.MuteConsole.Mute", /* parameters= */ NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to issue Mute() call to io.systemd.MuteConsole: %m");

        /* Now run the event loop, it will exit on the first reply, which is when we know the console output
         * is now muted. */
        r = sd_event_loop(event);
        if (r < 0)
                return r;

        *ret_link = TAKE_PTR(link);
        return 0;
}
