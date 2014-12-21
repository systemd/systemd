/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2014 David Herrmann <dh.herrmann@gmail.com>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

/*
 * Terminal Screens
 * The term_screen layer implements the terminal-side. It handles all commands
 * returned by the seq-parser and applies them to its own pages.
 *
 * While there are a lot of legacy control-sequences, we only support a small
 * subset. There is no reason to implement unused codes like horizontal
 * scrolling.
 * If you implement new commands, make sure to document them properly.
 *
 * Standards:
 *   ECMA-48
 *   ANSI X3.64
 *   ISO/IEC 6429
 * References:
 *   http://www.vt100.net/emu/ctrlseq_dec.html
 *   http://www.vt100.net/docs/vt100-ug/chapter3.html
 *   http://www.vt100.net/docs/vt510-rm/chapter4
 *   http://www.vt100.net/docs/vt510-rm/contents
 *   http://invisible-island.net/xterm/ctlseqs/ctlseqs.html
 *   ASCII
 *   http://en.wikipedia.org/wiki/C0_and_C1_control_codes
 *   https://en.wikipedia.org/wiki/ANSI_color
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <xkbcommon/xkbcommon-keysyms.h>
#include "macro.h"
#include "term-internal.h"
#include "util.h"
#include "utf8.h"

int term_screen_new(term_screen **out, term_screen_write_fn write_fn, void *write_fn_data, term_screen_cmd_fn cmd_fn, void *cmd_fn_data) {
        _cleanup_(term_screen_unrefp) term_screen *screen = NULL;
        int r;

        assert_return(out, -EINVAL);

        screen = new0(term_screen, 1);
        if (!screen)
                return -ENOMEM;

        screen->ref = 1;
        screen->age = 1;
        screen->write_fn = write_fn;
        screen->write_fn_data = write_fn_data;
        screen->cmd_fn = cmd_fn;
        screen->cmd_fn_data = cmd_fn_data;
        screen->flags = TERM_FLAG_7BIT_MODE;
        screen->conformance_level = TERM_CONFORMANCE_LEVEL_VT400;
        screen->g0 = &term_unicode_lower;
        screen->g1 = &term_unicode_upper;
        screen->g2 = &term_unicode_lower;
        screen->g3 = &term_unicode_upper;
        screen->state.gl = &screen->g0;
        screen->state.gr = &screen->g1;
        screen->saved = screen->state;
        screen->saved_alt = screen->saved;

        r = term_page_new(&screen->page_main);
        if (r < 0)
                return r;

        r = term_page_new(&screen->page_alt);
        if (r < 0)
                return r;

        r = term_parser_new(&screen->parser, false);
        if (r < 0)
                return r;

        r = term_history_new(&screen->history_main);
        if (r < 0)
                return r;

        screen->page = screen->page_main;
        screen->history = screen->history_main;

        *out = screen;
        screen = NULL;
        return 0;
}

term_screen *term_screen_ref(term_screen *screen) {
        if (!screen)
                return NULL;

        assert_return(screen->ref > 0, NULL);

        ++screen->ref;
        return screen;
}

term_screen *term_screen_unref(term_screen *screen) {
        if (!screen)
                return NULL;

        assert_return(screen->ref > 0, NULL);

        if (--screen->ref)
                return NULL;

        free(screen->answerback);
        free(screen->tabs);
        term_history_free(screen->history_main);
        term_page_free(screen->page_alt);
        term_page_free(screen->page_main);
        term_parser_free(screen->parser);
        free(screen);

        return NULL;
}

/*
 * Write-Helpers
 * Unfortunately, 7bit/8bit compat mode requires us to send C1 controls encoded
 * as 7bit if asked by the application. This is really used in the wild, so we
 * cannot fall back to "always 7bit".
 * screen_write() is the underlying backend which forwards any writes to the
 * users's callback. It's the users responsibility to buffer these and write
 * them out once their call to term_screen_feed_*() returns.
 * The SEQ_WRITE() and SEQ_WRITE_KEY() macros allow constructing C0/C1 sequences
 * directly in the code-base without requiring any intermediate buffer during
 * runtime.
 */

#define C0_CSI "\e["
#define C1_CSI "\x9b"

#define SEQ(_screen, _prefix_esc, _c0, _c1, _seq) \
                (((_screen)->flags & TERM_FLAG_7BIT_MODE) ? \
                        ((_prefix_esc) ? ("\e" _c0 _seq) : (_c0 _seq)) : \
                        ((_prefix_esc) ? ("\e" _c1 _seq) : (_c1 _seq)))

#define SEQ_SIZE(_screen, _prefix_esc, _c0, _c1, _seq) \
                (((_screen)->flags & TERM_FLAG_7BIT_MODE) ? \
                        ((_prefix_esc) ? sizeof("\e" _c0 _seq) : sizeof(_c0 _seq)) : \
                        ((_prefix_esc) ? sizeof("\e" _c1 _seq) : sizeof(_c1 _seq)))

#define SEQ_WRITE_KEY(_screen, _prefix_esc, _c0, _c1, _seq) \
                screen_write((_screen), \
                             SEQ((_screen), (_prefix_esc), \
                                 _c0, _c1, _seq), \
                             SEQ_SIZE((_screen), (_prefix_esc), \
                                     _c0, _c1, _seq) - 1)

#define SEQ_WRITE(_screen, _c0, _c1, _seq) \
                SEQ_WRITE_KEY((_screen), false, _c0, _c1, _seq)

static int screen_write(term_screen *screen, const void *buf, size_t len) {
        if (len < 1 || !screen->write_fn)
                return 0;

        return screen->write_fn(screen, screen->write_fn_data, buf, len);
}

/*
 * Command Forwarding
 * Some commands cannot be handled by the screen-layer directly. Those are
 * forwarded to the command-handler of the caller. This is rarely used and can
 * safely be set to NULL.
 */

static int screen_forward(term_screen *screen, unsigned int cmd, const term_seq *seq) {
        if (!screen->cmd_fn)
                return 0;

        return screen->cmd_fn(screen, screen->cmd_fn_data, cmd, seq);
}

/*
 * Screen Helpers
 * These helpers implement common-operations like cursor-handler and more, which
 * are used by several command dispatchers.
 */

static unsigned int screen_clamp_x(term_screen *screen, unsigned int x) {
        if (x >= screen->page->width)
                return (screen->page->width > 0) ? screen->page->width - 1 : 0;

        return x;
}

static unsigned int screen_clamp_y(term_screen *screen, unsigned int y) {
        if (y >= screen->page->height)
                return (screen->page->height > 0) ? screen->page->height - 1 : 0;

        return y;
}

static bool screen_tab_is_set(term_screen *screen, unsigned int pos) {
        if (pos >= screen->page->width)
                return false;

        return screen->tabs[pos / 8] & (1 << (pos % 8));
}

static inline void screen_age_cursor(term_screen *screen) {
        term_cell *cell;

        cell = term_page_get_cell(screen->page, screen->state.cursor_x, screen->state.cursor_y);
        if (cell)
                cell->age = screen->age;
}

static void screen_cursor_clear_wrap(term_screen *screen) {
        screen->flags &= ~TERM_FLAG_PENDING_WRAP;
}

static void screen_cursor_set(term_screen *screen, unsigned int x, unsigned int y) {
        x = screen_clamp_x(screen, x);
        y = screen_clamp_y(screen, y);

        if (x == screen->state.cursor_x && y == screen->state.cursor_y)
                return;

        if (!(screen->flags & TERM_FLAG_HIDE_CURSOR))
                screen_age_cursor(screen);

        screen->state.cursor_x = x;
        screen->state.cursor_y = y;

        if (!(screen->flags & TERM_FLAG_HIDE_CURSOR))
                screen_age_cursor(screen);
}

static void screen_cursor_set_rel(term_screen *screen, unsigned int x, unsigned int y) {
        if (screen->state.origin_mode) {
                x = screen_clamp_x(screen, x);
                y = screen_clamp_x(screen, y) + screen->page->scroll_idx;

                if (y >= screen->page->scroll_idx + screen->page->scroll_num) {
                        y = screen->page->scroll_idx + screen->page->scroll_num;
                        if (screen->page->scroll_num > 0)
                                y -= 1;
                }
        }

        screen_cursor_set(screen, x, y);
}

static void screen_cursor_left(term_screen *screen, unsigned int num) {
        if (num > screen->state.cursor_x)
                num = screen->state.cursor_x;

        screen_cursor_set(screen, screen->state.cursor_x - num, screen->state.cursor_y);
}

static void screen_cursor_left_tab(term_screen *screen, unsigned int num) {
        unsigned int i;

        i = screen->state.cursor_x;
        while (i > 0 && num > 0) {
                if (screen_tab_is_set(screen, --i))
                        --num;
        }

        screen_cursor_set(screen, i, screen->state.cursor_y);
}

static void screen_cursor_right(term_screen *screen, unsigned int num) {
        if (num > screen->page->width)
                num = screen->page->width;

        screen_cursor_set(screen, screen->state.cursor_x + num, screen->state.cursor_y);
}

static void screen_cursor_right_tab(term_screen *screen, unsigned int num) {
        unsigned int i;

        i = screen->state.cursor_x;
        while (i + 1 < screen->page->width && num > 0) {
                if (screen_tab_is_set(screen, ++i))
                        --num;
        }

        screen_cursor_set(screen, i, screen->state.cursor_y);
}

static void screen_cursor_up(term_screen *screen, unsigned int num, bool scroll) {
        unsigned int max;

        if (screen->state.cursor_y < screen->page->scroll_idx) {
                if (num > screen->state.cursor_y)
                        num = screen->state.cursor_y;

                screen_cursor_set(screen, screen->state.cursor_x, screen->state.cursor_y - num);
        } else {
                max = screen->state.cursor_y - screen->page->scroll_idx;
                if (num > max) {
                        if (num < 1)
                                return;

                        if (!(screen->flags & TERM_FLAG_HIDE_CURSOR))
                                screen_age_cursor(screen);

                        if (scroll)
                                term_page_scroll_down(screen->page, num - max, &screen->state.attr, screen->age, NULL);

                        screen->state.cursor_y = screen->page->scroll_idx;

                        if (!(screen->flags & TERM_FLAG_HIDE_CURSOR))
                                screen_age_cursor(screen);
                } else {
                        screen_cursor_set(screen, screen->state.cursor_x, screen->state.cursor_y - num);
                }
        }
}

static void screen_cursor_down(term_screen *screen, unsigned int num, bool scroll) {
        unsigned int max;

        if (screen->state.cursor_y >= screen->page->scroll_idx + screen->page->scroll_num) {
                if (num > screen->page->height)
                        num = screen->page->height;

                screen_cursor_set(screen, screen->state.cursor_x, screen->state.cursor_y - num);
        } else {
                max = screen->page->scroll_idx + screen->page->scroll_num - 1 - screen->state.cursor_y;
                if (num > max) {
                        if (num < 1)
                                return;

                        if (!(screen->flags & TERM_FLAG_HIDE_CURSOR))
                                screen_age_cursor(screen);

                        if (scroll)
                                term_page_scroll_up(screen->page, num - max, &screen->state.attr, screen->age, screen->history);

                        screen->state.cursor_y = screen->page->scroll_idx + screen->page->scroll_num - 1;

                        if (!(screen->flags & TERM_FLAG_HIDE_CURSOR))
                                screen_age_cursor(screen);
                } else {
                        screen_cursor_set(screen, screen->state.cursor_x, screen->state.cursor_y + num);
                }
        }
}

static void screen_save_state(term_screen *screen, term_state *where) {
        *where = screen->state;
}

static void screen_restore_state(term_screen *screen, term_state *from) {
        screen_cursor_set(screen, from->cursor_x, from->cursor_y);
        screen->state = *from;
}

static void screen_reset_page(term_screen *screen, term_page *page) {
        term_page_set_scroll_region(page, 0, page->height);
        term_page_erase(page, 0, 0, page->width, page->height, &screen->state.attr, screen->age, false);
}

static void screen_change_alt(term_screen *screen, bool set) {
        if (set) {
                screen->page = screen->page_alt;
                screen->history = NULL;
        } else {
                screen->page = screen->page_main;
                screen->history = screen->history_main;
        }

        screen->page->age = screen->age;
}

static inline void set_reset(term_screen *screen, unsigned int flag, bool set) {
        if (set)
                screen->flags |= flag;
        else
                screen->flags &= ~flag;
}

static void screen_mode_change_ansi(term_screen *screen, unsigned mode, bool set) {
        switch (mode) {
        case 20:
                /*
                 * LNM: line-feed/new-line mode
                 * TODO
                 */
                set_reset(screen, TERM_FLAG_NEWLINE_MODE, set);

                break;
        default:
                log_debug("terminal: failed to %s unknown ANSI mode %u", set ? "set" : "unset", mode);
        }
}

static void screen_mode_change_dec(term_screen *screen, unsigned int mode, bool set) {
        switch (mode) {
        case 1:
                /*
                 * DECCKM: cursor-keys
                 * TODO
                 */
                set_reset(screen, TERM_FLAG_CURSOR_KEYS, set);

                break;
        case 6:
                /*
                 * DECOM: origin-mode
                 * TODO
                 */
                screen->state.origin_mode = set;

                break;
        case 7:
                /*
                 * DECAWN: auto-wrap mode
                 * TODO
                 */
                screen->state.auto_wrap = set;

                break;
        case 25:
                /*
                 * DECTCEM: text-cursor-enable
                 * TODO
                 */
                set_reset(screen, TERM_FLAG_HIDE_CURSOR, !set);
                screen_age_cursor(screen);

                break;
        case 47:
                /*
                 * XTERM-ASB: alternate-screen-buffer
                 * This enables/disables the alternate screen-buffer.
                 * It effectively saves the current page content and
                 * allows you to restore it when changing to the
                 * original screen-buffer again.
                 */
                screen_change_alt(screen, set);

                break;
        case 1047:
                /*
                 * XTERM-ASBPE: alternate-screen-buffer-post-erase
                 * This is the same as XTERM-ASB but erases the
                 * alternate screen-buffer before switching back to the
                 * original buffer. Use it to discard any data on the
                 * alternate screen buffer when done.
                 */
                if (!set)
                        screen_reset_page(screen, screen->page_alt);

                screen_change_alt(screen, set);

                break;
        case 1048:
                /*
                 * XTERM-ASBCS: alternate-screen-buffer-cursor-state
                 * This has the same effect as DECSC/DECRC, but uses a
                 * separate state buffer. It is usually used in
                 * combination with alternate screen buffers to provide
                 * stacked state storage.
                 */
                if (set)
                        screen_save_state(screen, &screen->saved_alt);
                else
                        screen_restore_state(screen, &screen->saved_alt);

                break;
        case 1049:
                /*
                 * XTERM-ASBX: alternate-screen-buffer-extended
                 * This combines XTERM-ASBPE and XTERM-ASBCS somewhat.
                 * When enabling, state is saved, alternate screen
                 * buffer is activated and cleared.
                 * When disabled, alternate screen buffer is cleared,
                 * then normal screen buffer is enabled and state is
                 * restored.
                 */
                if (set)
                        screen_save_state(screen, &screen->saved_alt);

                screen_reset_page(screen, screen->page_alt);
                screen_change_alt(screen, set);

                if (!set)
                        screen_restore_state(screen, &screen->saved_alt);

                break;
        default:
                log_debug("terminal: failed to %s unknown DEC mode %u", set ? "set" : "unset", mode);
        }
}

/* map a character according to current GL and GR maps */
static uint32_t screen_map(term_screen *screen, uint32_t val) {
        uint32_t nval = -1U;

        /* 32 and 127 always map to identity. 160 and 255 map to identity iff a
         * 96 character set is loaded into GR. Values above 255 always map to
         * identity. */
        switch (val) {
        case 33 ... 126:
                if (screen->state.glt) {
                        nval = (**screen->state.glt)[val - 32];
                        screen->state.glt = NULL;
                } else {
                        nval = (**screen->state.gl)[val - 32];
                }
                break;
        case 160 ... 255:
                if (screen->state.grt) {
                        nval = (**screen->state.grt)[val - 160];
                        screen->state.grt = NULL;
                } else {
                        nval = (**screen->state.gr)[val - 160];
                }
                break;
        }

        return (nval == -1U) ? val : nval;
}

/*
 * Command Handlers
 * This is the unofficial documentation of all the TERM_CMD_* definitions. Each
 * handled command has a separate function with an extensive comment on the
 * semantics of the command.
 * Note that many semantics are unknown and need to be verified. This is mostly
 * about error-handling, though. Applications rarely rely on those features.
 */

static int screen_DA1(term_screen *screen, const term_seq *seq);
static int screen_LF(term_screen *screen, const term_seq *seq);

static int screen_GRAPHIC(term_screen *screen, const term_seq *seq) {
        term_char_t ch = TERM_CHAR_NULL;

        if (screen->state.cursor_x + 1 == screen->page->width
            && screen->flags & TERM_FLAG_PENDING_WRAP
            && screen->state.auto_wrap) {
                screen_cursor_down(screen, 1, true);
                screen_cursor_set(screen, 0, screen->state.cursor_y);
        }

        screen_cursor_clear_wrap(screen);

        ch = term_char_merge(ch, screen_map(screen, seq->terminator));
        term_page_write(screen->page, screen->state.cursor_x, screen->state.cursor_y, ch, 1, &screen->state.attr, screen->age, false);

        if (screen->state.cursor_x + 1 == screen->page->width)
                screen->flags |= TERM_FLAG_PENDING_WRAP;
        else
                screen_cursor_right(screen, 1);

        return 0;
}

static int screen_BEL(term_screen *screen, const term_seq *seq) {
        /*
         * BEL - sound bell tone
         * This command should trigger an acoustic bell. Usually, this is
         * forwarded directly to the pcspkr. However, bells have become quite
         * uncommon and annoying, so we're not implementing them here. Instead,
         * it's one of the commands we forward to the caller.
         */

        return screen_forward(screen, TERM_CMD_BEL, seq);
}

static int screen_BS(term_screen *screen, const term_seq *seq) {
        /*
         * BS - backspace
         * Move cursor one cell to the left. If already at the left margin,
         * nothing happens.
         */

        screen_cursor_clear_wrap(screen);
        screen_cursor_left(screen, 1);
        return 0;
}

static int screen_CBT(term_screen *screen, const term_seq *seq) {
        /*
         * CBT - cursor-backward-tabulation
         * Move the cursor @args[0] tabs backwards (to the left). The
         * current cursor cell, in case it's a tab, is not counted.
         * Furthermore, the cursor cannot be moved beyond position 0 and
         * it will stop there.
         *
         * Defaults:
         *   args[0]: 1
         */

        unsigned int num = 1;

        if (seq->args[0] > 0)
                num = seq->args[0];

        screen_cursor_clear_wrap(screen);
        screen_cursor_left_tab(screen, num);

        return 0;
}

static int screen_CHA(term_screen *screen, const term_seq *seq) {
        /*
         * CHA - cursor-horizontal-absolute
         * Move the cursor to position @args[0] in the current line. The
         * cursor cannot be moved beyond the rightmost cell and will stop
         * there.
         *
         * Defaults:
         *   args[0]: 1
         */

        unsigned int pos = 1;

        if (seq->args[0] > 0)
                pos = seq->args[0];

        screen_cursor_clear_wrap(screen);
        screen_cursor_set(screen, pos - 1, screen->state.cursor_y);

        return 0;
}

static int screen_CHT(term_screen *screen, const term_seq *seq) {
        /*
         * CHT - cursor-horizontal-forward-tabulation
         * Move the cursor @args[0] tabs forward (to the right). The
         * current cursor cell, in case it's a tab, is not counted.
         * Furthermore, the cursor cannot be moved beyond the rightmost cell
         * and will stop there.
         *
         * Defaults:
         *   args[0]: 1
         */

        unsigned int num = 1;

        if (seq->args[0] > 0)
                num = seq->args[0];

        screen_cursor_clear_wrap(screen);
        screen_cursor_right_tab(screen, num);

        return 0;
}

static int screen_CNL(term_screen *screen, const term_seq *seq) {
        /*
         * CNL - cursor-next-line
         * Move the cursor @args[0] lines down.
         *
         * TODO: Does this stop at the bottom or cause a scroll-up?
         *
         * Defaults:
         *   args[0]: 1
         */

        unsigned int num = 1;

        if (seq->args[0] > 0)
                num = seq->args[0];

        screen_cursor_clear_wrap(screen);
        screen_cursor_down(screen, num, false);

        return 0;
}

static int screen_CPL(term_screen *screen, const term_seq *seq) {
        /*
         * CPL - cursor-preceding-line
         * Move the cursor @args[0] lines up.
         *
         * TODO: Does this stop at the top or cause a scroll-up?
         *
         * Defaults:
         *   args[0]: 1
         */

        unsigned int num = 1;

        if (seq->args[0] > 0)
                num = seq->args[0];

        screen_cursor_clear_wrap(screen);
        screen_cursor_up(screen, num, false);

        return 0;
}

static int screen_CR(term_screen *screen, const term_seq *seq) {
        /*
         * CR - carriage-return
         * Move the cursor to the left margin on the current line.
         */

        screen_cursor_clear_wrap(screen);
        screen_cursor_set(screen, 0, screen->state.cursor_y);

        return 0;
}

static int screen_CUB(term_screen *screen, const term_seq *seq) {
        /*
         * CUB - cursor-backward
         * Move the cursor @args[0] positions to the left. The cursor stops
         * at the left-most position.
         *
         * Defaults:
         *   args[0]: 1
         */

        unsigned int num = 1;

        if (seq->args[0] > 0)
                num = seq->args[0];

        screen_cursor_clear_wrap(screen);
        screen_cursor_left(screen, num);

        return 0;
}

static int screen_CUD(term_screen *screen, const term_seq *seq) {
        /*
         * CUD - cursor-down
         * Move the cursor @args[0] positions down. The cursor stops at the
         * bottom margin. If it was already moved further, it stops at the
         * bottom line.
         *
         * Defaults:
         *   args[0]: 1
         */

        unsigned int num = 1;

        if (seq->args[0] > 0)
                num = seq->args[0];

        screen_cursor_clear_wrap(screen);
        screen_cursor_down(screen, num, false);

        return 0;
}

static int screen_CUF(term_screen *screen, const term_seq *seq) {
        /*
         * CUF -cursor-forward
         * Move the cursor @args[0] positions to the right. The cursor stops
         * at the right-most position.
         *
         * Defaults:
         *   args[0]: 1
         */

        unsigned int num = 1;

        if (seq->args[0] > 0)
                num = seq->args[0];

        screen_cursor_clear_wrap(screen);
        screen_cursor_right(screen, num);

        return 0;
}

static int screen_CUP(term_screen *screen, const term_seq *seq) {
        /*
         * CUP - cursor-position
         * Moves the cursor to position @args[1] x @args[0]. If either is 0, it
         * is treated as 1. The positions are subject to the origin-mode and
         * clamped to the addressable with/height.
         *
         * Defaults:
         *   args[0]: 1
         *   args[1]: 1
         */

        unsigned int x = 1, y = 1;

        if (seq->args[0] > 0)
                y = seq->args[0];
        if (seq->args[1] > 0)
                x = seq->args[1];

        screen_cursor_clear_wrap(screen);
        screen_cursor_set_rel(screen, x - 1, y - 1);

        return 0;
}

static int screen_CUU(term_screen *screen, const term_seq *seq) {
        /*
         * CUU - cursor-up
         * Move the cursor @args[0] positions up. The cursor stops at the
         * top margin. If it was already moved further, it stops at the
         * top line.
         *
         * Defaults:
         *   args[0]: 1
         *
         */

        unsigned int num = 1;

        if (seq->args[0] > 0)
                num = seq->args[0];

        screen_cursor_clear_wrap(screen);
        screen_cursor_up(screen, num, false);

        return 0;
}

static int screen_DA1(term_screen *screen, const term_seq *seq) {
        /*
         * DA1 - primary-device-attributes
         * The primary DA asks for basic terminal features. We simply return
         * a hard-coded list of features we implement.
         * Note that the primary DA asks for supported features, not currently
         * enabled features.
         *
         * The terminal's answer is:
         *   ^[ ? 64 ; ARGS c
         * The first argument, 64, is fixed and denotes a VT420, the last
         * DEC-term that extended this number.
         * All following arguments denote supported features. Note
         * that at most 15 features can be sent (max CSI args). It is safe to
         * send more, but clients might not be able to parse them. This is a
         * client's problem and we shouldn't care. There is no other way to
         * send those feature lists, so we have to extend them beyond 15 in
         * those cases.
         *
         * Known modes:
         *    1: 132 column mode
         *       The 132 column mode is supported by the terminal.
         *    2: printer port
         *       A priner-port is supported and can be addressed via
         *       control-codes.
         *    3: ReGIS graphics
         *       Support for ReGIS graphics is available. The ReGIS routines
         *       provide the "remote graphics instruction set" and allow basic
         *       vector-rendering.
         *    4: sixel
         *       Support of Sixel graphics is available. This provides access
         *       to the sixel bitmap routines.
         *    6: selective erase
         *       The terminal supports DECSCA and related selective-erase
         *       functions. This allows to protect specific cells from being
         *       erased, if specified.
         *    7: soft character set (DRCS)
         *       TODO: ?
         *    8: user-defined keys (UDKs)
         *       TODO: ?
         *    9: national-replacement character sets (NRCS)
         *       National-replacement character-sets are available.
         *   12: Yugoslavian (SCS)
         *       TODO: ?
         *   15: technical character set
         *       The DEC technical-character-set is available.
         *   18: windowing capability
         *       TODO: ?
         *   21: horizontal scrolling
         *       TODO: ?
         *   22: ANSII color
         *       TODO: ?
         *   23: Greek
         *       TODO: ?
         *   24: Turkish
         *       TODO: ?
         *   29: ANSI text locator
         *       TODO: ?
         *   42: ISO Latin-2 character set
         *       TODO: ?
         *   44: PCTerm
         *       TODO: ?
         *   45: soft keymap
         *       TODO: ?
         *   46: ASCII emulation
         *       TODO: ?
         */

        return SEQ_WRITE(screen, C0_CSI, C1_CSI, "?64;1;6;9;15c");
}

static int screen_DA2(term_screen *screen, const term_seq *seq) {
        /*
         * DA2 - secondary-device-attributes
         * The secondary DA asks for the terminal-ID, firmware versions and
         * other non-primary attributes. All these values are
         * informational-only and should not be used by the host to detect
         * terminal features.
         *
         * The terminal's response is:
         *   ^[ > 61 ; FIRMWARE ; KEYBOARD c
         * whereas 65 is fixed for VT525 terminals, the last terminal-line that
         * increased this number. FIRMWARE is the firmware
         * version encoded as major/minor (20 == 2.0) and KEYBOARD is 0 for STD
         * keyboard and 1 for PC keyboards.
         *
         * We replace the firmware-version with the systemd-version so clients
         * can decode it again.
         */

        return SEQ_WRITE(screen, C0_CSI, C1_CSI, ">65;" PACKAGE_VERSION ";1c");
}

static int screen_DA3(term_screen *screen, const term_seq *seq) {
        /*
         * DA3 - tertiary-device-attributes
         * The tertiary DA is used to query the terminal-ID.
         *
         * The terminal's response is:
         *   ^P ! | XX AA BB CC ^\
         * whereas all four parameters are hexadecimal-encoded pairs. XX
         * denotes the manufacturing site, AA BB CC is the terminal's ID.
         */

        /* we do not support tertiary DAs */
        return 0;
}

static int screen_DC1(term_screen *screen, const term_seq *seq) {
        /*
         * DC1 - device-control-1 or XON
         * This clears any previous XOFF and resumes terminal-transmission.
         */

        /* we do not support XON */
        return 0;
}

static int screen_DC3(term_screen *screen, const term_seq *seq) {
        /*
         * DC3 - device-control-3 or XOFF
         * Stops terminal transmission. No further characters are sent until
         * an XON is received.
         */

        /* we do not support XOFF */
        return 0;
}

static int screen_DCH(term_screen *screen, const term_seq *seq) {
        /*
         * DCH - delete-character
         * This deletes @argv[0] characters at the current cursor position. As
         * characters are deleted, the remaining characters between the cursor
         * and right margin move to the left. Character attributes move with the
         * characters. The terminal adds blank spaces with no visual character
         * attributes at the right margin. DCH has no effect outside the
         * scrolling margins.
         *
         * Defaults:
         *   args[0]: 1
         */

        unsigned int num = 1;

        if (seq->args[0] > 0)
                num = seq->args[0];

        screen_cursor_clear_wrap(screen);
        term_page_delete_cells(screen->page, screen->state.cursor_x, screen->state.cursor_y, num, &screen->state.attr, screen->age);

        return 0;
}

static int screen_DECALN(term_screen *screen, const term_seq *seq) {
        /*
         * DECALN - screen-alignment-pattern
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECANM(term_screen *screen, const term_seq *seq) {
        /*
         * DECANM - ansi-mode
         * Set the terminal into VT52 compatibility mode. Control sequences
         * overlap with regular sequences so we have to detect them early before
         * dispatching them.
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECBI(term_screen *screen, const term_seq *seq) {
        /*
         * DECBI - back-index
         * This control function moves the cursor backward one column. If the
         * cursor is at the left margin, then all screen data within the margin
         * moves one column to the right. The column that shifted past the right
         * margin is lost.
         * DECBI adds a new column at the left margin with no visual attributes.
         * DECBI does not affect the margins. If the cursor is beyond the
         * left-margin at the left border, then the terminal ignores DECBI.
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECCARA(term_screen *screen, const term_seq *seq) {
        /*
         * DECCARA - change-attributes-in-rectangular-area
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECCRA(term_screen *screen, const term_seq *seq) {
        /*
         * DECCRA - copy-rectangular-area
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECDC(term_screen *screen, const term_seq *seq) {
        /*
         * DECDC - delete-column
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECDHL_BH(term_screen *screen, const term_seq *seq) {
        /*
         * DECDHL_BH - double-width-double-height-line: bottom half
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECDHL_TH(term_screen *screen, const term_seq *seq) {
        /*
         * DECDHL_TH - double-width-double-height-line: top half
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECDWL(term_screen *screen, const term_seq *seq) {
        /*
         * DECDWL - double-width-single-height-line
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECEFR(term_screen *screen, const term_seq *seq) {
        /*
         * DECEFR - enable-filter-rectangle
         * Defines the coordinates of a filter rectangle (top, left, bottom,
         * right as @args[0] to @args[3]) and activates it.
         * Anytime the locator is detected outside of the filter rectangle, an
         * outside rectangle event is generated and the rectangle is disabled.
         * Filter rectangles are always treated as "one-shot" events. Any
         * parameters that are omitted default to the current locator position.
         * If all parameters are omitted, any locator motion will be reported.
         * DECELR always cancels any prevous rectangle definition.
         *
         * The locator is usually associated with the mouse-cursor, but based
         * on cells instead of pixels. See DECELR how to initialize and enable
         * it. DECELR can also enable pixel-mode instead of cell-mode.
         *
         * TODO: implement
         */

        return 0;
}

static int screen_DECELF(term_screen *screen, const term_seq *seq) {
        /*
         * DECELF - enable-local-functions
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECELR(term_screen *screen, const term_seq *seq) {
        /*
         * DECELR - enable-locator-reporting
         * This changes the locator-reporting mode. @args[0] specifies the mode
         * to set, 0 disables locator-reporting, 1 enables it continuously, 2
         * enables it for a single report. @args[1] specifies the
         * precision-mode. 0 and 2 set the reporting to cell-precision, 1 sets
         * pixel-precision.
         *
         * Defaults:
         *   args[0]: 0
         *   args[1]: 0
         *
         * TODO: implement
         */

        return 0;
}

static int screen_DECERA(term_screen *screen, const term_seq *seq) {
        /*
         * DECERA - erase-rectangular-area
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECFI(term_screen *screen, const term_seq *seq) {
        /*
         * DECFI - forward-index
         * This control function moves the cursor forward one column. If the
         * cursor is at the right margin, then all screen data within the
         * margins moves one column to the left. The column shifted past the
         * left margin is lost.
         * DECFI adds a new column at the right margin, with no visual
         * attributes. DECFI does not affect margins. If the cursor is beyond
         * the right margin at the border of the page when the terminal
         * receives DECFI, then the terminal ignores DECFI.
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECFRA(term_screen *screen, const term_seq *seq) {
        /*
         * DECFRA - fill-rectangular-area
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECIC(term_screen *screen, const term_seq *seq) {
        /*
         * DECIC - insert-column
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECID(term_screen *screen, const term_seq *seq) {
        /*
         * DECID - return-terminal-id
         * This is an obsolete form of TERM_CMD_DA1.
         */

        return screen_DA1(screen, seq);
}

static int screen_DECINVM(term_screen *screen, const term_seq *seq) {
        /*
         * DECINVM - invoke-macro
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECKBD(term_screen *screen, const term_seq *seq) {
        /*
         * DECKBD - keyboard-language-selection
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECKPAM(term_screen *screen, const term_seq *seq) {
        /*
         * DECKPAM - keypad-application-mode
         * Enables the keypad-application mode. If enabled, the keypad sends
         * special characters instead of the printed characters. This way,
         * applications can detect whether a numeric key was pressed on the
         * top-row or on the keypad.
         * Default is keypad-numeric-mode.
         */

        screen->flags |= TERM_FLAG_KEYPAD_MODE;

        return 0;
}

static int screen_DECKPNM(term_screen *screen, const term_seq *seq) {
        /*
         * DECKPNM - keypad-numeric-mode
         * This disables the keypad-application-mode (DECKPAM) and returns to
         * the keypad-numeric-mode. Keypresses on the keypad generate the same
         * sequences as corresponding keypresses on the main keyboard.
         * Default is keypad-numeric-mode.
         */

        screen->flags &= ~TERM_FLAG_KEYPAD_MODE;

        return 0;
}

static int screen_DECLFKC(term_screen *screen, const term_seq *seq) {
        /*
         * DECLFKC - local-function-key-control
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECLL(term_screen *screen, const term_seq *seq) {
        /*
         * DECLL - load-leds
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECLTOD(term_screen *screen, const term_seq *seq) {
        /*
         * DECLTOD - load-time-of-day
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECPCTERM(term_screen *screen, const term_seq *seq) {
        /*
         * DECPCTERM - pcterm-mode
         * This enters/exits the PCTerm mode. Default mode is VT-mode. It can
         * also select parameters for scancode/keycode mappings in SCO mode.
         *
         * Definitely not worth implementing. Lets kill PCTerm/SCO modes!
         */

        return 0;
}

static int screen_DECPKA(term_screen *screen, const term_seq *seq) {
        /*
         * DECPKA - program-key-action
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECPKFMR(term_screen *screen, const term_seq *seq) {
        /*
         * DECPKFMR - program-key-free-memory-report
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECRARA(term_screen *screen, const term_seq *seq) {
        /*
         * DECRARA - reverse-attributes-in-rectangular-area
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECRC(term_screen *screen, const term_seq *seq) {
        /*
         * DECRC - restore-cursor
         * Restores the terminal to the state saved by the save cursor (DECSC)
         * function. This includes more than just the cursor-position.
         *
         * If nothing was saved by DECSC, then DECRC performs the following
         * actions:
         *   * Moves the cursor to the home position (upper left of screen).
         *   * Resets origin mode (DECOM).
         *   * Turns all character attributes off (normal setting).
         *   * Maps the ASCII character set into GL, and the DEC Supplemental
         *     Graphic set into GR.
         *
         * The terminal maintains a separate DECSC buffer for the main display
         * and the status line. This feature lets you save a separate operating
         * state for the main display and the status line.
         */

        screen_restore_state(screen, &screen->saved);

        return 0;
}

static int screen_DECREQTPARM(term_screen *screen, const term_seq *seq) {
        /*
         * DECREQTPARM - request-terminal-parameters
         * The sequence DECREPTPARM is sent by the terminal controller to notify
         * the host of the status of selected terminal parameters. The status
         * sequence may be sent when requested by the host or at the terminal's
         * discretion. DECREPTPARM is sent upon receipt of a DECREQTPARM.
         *
         * If @args[0] is 0, this marks a request and the terminal is allowed
         * to send DECREPTPARM messages without request. If it is 1, the same
         * applies but the terminal should no longer send DECREPTPARM
         * unrequested.
         * 2 and 3 mark a report, but 3 is only used if the terminal answers as
         * an explicit request with @args[0] == 1.
         *
         * The other arguments are ignored in requests, but have the following
         * meaning in responses:
         *   args[1]: 1=no-parity-set 4=parity-set-and-odd 5=parity-set-and-even
         *   args[2]: 1=8bits-per-char 2=7bits-per-char
         *   args[3]: transmission-speed
         *   args[4]: receive-speed
         *   args[5]: 1=bit-rate-multiplier-is-16
         *   args[6]: This value communicates the four switch values in block 5
         *            of SETUP B, which are only visible to the user when an STP
         *            option is installed. These bits may be assigned for an STP
         *            device. The four bits are a decimal-encoded binary number.
         *            Value between 0-15.
         *
         * The transmission/receive speeds have mappings for number => bits/s
         * which are quite weird. Examples are: 96->3600, 112->9600, 120->19200
         *
         * Defaults:
         *   args[0]: 0
         */

        if (seq->n_args < 1 || seq->args[0] == 0) {
                screen->flags &= ~TERM_FLAG_INHIBIT_TPARM;
                return SEQ_WRITE(screen, C0_CSI, C1_CSI, "2;1;1;120;120;1;0x");
        } else if (seq->args[0] == 1) {
                screen->flags |= TERM_FLAG_INHIBIT_TPARM;
                return SEQ_WRITE(screen, C0_CSI, C1_CSI, "3;1;1;120;120;1;0x");
        } else {
                return 0;
        }
}

static int screen_DECRPKT(term_screen *screen, const term_seq *seq) {
        /*
         * DECRPKT - report-key-type
         * Response to DECRQKT, we can safely ignore it as we're the one sending
         * it to the host.
         */

        return 0;
}

static int screen_DECRQCRA(term_screen *screen, const term_seq *seq) {
        /*
         * DECRQCRA - request-checksum-of-rectangular-area
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECRQDE(term_screen *screen, const term_seq *seq) {
        /*
         * DECRQDE - request-display-extent
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECRQKT(term_screen *screen, const term_seq *seq) {
        /*
         * DECRQKT - request-key-type
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECRQLP(term_screen *screen, const term_seq *seq) {
        /*
         * DECRQLP - request-locator-position
         * See DECELR for locator-information.
         *
         * TODO: document and implement
         */

        return 0;
}

static int screen_DECRQM_ANSI(term_screen *screen, const term_seq *seq) {
        /*
         * DECRQM_ANSI - request-mode-ansi
         * The host sends this control function to find out if a particular mode
         * is set or reset. The terminal responds with a report mode function.
         * @args[0] contains the mode to query.
         *
         * Response is DECRPM with the first argument set to the mode that was
         * queried, second argument is 0 if mode is invalid, 1 if mode is set,
         * 2 if mode is not set (reset), 3 if mode is permanently set and 4 if
         * mode is permanently not set (reset):
         *   ANSI: ^[ MODE ; VALUE $ y
         *   DEC:  ^[ ? MODE ; VALUE $ y
         *
         * TODO: implement
         */

        return 0;
}

static int screen_DECRQM_DEC(term_screen *screen, const term_seq *seq) {
        /*
         * DECRQM_DEC - request-mode-dec
         * Same as DECRQM_ANSI but for DEC modes.
         *
         * TODO: implement
         */

        return 0;
}

static int screen_DECRQPKFM(term_screen *screen, const term_seq *seq) {
        /*
         * DECRQPKFM - request-program-key-free-memory
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECRQPSR(term_screen *screen, const term_seq *seq) {
        /*
         * DECRQPSR - request-presentation-state-report
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECRQTSR(term_screen *screen, const term_seq *seq) {
        /*
         * DECRQTSR - request-terminal-state-report
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECRQUPSS(term_screen *screen, const term_seq *seq) {
        /*
         * DECRQUPSS - request-user-preferred-supplemental-set
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECSACE(term_screen *screen, const term_seq *seq) {
        /*
         * DECSACE - select-attribute-change-extent
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECSASD(term_screen *screen, const term_seq *seq) {
        /*
         * DECSASD - select-active-status-display
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECSC(term_screen *screen, const term_seq *seq) {
        /*
         * DECSC - save-cursor
         * Save cursor and terminal state so it can be restored later on.
         * Saves the following items in the terminal's memory:
         *   * Cursor position
         *   * Character attributes set by the SGR command
         *   * Character sets (G0, G1, G2, or G3) currently in GL and GR
         *   * Wrap flag (autowrap or no autowrap)
         *   * State of origin mode (DECOM)
         *   * Selective erase attribute
         *   * Any single shift 2 (SS2) or single shift 3 (SS3) functions sent
         */

        screen_save_state(screen, &screen->saved);

        return 0;
}

static int screen_DECSCA(term_screen *screen, const term_seq *seq) {
        /*
         * DECSCA - select-character-protection-attribute
         * Defines the characters that come after it as erasable or not erasable
         * from the screen. The selective erase control functions (DECSED and
         * DECSEL) can only erase characters defined as erasable.
         *
         * @args[0] specifies the new mode. 0 and 2 mark any following character
         * as erasable, 1 marks it as not erasable.
         *
         * Defaults:
         *   args[0]: 0
         */

        unsigned int mode = 0;

        if (seq->args[0] > 0)
                mode = seq->args[0];

        switch (mode) {
        case 0:
        case 2:
                screen->state.attr.protect = 0;
                break;
        case 1:
                screen->state.attr.protect = 1;
                break;
        }

        return 0;
}

static int screen_DECSCL(term_screen *screen, const term_seq *seq) {
        /*
         * DECSCL - select-conformance-level
         * Select the terminal's operating level. The factory default is
         * level 4 (VT Level 4 mode, 7-bit controls).
         * When you change the conformance level, the terminal performs a hard
         * reset (RIS).
         *
         * @args[0] defines the conformance-level, valid values are:
         *   61: Level 1 (VT100)
         *   62: Level 2 (VT200)
         *   63: Level 3 (VT300)
         *   64: Level 4 (VT400)
         * @args[1] defines the 8bit-mode, valid values are:
         *    0: 8-bit controls
         *    1: 7-bit controls
         *    2: 8-bit controls (same as 0)
         *
         * If @args[0] is 61, then @args[1] is ignored and 7bit controls are
         * enforced.
         *
         * Defaults:
         *   args[0]: 64
         *   args[1]: 0
         */

        unsigned int level = 64, bit = 0;

        if (seq->n_args > 0) {
                level = seq->args[0];
                if (seq->n_args > 1)
                        bit = seq->args[1];
        }

        term_screen_hard_reset(screen);

        switch (level) {
        case 61:
                screen->conformance_level = TERM_CONFORMANCE_LEVEL_VT100;
                screen->flags |= TERM_FLAG_7BIT_MODE;
                break;
        case 62 ... 69:
                screen->conformance_level = TERM_CONFORMANCE_LEVEL_VT400;
                if (bit == 1)
                        screen->flags |= TERM_FLAG_7BIT_MODE;
                else
                        screen->flags &= ~TERM_FLAG_7BIT_MODE;
                break;
        }

        return 0;
}

static int screen_DECSCP(term_screen *screen, const term_seq *seq) {
        /*
         * DECSCP - select-communication-port
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECSCPP(term_screen *screen, const term_seq *seq) {
        /*
         * DECSCPP - select-columns-per-page
         * Select columns per page. The number of rows is unaffected by this.
         * @args[0] selectes the number of columns (width), DEC only defines 80
         * and 132, but we allow any integer here. 0 is equivalent to 80.
         * Page content is *not* cleared and the cursor is left untouched.
         * However, if the page is reduced in width and the cursor would be
         * outside the visible region, it's set to the right border. Newly added
         * cells are cleared. No data is retained outside the visible region.
         *
         * Defaults:
         *   args[0]: 0
         *
         * TODO: implement
         */

        return 0;
}

static int screen_DECSCS(term_screen *screen, const term_seq *seq) {
        /*
         * DECSCS - select-communication-speed
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECSCUSR(term_screen *screen, const term_seq *seq) {
        /*
         * DECSCUSR - set-cursor-style
         * This changes the style of the cursor. @args[0] can be one of:
         *   0, 1: blinking block
         *      2: steady block
         *      3: blinking underline
         *      4: steady underline
         * Changing this setting does _not_ affect the cursor visibility itself.
         * Use DECTCEM for that.
         *
         * Defaults:
         *   args[0]: 0
         *
         * TODO: implement
         */

        return 0;
}

static int screen_DECSDDT(term_screen *screen, const term_seq *seq) {
        /*
         * DECSDDT - select-disconnect-delay-time
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECSDPT(term_screen *screen, const term_seq *seq) {
        /*
         * DECSDPT - select-digital-printed-data-type
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECSED(term_screen *screen, const term_seq *seq) {
        /*
         * DECSED - selective-erase-in-display
         * This control function erases some or all of the erasable characters
         * in the display. DECSED can only erase characters defined as erasable
         * by the DECSCA control function. DECSED works inside or outside the
         * scrolling margins.
         *
         * @args[0] defines which regions are erased. If it is 0, all cells from
         * the cursor (inclusive) till the end of the display are erase. If it
         * is 1, all cells from the start of the display till the cursor
         * (inclusive) are erased. If it is 2, all cells are erased.
         *
         * Defaults:
         *   args[0]: 0
         */

        unsigned int mode = 0;

        if (seq->args[0] > 0)
                mode = seq->args[0];

        switch (mode) {
        case 0:
                term_page_erase(screen->page,
                                screen->state.cursor_x, screen->state.cursor_y,
                                screen->page->width, screen->page->height,
                                &screen->state.attr, screen->age, true);
                break;
        case 1:
                term_page_erase(screen->page,
                                0, 0,
                                screen->state.cursor_x, screen->state.cursor_y,
                                &screen->state.attr, screen->age, true);
                break;
        case 2:
                term_page_erase(screen->page,
                                0, 0,
                                screen->page->width, screen->page->height,
                                &screen->state.attr, screen->age, true);
                break;
        }

        return 0;
}

static int screen_DECSEL(term_screen *screen, const term_seq *seq) {
        /*
         * DECSEL - selective-erase-in-line
         * This control function erases some or all of the erasable characters
         * in a single line of text. DECSEL erases only those characters defined
         * as erasable by the DECSCA control function. DECSEL works inside or
         * outside the scrolling margins.
         *
         * @args[0] defines the region to be erased. If it is 0, all cells from
         * the cursor (inclusive) till the end of the line are erase. If it is
         * 1, all cells from the start of the line till the cursor (inclusive)
         * are erased. If it is 2, the whole line of the cursor is erased.
         *
         * Defaults:
         *   args[0]: 0
         */

        unsigned int mode = 0;

        if (seq->args[0] > 0)
                mode = seq->args[0];

        switch (mode) {
        case 0:
                term_page_erase(screen->page,
                                screen->state.cursor_x, screen->state.cursor_y,
                                screen->page->width, screen->state.cursor_y,
                                &screen->state.attr, screen->age, true);
                break;
        case 1:
                term_page_erase(screen->page,
                                0, screen->state.cursor_y,
                                screen->state.cursor_x, screen->state.cursor_y,
                                &screen->state.attr, screen->age, true);
                break;
        case 2:
                term_page_erase(screen->page,
                                0, screen->state.cursor_y,
                                screen->page->width, screen->state.cursor_y,
                                &screen->state.attr, screen->age, true);
                break;
        }

        return 0;
}

static int screen_DECSERA(term_screen *screen, const term_seq *seq) {
        /*
         * DECSERA - selective-erase-rectangular-area
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECSFC(term_screen *screen, const term_seq *seq) {
        /*
         * DECSFC - select-flow-control
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECSKCV(term_screen *screen, const term_seq *seq) {
        /*
         * DECSKCV - set-key-click-volume
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECSLCK(term_screen *screen, const term_seq *seq) {
        /*
         * DECSLCK - set-lock-key-style
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECSLE(term_screen *screen, const term_seq *seq) {
        /*
         * DECSLE - select-locator-events
         *
         * TODO: implement
         */

        return 0;
}

static int screen_DECSLPP(term_screen *screen, const term_seq *seq) {
        /*
         * DECSLPP - set-lines-per-page
         * Set the number of lines used for the page. @args[0] specifies the
         * number of lines to be used. DEC only allows a limited number of
         * choices, however, we allow all integers. 0 is equivalent to 24.
         *
         * Defaults:
         *   args[0]: 0
         *
         * TODO: implement
         */

        return 0;
}

static int screen_DECSLRM_OR_SC(term_screen *screen, const term_seq *seq) {
        /*
         * DECSLRM_OR_SC - set-left-and-right-margins or save-cursor
         *
         * TODO: Detect save-cursor and run it. DECSLRM is not worth
         *       implementing.
         */

        return 0;
}

static int screen_DECSMBV(term_screen *screen, const term_seq *seq) {
        /*
         * DECSMBV - set-margin-bell-volume
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECSMKR(term_screen *screen, const term_seq *seq) {
        /*
         * DECSMKR - select-modifier-key-reporting
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECSNLS(term_screen *screen, const term_seq *seq) {
        /*
         * DECSNLS - set-lines-per-screen
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECSPP(term_screen *screen, const term_seq *seq) {
        /*
         * DECSPP - set-port-parameter
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECSPPCS(term_screen *screen, const term_seq *seq) {
        /*
         * DECSPPCS - select-pro-printer-character-set
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECSPRTT(term_screen *screen, const term_seq *seq) {
        /*
         * DECSPRTT - select-printer-type
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECSR(term_screen *screen, const term_seq *seq) {
        /*
         * DECSR - secure-reset
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECSRFR(term_screen *screen, const term_seq *seq) {
        /*
         * DECSRFR - select-refresh-rate
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECSSCLS(term_screen *screen, const term_seq *seq) {
        /*
         * DECSSCLS - set-scroll-speed
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECSSDT(term_screen *screen, const term_seq *seq) {
        /*
         * DECSSDT - select-status-display-line-type
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECSSL(term_screen *screen, const term_seq *seq) {
        /*
         * DECSSL - select-setup-language
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECST8C(term_screen *screen, const term_seq *seq) {
        /*
         * DECST8C - set-tab-at-every-8-columns
         * Clear the tab-ruler and reset it to a tab at every 8th column,
         * starting at 9 (though, setting a tab at 1 is fine as it has no
         * effect).
         */

        unsigned int i;

        for (i = 0; i < screen->page->width; i += 8)
                screen->tabs[i / 8] = 0x1;

        return 0;
}

static int screen_DECSTBM(term_screen *screen, const term_seq *seq) {
        /*
         * DECSTBM - set-top-and-bottom-margins
         * This control function sets the top and bottom margins for the current
         * page. You cannot perform scrolling outside the margins.
         *
         * @args[0] defines the top margin, @args[1] defines the bottom margin.
         * The bottom margin must be lower than the top-margin.
         *
         * This call resets the cursor position to 0/0 of the page.
         *
         * Defaults:
         *   args[0]: 1
         *   args[1]: last page-line
         */

        unsigned int top, bottom;

        top = 1;
        bottom = screen->page->height;

        if (seq->args[0] > 0)
                top = seq->args[0];
        if (seq->args[1] > 0)
                bottom = seq->args[1];

        if (top > screen->page->height)
                top = screen->page->height;
        if (bottom > screen->page->height)
                bottom = screen->page->height;

        if (top >= bottom || top > screen->page->height || bottom > screen->page->height) {
                top = 1;
                bottom = screen->page->height;
        }

        term_page_set_scroll_region(screen->page, top - 1, bottom - top + 1);
        screen_cursor_clear_wrap(screen);
        screen_cursor_set(screen, 0, 0);

        return 0;
}

static int screen_DECSTR(term_screen *screen, const term_seq *seq) {
        /*
         * DECSTR - soft-terminal-reset
         * Perform a soft reset to the default values.
         */

        term_screen_soft_reset(screen);

        return 0;
}

static int screen_DECSTRL(term_screen *screen, const term_seq *seq) {
        /*
         * DECSTRL - set-transmit-rate-limit
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECSWBV(term_screen *screen, const term_seq *seq) {
        /*
         * DECSWBV - set-warning-bell-volume
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECSWL(term_screen *screen, const term_seq *seq) {
        /*
         * DECSWL - single-width-single-height-line
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECTID(term_screen *screen, const term_seq *seq) {
        /*
         * DECTID - select-terminal-id
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECTME(term_screen *screen, const term_seq *seq) {
        /*
         * DECTME - terminal-mode-emulation
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DECTST(term_screen *screen, const term_seq *seq) {
        /*
         * DECTST - invoke-confidence-test
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_DL(term_screen *screen, const term_seq *seq) {
        /*
         * DL - delete-line
         * This control function deletes one or more lines in the scrolling
         * region, starting with the line that has the cursor. @args[0] defines
         * the number of lines to delete. 0 is treated the same as 1.
         * As lines are deleted, lines below the cursor and in the scrolling
         * region move up. The terminal adds blank lines with no visual
         * character attributes at the bottom of the scrolling region. If it is
         * greater than the number of lines remaining on the page, DL deletes
         * only the remaining lines. DL has no effect outside the scrolling
         * margins.
         *
         * Defaults:
         *   args[0]: 1
         */

        unsigned int num = 1;

        if (seq->args[0] > 0)
                num = seq->args[0];

        term_page_delete_lines(screen->page, screen->state.cursor_y, num, &screen->state.attr, screen->age);

        return 0;
}

static int screen_DSR_ANSI(term_screen *screen, const term_seq *seq) {
        /*
         * DSR_ANSI - device-status-report-ansi
         *
         * TODO: implement
         */

        return 0;
}

static int screen_DSR_DEC(term_screen *screen, const term_seq *seq) {
        /*
         * DSR_DEC - device-status-report-dec
         *
         * TODO: implement
         */

        return 0;
}

static int screen_ECH(term_screen *screen, const term_seq *seq) {
        /*
         * ECH - erase-character
         * This control function erases one or more characters, from the cursor
         * position to the right. ECH clears character attributes from erased
         * character positions. ECH works inside or outside the scrolling
         * margins.
         * @args[0] defines the number of characters to erase. 0 is treated the
         * same as 1.
         *
         * Defaults:
         *   args[0]: 1
         */

        unsigned int num = 1;

        if (seq->args[0] > 0)
                num = seq->args[0];

        term_page_erase(screen->page,
                        screen->state.cursor_x, screen->state.cursor_y,
                        screen->state.cursor_x + num, screen->state.cursor_y,
                        &screen->state.attr, screen->age, false);

        return 0;
}

static int screen_ED(term_screen *screen, const term_seq *seq) {
        /*
         * ED - erase-in-display
         * This control function erases characters from part or all of the
         * display. When you erase complete lines, they become single-height,
         * single-width lines, with all visual character attributes cleared. ED
         * works inside or outside the scrolling margins.
         *
         * @args[0] defines the region to erase. 0 means from cursor (inclusive)
         * till the end of the screen. 1 means from the start of the screen till
         * the cursor (inclusive) and 2 means the whole screen.
         *
         * Defaults:
         *   args[0]: 0
         */

        unsigned int mode = 0;

        if (seq->args[0] > 0)
                mode = seq->args[0];

        switch (mode) {
        case 0:
                term_page_erase(screen->page,
                                screen->state.cursor_x, screen->state.cursor_y,
                                screen->page->width, screen->page->height,
                                &screen->state.attr, screen->age, false);
                break;
        case 1:
                term_page_erase(screen->page,
                                0, 0,
                                screen->state.cursor_x, screen->state.cursor_y,
                                &screen->state.attr, screen->age, false);
                break;
        case 2:
                term_page_erase(screen->page,
                                0, 0,
                                screen->page->width, screen->page->height,
                                &screen->state.attr, screen->age, false);
                break;
        }

        return 0;
}

static int screen_EL(term_screen *screen, const term_seq *seq) {
        /*
         * EL - erase-in-line
         * This control function erases characters on the line that has the
         * cursor. EL clears all character attributes from erased character
         * positions. EL works inside or outside the scrolling margins.
         *
         * @args[0] defines the region to erase. 0 means from cursor (inclusive)
         * till the end of the line. 1 means from the start of the line till the
         * cursor (inclusive) and 2 means the whole line.
         *
         * Defaults:
         *   args[0]: 0
         */

        unsigned int mode = 0;

        if (seq->args[0] > 0)
                mode = seq->args[0];

        switch (mode) {
        case 0:
                term_page_erase(screen->page,
                                screen->state.cursor_x, screen->state.cursor_y,
                                screen->page->width, screen->state.cursor_y,
                                &screen->state.attr, screen->age, false);
                break;
        case 1:
                term_page_erase(screen->page,
                                0, screen->state.cursor_y,
                                screen->state.cursor_x, screen->state.cursor_y,
                                &screen->state.attr, screen->age, false);
                break;
        case 2:
                term_page_erase(screen->page,
                                0, screen->state.cursor_y,
                                screen->page->width, screen->state.cursor_y,
                                &screen->state.attr, screen->age, false);
                break;
        }

        return 0;
}

static int screen_ENQ(term_screen *screen, const term_seq *seq) {
        /*
         * ENQ - enquiry
         * Transmit the answerback-string. If none is set, do nothing.
         */

        if (screen->answerback)
                return screen_write(screen, screen->answerback, strlen(screen->answerback));

        return 0;
}

static int screen_EPA(term_screen *screen, const term_seq *seq) {
        /*
         * EPA - end-of-guarded-area
         *
         * TODO: What is this?
         */

        return 0;
}

static int screen_FF(term_screen *screen, const term_seq *seq) {
        /*
         * FF - form-feed
         * This causes the cursor to jump to the next line. It is treated the
         * same as LF.
         */

        return screen_LF(screen, seq);
}

static int screen_HPA(term_screen *screen, const term_seq *seq) {
        /*
         * HPA - horizontal-position-absolute
         * HPA causes the active position to be moved to the n-th horizontal
         * position of the active line. If an attempt is made to move the active
         * position past the last position on the line, then the active position
         * stops at the last position on the line.
         *
         * @args[0] defines the horizontal position. 0 is treated as 1.
         *
         * Defaults:
         *   args[0]: 1
         */

        unsigned int num = 1;

        if (seq->args[0] > 0)
                num = seq->args[0];

        screen_cursor_clear_wrap(screen);
        screen_cursor_set(screen, num - 1, screen->state.cursor_y);

        return 0;
}

static int screen_HPR(term_screen *screen, const term_seq *seq) {
        /*
         * HPR - horizontal-position-relative
         * HPR causes the active position to be moved to the n-th following
         * horizontal position of the active line. If an attempt is made to move
         * the active position past the last position on the line, then the
         * active position stops at the last position on the line.
         *
         * @args[0] defines the horizontal position. 0 is treated as 1.
         *
         * Defaults:
         *   args[0]: 1
         */

        unsigned int num = 1;

        if (seq->args[0] > 0)
                num = seq->args[0];

        screen_cursor_clear_wrap(screen);
        screen_cursor_right(screen, num);

        return 0;
}

static int screen_HT(term_screen *screen, const term_seq *seq) {
        /*
         * HT - horizontal-tab
         * Moves the cursor to the next tab stop. If there are no more tab
         * stops, the cursor moves to the right margin. HT does not cause text
         * to auto wrap.
         */

        screen_cursor_clear_wrap(screen);
        screen_cursor_right_tab(screen, 1);

        return 0;
}

static int screen_HTS(term_screen *screen, const term_seq *seq) {
        /*
         * HTS - horizontal-tab-set
         * HTS sets a horizontal tab stop at the column position indicated by
         * the value of the active column when the terminal receives an HTS.
         *
         * Executing an HTS does not effect the other horizontal tab stop
         * settings.
         */

        unsigned int pos;

        pos = screen->state.cursor_x;
        if (screen->page->width > 0)
                screen->tabs[pos / 8] |= 1U << (pos % 8);

        return 0;
}

static int screen_HVP(term_screen *screen, const term_seq *seq) {
        /*
         * HVP - horizontal-and-vertical-position
         * This control function works the same as the cursor position (CUP)
         * function. Origin mode (DECOM) selects line numbering and the ability
         * to move the cursor into margins.
         *
         * Defaults:
         *   args[0]: 1
         *   args[1]: 1
         */

        return screen_CUP(screen, seq);
}

static int screen_ICH(term_screen *screen, const term_seq *seq) {
        /*
         * ICH - insert-character
         * This control function inserts one or more space (SP) characters
         * starting at the cursor position. @args[0] is the number of characters
         * to insert. 0 is treated as 1.
         *
         * The ICH sequence inserts blank characters with the normal
         * character attribute. The cursor remains at the beginning of the blank
         * characters. Text between the cursor and right margin moves to the
         * right. Characters scrolled past the right margin are lost. ICH has no
         * effect outside the scrolling margins.
         *
         * Defaults:
         *   args[0]: 1
         */

        unsigned int num = 1;

        if (seq->args[0] > 0)
                num = seq->args[0];

        screen_cursor_clear_wrap(screen);
        term_page_insert_cells(screen->page, screen->state.cursor_x, screen->state.cursor_y, num, &screen->state.attr, screen->age);

        return 0;
}

static int screen_IL(term_screen *screen, const term_seq *seq) {
        /*
         * IL - insert-line
         * This control function inserts one or more blank lines, starting at
         * the cursor. @args[0] is the number of lines to insert. 0 is treated
         * as 1.
         *
         * As lines are inserted, lines below the cursor and in the scrolling
         * region move down. Lines scrolled off the page are lost. IL has no
         * effect outside the page margins.
         *
         * Defaults:
         *   args[0]: 1
         */

        unsigned int num = 1;

        if (seq->args[0] > 0)
                num = seq->args[0];

        screen_cursor_clear_wrap(screen);
        term_page_insert_lines(screen->page, screen->state.cursor_y, num, &screen->state.attr, screen->age);

        return 0;
}

static int screen_IND(term_screen *screen, const term_seq *seq) {
        /*
         * IND - index
         * IND moves the cursor down one line in the same column. If the cursor
         * is at the bottom margin, then the screen performs a scroll-up.
         */

        screen_cursor_down(screen, 1, true);

        return 0;
}

static int screen_LF(term_screen *screen, const term_seq *seq) {
        /*
         * LF - line-feed
         * Causes a line feed or a new line operation, depending on the setting
         * of line feed/new line mode.
         */

        screen_cursor_down(screen, 1, true);
        if (screen->flags & TERM_FLAG_NEWLINE_MODE)
                screen_cursor_left(screen, screen->state.cursor_x);

        return 0;
}

static int screen_LS1R(term_screen *screen, const term_seq *seq) {
        /*
         * LS1R - locking-shift-1-right
         * Map G1 into GR.
         */

        screen->state.gr = &screen->g1;

        return 0;
}

static int screen_LS2(term_screen *screen, const term_seq *seq) {
        /*
         * LS2 - locking-shift-2
         * Map G2 into GL.
         */

        screen->state.gl = &screen->g2;

        return 0;
}

static int screen_LS2R(term_screen *screen, const term_seq *seq) {
        /*
         * LS2R - locking-shift-2-right
         * Map G2 into GR.
         */

        screen->state.gr = &screen->g2;

        return 0;
}

static int screen_LS3(term_screen *screen, const term_seq *seq) {
        /*
         * LS3 - locking-shift-3
         * Map G3 into GL.
         */

        screen->state.gl = &screen->g3;

        return 0;
}

static int screen_LS3R(term_screen *screen, const term_seq *seq) {
        /*
         * LS3R - locking-shift-3-right
         * Map G3 into GR.
         */

        screen->state.gr = &screen->g3;

        return 0;
}

static int screen_MC_ANSI(term_screen *screen, const term_seq *seq) {
        /*
         * MC_ANSI - media-copy-ansi
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_MC_DEC(term_screen *screen, const term_seq *seq) {
        /*
         * MC_DEC - media-copy-dec
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_NEL(term_screen *screen, const term_seq *seq) {
        /*
         * NEL - next-line
         * Moves cursor to first position on next line. If cursor is at bottom
         * margin, then screen performs a scroll-up.
         */

        screen_cursor_clear_wrap(screen);
        screen_cursor_down(screen, 1, true);
        screen_cursor_set(screen, 0, screen->state.cursor_y);

        return 0;
}

static int screen_NP(term_screen *screen, const term_seq *seq) {
        /*
         * NP - next-page
         * This control function moves the cursor forward to the home position
         * on one of the following pages in page memory. If there is only one
         * page, then the terminal ignores NP.
         * If NP tries to move the cursor past the last page in memory, then the
         * cursor stops at the last page.
         *
         * @args[0] defines the number of pages to forward. 0 is treated as 1.
         *
         * Defaults:
         *   args[0]: 1
         *
         * Probably not worth implementing. We only support a single page.
         */

        return 0;
}

static int screen_NULL(term_screen *screen, const term_seq *seq) {
        /*
         * NULL - null
         * The NULL operation does nothing. ASCII NULL is always ignored.
         */

        return 0;
}

static int screen_PP(term_screen *screen, const term_seq *seq) {
        /*
         * PP - preceding-page
         * This control function moves the cursor backward to the home position
         * on one of the preceding pages in page memory. If there is only one
         * page, then the terminal ignores PP.
         * If PP tries to move the cursor back farther than the first page in
         * memory, then the cursor stops at the first page.
         *
         * @args[0] defines the number of pages to go backwards. 0 is treated
         * as 1.
         *
         * Defaults:
         *   args[0]: 1
         *
         * Probably not worth implementing. We only support a single page.
         */

        return 0;
}

static int screen_PPA(term_screen *screen, const term_seq *seq) {
        /*
         * PPA - page-position-absolute
         * This control function can move the cursor to the corresponding row
         * and column on any page in page memory. You select the page by its
         * number. If there is only one page, then the terminal ignores PPA.
         *
         * @args[0] is the number of the page to move the cursor to. If it is
         * greater than the number of the last page in memory, then the cursor
         * stops at the last page. If it is less than the number of the first
         * page, then the cursor stops at the first page.
         *
         * Defaults:
         *   args[0]: 1
         *
         * Probably not worth implementing. We only support a single page.
         */

        return 0;
}

static int screen_PPB(term_screen *screen, const term_seq *seq) {
        /*
         * PPB - page-position-backward
         * This control function moves the cursor backward to the corresponding
         * row and column on one of the preceding pages in page memory. If there
         * is only one page, then the terminal ignores PPB.
         *
         * @args[0] indicates the number of pages to move the cursor backward.
         * If it tries to move the cursor back farther than the first page in
         * memory, then the cursor stops at the first page. 0 is treated as 1.
         *
         * Defaults:
         *   args[0]: 1
         *
         * Probably not worth implementing. We only support a single page.
         */

        return 0;
}

static int screen_PPR(term_screen *screen, const term_seq *seq) {
        /*
         * PPR - page-position-relative
         * This control function moves the cursor forward to the corresponding
         * row and column on one of the following pages in page memory. If there
         * is only one page, then the terminal ignores PPR.
         *
         * @args[0] indicates how many pages to move the cursor forward. If it
         * tries to move the cursor beyond the last page in memory, then the
         * cursor stops at the last page. 0 is treated as 1.
         *
         * Defaults:
         *   args[0]: 1
         *
         * Probably not worth implementing. We only support a single page.
         */

        return 0;
}

static int screen_RC(term_screen *screen, const term_seq *seq) {
        /*
         * RC - restore-cursor
         */

        return screen_DECRC(screen, seq);
}

static int screen_REP(term_screen *screen, const term_seq *seq) {
        /*
         * REP - repeat
         * Repeat the preceding graphics-character the given number of times.
         * @args[0] specifies how often it shall be repeated. 0 is treated as 1.
         *
         * Defaults:
         *   args[0]: 1
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_RI(term_screen *screen, const term_seq *seq) {
        /*
         * RI - reverse-index
         * Moves the cursor up one line in the same column. If the cursor is at
         * the top margin, the page scrolls down.
         */

        screen_cursor_up(screen, 1, true);

        return 0;
}

static int screen_RIS(term_screen *screen, const term_seq *seq) {
        /*
         * RIS - reset-to-initial-state
         * This control function causes a nonvolatile memory (NVR) recall to
         * occur. RIS replaces all set-up features with their saved settings.
         *
         * The terminal stores these saved settings in NVR memory. The saved
         * setting for a feature is the same as the factory-default setting,
         * unless you saved a new setting.
         */

        term_screen_hard_reset(screen);

        return 0;
}

static int screen_RM_ANSI(term_screen *screen, const term_seq *seq) {
        /*
         * RM_ANSI - reset-mode-ansi
         *
         * TODO: implement (see VT510rm manual)
         */

        unsigned int i;

        for (i = 0; i < seq->n_args; ++i)
                screen_mode_change_ansi(screen, seq->args[i], false);

        return 0;
}

static int screen_RM_DEC(term_screen *screen, const term_seq *seq) {
        /*
         * RM_DEC - reset-mode-dec
         * This is the same as RM_ANSI but for DEC modes.
         */

        unsigned int i;

        for (i = 0; i < seq->n_args; ++i)
                screen_mode_change_dec(screen, seq->args[i], false);

        return 0;
}

static int screen_S7C1T(term_screen *screen, const term_seq *seq) {
        /*
         * S7C1T - set-7bit-c1-terminal
         * This causes the terminal to start sending C1 controls as 7bit
         * sequences instead of 8bit C1 controls.
         * This is ignored if the terminal is below level-2 emulation mode
         * (VT100 and below), the terminal already sends 7bit controls then.
         */

        if (screen->conformance_level > TERM_CONFORMANCE_LEVEL_VT100)
                screen->flags |= TERM_FLAG_7BIT_MODE;

        return 0;
}

static int screen_S8C1T(term_screen *screen, const term_seq *seq) {
        /*
         * S8C1T - set-8bit-c1-terminal
         * This causes the terminal to start sending C1 controls as 8bit C1
         * control instead of 7bit sequences.
         * This is ignored if the terminal is below level-2 emulation mode
         * (VT100 and below). The terminal always sends 7bit controls in those
         * modes.
         */

        if (screen->conformance_level > TERM_CONFORMANCE_LEVEL_VT100)
                screen->flags &= ~TERM_FLAG_7BIT_MODE;

        return 0;
}

static int screen_SCS(term_screen *screen, const term_seq *seq) {
        /*
         * SCS - select-character-set
         * Designate character sets to G-sets. The mapping from intermediates
         * and terminal characters in the escape sequence to G-sets and
         * character-sets is non-trivial and implemented separately. See there
         * for more information.
         * This call simply sets the selected G-set to the desired
         * character-set.
         */

        term_charset *cs = NULL;

        /* TODO: support more of them? */
        switch (seq->charset) {
        case TERM_CHARSET_ISO_LATIN1_SUPPLEMENTAL:
        case TERM_CHARSET_ISO_LATIN2_SUPPLEMENTAL:
        case TERM_CHARSET_ISO_LATIN5_SUPPLEMENTAL:
        case TERM_CHARSET_ISO_GREEK_SUPPLEMENTAL:
        case TERM_CHARSET_ISO_HEBREW_SUPPLEMENTAL:
        case TERM_CHARSET_ISO_LATIN_CYRILLIC:
                break;

        case TERM_CHARSET_DEC_SPECIAL_GRAPHIC:
                cs = &term_dec_special_graphics;
                break;
        case TERM_CHARSET_DEC_SUPPLEMENTAL:
                cs = &term_dec_supplemental_graphics;
                break;
        case TERM_CHARSET_DEC_TECHNICAL:
        case TERM_CHARSET_CYRILLIC_DEC:
        case TERM_CHARSET_DUTCH_NRCS:
        case TERM_CHARSET_FINNISH_NRCS:
        case TERM_CHARSET_FRENCH_NRCS:
        case TERM_CHARSET_FRENCH_CANADIAN_NRCS:
        case TERM_CHARSET_GERMAN_NRCS:
        case TERM_CHARSET_GREEK_DEC:
        case TERM_CHARSET_GREEK_NRCS:
        case TERM_CHARSET_HEBREW_DEC:
        case TERM_CHARSET_HEBREW_NRCS:
        case TERM_CHARSET_ITALIAN_NRCS:
        case TERM_CHARSET_NORWEGIAN_DANISH_NRCS:
        case TERM_CHARSET_PORTUGUESE_NRCS:
        case TERM_CHARSET_RUSSIAN_NRCS:
        case TERM_CHARSET_SCS_NRCS:
        case TERM_CHARSET_SPANISH_NRCS:
        case TERM_CHARSET_SWEDISH_NRCS:
        case TERM_CHARSET_SWISS_NRCS:
        case TERM_CHARSET_TURKISH_DEC:
        case TERM_CHARSET_TURKISH_NRCS:
                break;

        case TERM_CHARSET_USERPREF_SUPPLEMENTAL:
                break;
        }

        if (seq->intermediates & TERM_SEQ_FLAG_POPEN)
                screen->g0 = cs ? : &term_unicode_lower;
        else if (seq->intermediates & TERM_SEQ_FLAG_PCLOSE)
                screen->g1 = cs ? : &term_unicode_upper;
        else if (seq->intermediates & TERM_SEQ_FLAG_MULT)
                screen->g2 = cs ? : &term_unicode_lower;
        else if (seq->intermediates & TERM_SEQ_FLAG_PLUS)
                screen->g3 = cs ? : &term_unicode_upper;
        else if (seq->intermediates & TERM_SEQ_FLAG_MINUS)
                screen->g1 = cs ? : &term_unicode_upper;
        else if (seq->intermediates & TERM_SEQ_FLAG_DOT)
                screen->g2 = cs ? : &term_unicode_lower;
        else if (seq->intermediates & TERM_SEQ_FLAG_SLASH)
                screen->g3 = cs ? : &term_unicode_upper;

        return 0;
}

static int screen_SD(term_screen *screen, const term_seq *seq) {
        /*
         * SD - scroll-down
         * This control function moves the user window down a specified number
         * of lines in page memory.
         * @args[0] is the number of lines to move the
         * user window up in page memory. New lines appear at the top of the
         * display. Old lines disappear at the bottom of the display. You
         * cannot pan past the top margin of the current page. 0 is treated
         * as 1.
         *
         * Defaults:
         *   args[0]: 1
         */

        unsigned int num = 1;

        if (seq->args[0] > 0)
                num = seq->args[0];

        term_page_scroll_down(screen->page, num, &screen->state.attr, screen->age, NULL);

        return 0;
}

static int screen_SGR(term_screen *screen, const term_seq *seq) {
        /*
         * SGR - select-graphics-rendition
         */

        term_color *dst;
        unsigned int i, code;
        int v;

        if (seq->n_args < 1) {
                zero(screen->state.attr);
                return 0;
        }

        for (i = 0; i < seq->n_args; ++i) {
                v = seq->args[i];
                switch (v) {
                case 1:
                        screen->state.attr.bold = 1;
                        break;
                case 3:
                        screen->state.attr.italic = 1;
                        break;
                case 4:
                        screen->state.attr.underline = 1;
                        break;
                case 5:
                        screen->state.attr.blink = 1;
                        break;
                case 7:
                        screen->state.attr.inverse = 1;
                        break;
                case 8:
                        screen->state.attr.hidden = 1;
                        break;
                case 22:
                        screen->state.attr.bold = 0;
                        break;
                case 23:
                        screen->state.attr.italic = 0;
                        break;
                case 24:
                        screen->state.attr.underline = 0;
                        break;
                case 25:
                        screen->state.attr.blink = 0;
                        break;
                case 27:
                        screen->state.attr.inverse = 0;
                        break;
                case 28:
                        screen->state.attr.hidden = 0;
                        break;
                case 30 ... 37:
                        screen->state.attr.fg.ccode = v - 30 + TERM_CCODE_BLACK;
                        break;
                case 39:
                        screen->state.attr.fg.ccode = 0;
                        break;
                case 40 ... 47:
                        screen->state.attr.bg.ccode = v - 40 + TERM_CCODE_BLACK;
                        break;
                case 49:
                        screen->state.attr.bg.ccode = 0;
                        break;
                case 90 ... 97:
                        screen->state.attr.fg.ccode = v - 90 + TERM_CCODE_LIGHT_BLACK;
                        break;
                case 100 ... 107:
                        screen->state.attr.bg.ccode = v - 100 + TERM_CCODE_LIGHT_BLACK;
                        break;
                case 38:
                        /* fallthrough */
                case 48:

                        if (v == 38)
                                dst = &screen->state.attr.fg;
                        else
                                dst = &screen->state.attr.bg;

                        ++i;
                        if (i >= seq->n_args)
                                break;

                        switch (seq->args[i]) {
                        case 2:
                                /* 24bit-color support */

                                i += 3;
                                if (i >= seq->n_args)
                                        break;

                                dst->ccode = TERM_CCODE_RGB;
                                dst->red = (seq->args[i - 2] >= 0) ? seq->args[i - 2] : 0;
                                dst->green = (seq->args[i - 1] >= 0) ? seq->args[i - 1] : 0;
                                dst->blue = (seq->args[i] >= 0) ? seq->args[i] : 0;

                                break;
                        case 5:
                                /* 256-color support */

                                ++i;
                                if (i >= seq->n_args || seq->args[i] < 0)
                                        break;

                                dst->ccode = TERM_CCODE_256;
                                code = seq->args[i];
                                dst->c256 = code < 256 ? code : 0;

                                break;
                        }

                        break;
                case -1:
                        /* fallthrough */
                case 0:
                        zero(screen->state.attr);
                        break;
                }
        }

        return 0;
}

static int screen_SI(term_screen *screen, const term_seq *seq) {
        /*
         * SI - shift-in
         * Map G0 into GL.
         */

        screen->state.gl = &screen->g0;

        return 0;
}

static int screen_SM_ANSI(term_screen *screen, const term_seq *seq) {
        /*
         * SM_ANSI - set-mode-ansi
         *
         * TODO: implement
         */

        unsigned int i;

        for (i = 0; i < seq->n_args; ++i)
                screen_mode_change_ansi(screen, seq->args[i], true);

        return 0;
}

static int screen_SM_DEC(term_screen *screen, const term_seq *seq) {
        /*
         * SM_DEC - set-mode-dec
         * This is the same as SM_ANSI but for DEC modes.
         */

        unsigned int i;

        for (i = 0; i < seq->n_args; ++i)
                screen_mode_change_dec(screen, seq->args[i], true);

        return 0;
}

static int screen_SO(term_screen *screen, const term_seq *seq) {
        /*
         * SO - shift-out
         * Map G1 into GL.
         */

        screen->state.gl = &screen->g1;

        return 0;
}

static int screen_SPA(term_screen *screen, const term_seq *seq) {
        /*
         * SPA - start-of-protected-area
         *
         * TODO: What is this?
         */

        return 0;
}

static int screen_SS2(term_screen *screen, const term_seq *seq) {
        /*
         * SS2 - single-shift-2
         * Temporarily map G2 into GL for the next graphics character.
         */

        screen->state.glt = &screen->g2;

        return 0;
}

static int screen_SS3(term_screen *screen, const term_seq *seq) {
        /*
         * SS3 - single-shift-3
         * Temporarily map G3 into GL for the next graphics character
         */

        screen->state.glt = &screen->g3;

        return 0;
}

static int screen_ST(term_screen *screen, const term_seq *seq) {
        /*
         * ST - string-terminator
         * The string-terminator is usually part of control-sequences and
         * handled by the parser. In all other situations it is silently
         * ignored.
         */

        return 0;
}

static int screen_SU(term_screen *screen, const term_seq *seq) {
        /*
         * SU - scroll-up
         * This control function moves the user window up a specified number of
         * lines in page memory.
         * @args[0] is the number of lines to move the
         * user window down in page memory. New lines appear at the bottom of
         * the display. Old lines disappear at the top of the display. You
         * cannot pan past the bottom margin of the current page. 0 is treated
         * as 1.
         *
         * Defaults:
         *   args[0]: 1
         */

        unsigned int num = 1;

        if (seq->args[0] > 0)
                num = seq->args[0];

        term_page_scroll_up(screen->page, num, &screen->state.attr, screen->age, screen->history);

        return 0;
}

static int screen_SUB(term_screen *screen, const term_seq *seq) {
        /*
         * SUB - substitute
         * Cancel the current control-sequence and print a replacement
         * character. Our parser already handles this so all we have to do is
         * print the replacement character.
         */

        static const term_seq rep = {
                .type = TERM_SEQ_GRAPHIC,
                .command = TERM_CMD_GRAPHIC,
                .terminator = 0xfffd,
        };

        return screen_GRAPHIC(screen, &rep);
}

static int screen_TBC(term_screen *screen, const term_seq *seq) {
        /*
         * TBC - tab-clear
         * This clears tab-stops. If @args[0] is 0, the tab-stop at the current
         * cursor position is cleared. If it is 3, all tab stops are cleared.
         *
         * Defaults:
         *   args[0]: 0
         */

        unsigned int mode = 0, pos;

        if (seq->args[0] > 0)
                mode = seq->args[0];

        switch (mode) {
        case 0:
                pos = screen->state.cursor_x;
                if (screen->page->width > 0)
                        screen->tabs[pos / 8] &= ~(1U << (pos % 8));
                break;
        case 3:
                if (screen->page->width > 0)
                        memzero(screen->tabs, (screen->page->width + 7) / 8);
                break;
        }

        return 0;
}

static int screen_VPA(term_screen *screen, const term_seq *seq) {
        /*
         * VPA - vertical-line-position-absolute
         * VPA causes the active position to be moved to the corresponding
         * horizontal position. @args[0] specifies the line to jump to. If an
         * attempt is made to move the active position below the last line, then
         * the active position stops on the last line. 0 is treated as 1.
         *
         * Defaults:
         *   args[0]: 1
         */

        unsigned int pos = 1;

        if (seq->args[0] > 0)
                pos = seq->args[0];

        screen_cursor_clear_wrap(screen);
        screen_cursor_set_rel(screen, screen->state.cursor_x, pos - 1);

        return 0;
}

static int screen_VPR(term_screen *screen, const term_seq *seq) {
        /*
         * VPR - vertical-line-position-relative
         * VPR causes the active position to be moved to the corresponding
         * horizontal position. @args[0] specifies the number of lines to jump
         * down relative to the current cursor position. If an attempt is made
         * to move the active position below the last line, the active position
         * stops at the last line. 0 is treated as 1.
         *
         * Defaults:
         *   args[0]: 1
         */

        unsigned int num = 1;

        if (seq->args[0] > 0)
                num = seq->args[0];

        screen_cursor_clear_wrap(screen);
        screen_cursor_down(screen, num, false);

        return 0;
}

static int screen_VT(term_screen *screen, const term_seq *seq) {
        /*
         * VT - vertical-tab
         * This causes a vertical jump by one line. Terminals treat it exactly
         * the same as LF.
         */

        return screen_LF(screen, seq);
}

static int screen_XTERM_CLLHP(term_screen *screen, const term_seq *seq) {
        /*
         * XTERM_CLLHP - xterm-cursor-lower-left-hp-bugfix
         * Move the cursor to the lower-left corner of the page. This is an HP
         * bugfix by xterm.
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_XTERM_IHMT(term_screen *screen, const term_seq *seq) {
        /*
         * XTERM_IHMT - xterm-initiate-highlight-mouse-tracking
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_XTERM_MLHP(term_screen *screen, const term_seq *seq) {
        /*
         * XTERM_MLHP - xterm-memory-lock-hp-bugfix
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_XTERM_MUHP(term_screen *screen, const term_seq *seq) {
        /*
         * XTERM_MUHP - xterm-memory-unlock-hp-bugfix
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_XTERM_RPM(term_screen *screen, const term_seq *seq) {
        /*
         * XTERM_RPM - xterm-restore-private-mode
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_XTERM_RRV(term_screen *screen, const term_seq *seq) {
        /*
         * XTERM_RRV - xterm-reset-resource-value
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_XTERM_RTM(term_screen *screen, const term_seq *seq) {
        /*
         * XTERM_RTM - xterm-reset-title-mode
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_XTERM_SACL1(term_screen *screen, const term_seq *seq) {
        /*
         * XTERM_SACL1 - xterm-set-ansi-conformance-level-1
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_XTERM_SACL2(term_screen *screen, const term_seq *seq) {
        /*
         * XTERM_SACL2 - xterm-set-ansi-conformance-level-2
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_XTERM_SACL3(term_screen *screen, const term_seq *seq) {
        /*
         * XTERM_SACL3 - xterm-set-ansi-conformance-level-3
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_XTERM_SDCS(term_screen *screen, const term_seq *seq) {
        /*
         * XTERM_SDCS - xterm-set-default-character-set
         * Select the default character set. We treat this the same as UTF-8 as
         * this is our default character set. As we always use UTF-8, this
         * becomes as no-op.
         */

        return 0;
}

static int screen_XTERM_SGFX(term_screen *screen, const term_seq *seq) {
        /*
         * XTERM_SGFX - xterm-sixel-graphics
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_XTERM_SPM(term_screen *screen, const term_seq *seq) {
        /*
         * XTERM_SPM - xterm-set-private-mode
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_XTERM_SRV(term_screen *screen, const term_seq *seq) {
        /*
         * XTERM_SRV - xterm-set-resource-value
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_XTERM_STM(term_screen *screen, const term_seq *seq) {
        /*
         * XTERM_STM - xterm-set-title-mode
         *
         * Probably not worth implementing.
         */

        return 0;
}

static int screen_XTERM_SUCS(term_screen *screen, const term_seq *seq) {
        /*
         * XTERM_SUCS - xterm-select-utf8-character-set
         * Select UTF-8 as character set. This is our default on only character
         * set. Hence, this is a no-op.
         */

        return 0;
}

static int screen_XTERM_WM(term_screen *screen, const term_seq *seq) {
        /*
         * XTERM_WM - xterm-window-management
         *
         * Probably not worth implementing.
         */

        return 0;
}

/*
 * Feeding data
 * The screen_feed_*() handlers take data from the user and feed it into the
 * screen. Once the parser has detected a sequence, we parse the command-type
 * and forward it to the command-dispatchers.
 */

static int screen_feed_cmd(term_screen *screen, const term_seq *seq) {
        switch (seq->command) {
        case TERM_CMD_GRAPHIC:
                return screen_GRAPHIC(screen, seq);
        case TERM_CMD_BEL:
                return screen_BEL(screen, seq);
        case TERM_CMD_BS:
                return screen_BS(screen, seq);
        case TERM_CMD_CBT:
                return screen_CBT(screen, seq);
        case TERM_CMD_CHA:
                return screen_CHA(screen, seq);
        case TERM_CMD_CHT:
                return screen_CHT(screen, seq);
        case TERM_CMD_CNL:
                return screen_CNL(screen, seq);
        case TERM_CMD_CPL:
                return screen_CPL(screen, seq);
        case TERM_CMD_CR:
                return screen_CR(screen, seq);
        case TERM_CMD_CUB:
                return screen_CUB(screen, seq);
        case TERM_CMD_CUD:
                return screen_CUD(screen, seq);
        case TERM_CMD_CUF:
                return screen_CUF(screen, seq);
        case TERM_CMD_CUP:
                return screen_CUP(screen, seq);
        case TERM_CMD_CUU:
                return screen_CUU(screen, seq);
        case TERM_CMD_DA1:
                return screen_DA1(screen, seq);
        case TERM_CMD_DA2:
                return screen_DA2(screen, seq);
        case TERM_CMD_DA3:
                return screen_DA3(screen, seq);
        case TERM_CMD_DC1:
                return screen_DC1(screen, seq);
        case TERM_CMD_DC3:
                return screen_DC3(screen, seq);
        case TERM_CMD_DCH:
                return screen_DCH(screen, seq);
        case TERM_CMD_DECALN:
                return screen_DECALN(screen, seq);
        case TERM_CMD_DECANM:
                return screen_DECANM(screen, seq);
        case TERM_CMD_DECBI:
                return screen_DECBI(screen, seq);
        case TERM_CMD_DECCARA:
                return screen_DECCARA(screen, seq);
        case TERM_CMD_DECCRA:
                return screen_DECCRA(screen, seq);
        case TERM_CMD_DECDC:
                return screen_DECDC(screen, seq);
        case TERM_CMD_DECDHL_BH:
                return screen_DECDHL_BH(screen, seq);
        case TERM_CMD_DECDHL_TH:
                return screen_DECDHL_TH(screen, seq);
        case TERM_CMD_DECDWL:
                return screen_DECDWL(screen, seq);
        case TERM_CMD_DECEFR:
                return screen_DECEFR(screen, seq);
        case TERM_CMD_DECELF:
                return screen_DECELF(screen, seq);
        case TERM_CMD_DECELR:
                return screen_DECELR(screen, seq);
        case TERM_CMD_DECERA:
                return screen_DECERA(screen, seq);
        case TERM_CMD_DECFI:
                return screen_DECFI(screen, seq);
        case TERM_CMD_DECFRA:
                return screen_DECFRA(screen, seq);
        case TERM_CMD_DECIC:
                return screen_DECIC(screen, seq);
        case TERM_CMD_DECID:
                return screen_DECID(screen, seq);
        case TERM_CMD_DECINVM:
                return screen_DECINVM(screen, seq);
        case TERM_CMD_DECKBD:
                return screen_DECKBD(screen, seq);
        case TERM_CMD_DECKPAM:
                return screen_DECKPAM(screen, seq);
        case TERM_CMD_DECKPNM:
                return screen_DECKPNM(screen, seq);
        case TERM_CMD_DECLFKC:
                return screen_DECLFKC(screen, seq);
        case TERM_CMD_DECLL:
                return screen_DECLL(screen, seq);
        case TERM_CMD_DECLTOD:
                return screen_DECLTOD(screen, seq);
        case TERM_CMD_DECPCTERM:
                return screen_DECPCTERM(screen, seq);
        case TERM_CMD_DECPKA:
                return screen_DECPKA(screen, seq);
        case TERM_CMD_DECPKFMR:
                return screen_DECPKFMR(screen, seq);
        case TERM_CMD_DECRARA:
                return screen_DECRARA(screen, seq);
        case TERM_CMD_DECRC:
                return screen_DECRC(screen, seq);
        case TERM_CMD_DECREQTPARM:
                return screen_DECREQTPARM(screen, seq);
        case TERM_CMD_DECRPKT:
                return screen_DECRPKT(screen, seq);
        case TERM_CMD_DECRQCRA:
                return screen_DECRQCRA(screen, seq);
        case TERM_CMD_DECRQDE:
                return screen_DECRQDE(screen, seq);
        case TERM_CMD_DECRQKT:
                return screen_DECRQKT(screen, seq);
        case TERM_CMD_DECRQLP:
                return screen_DECRQLP(screen, seq);
        case TERM_CMD_DECRQM_ANSI:
                return screen_DECRQM_ANSI(screen, seq);
        case TERM_CMD_DECRQM_DEC:
                return screen_DECRQM_DEC(screen, seq);
        case TERM_CMD_DECRQPKFM:
                return screen_DECRQPKFM(screen, seq);
        case TERM_CMD_DECRQPSR:
                return screen_DECRQPSR(screen, seq);
        case TERM_CMD_DECRQTSR:
                return screen_DECRQTSR(screen, seq);
        case TERM_CMD_DECRQUPSS:
                return screen_DECRQUPSS(screen, seq);
        case TERM_CMD_DECSACE:
                return screen_DECSACE(screen, seq);
        case TERM_CMD_DECSASD:
                return screen_DECSASD(screen, seq);
        case TERM_CMD_DECSC:
                return screen_DECSC(screen, seq);
        case TERM_CMD_DECSCA:
                return screen_DECSCA(screen, seq);
        case TERM_CMD_DECSCL:
                return screen_DECSCL(screen, seq);
        case TERM_CMD_DECSCP:
                return screen_DECSCP(screen, seq);
        case TERM_CMD_DECSCPP:
                return screen_DECSCPP(screen, seq);
        case TERM_CMD_DECSCS:
                return screen_DECSCS(screen, seq);
        case TERM_CMD_DECSCUSR:
                return screen_DECSCUSR(screen, seq);
        case TERM_CMD_DECSDDT:
                return screen_DECSDDT(screen, seq);
        case TERM_CMD_DECSDPT:
                return screen_DECSDPT(screen, seq);
        case TERM_CMD_DECSED:
                return screen_DECSED(screen, seq);
        case TERM_CMD_DECSEL:
                return screen_DECSEL(screen, seq);
        case TERM_CMD_DECSERA:
                return screen_DECSERA(screen, seq);
        case TERM_CMD_DECSFC:
                return screen_DECSFC(screen, seq);
        case TERM_CMD_DECSKCV:
                return screen_DECSKCV(screen, seq);
        case TERM_CMD_DECSLCK:
                return screen_DECSLCK(screen, seq);
        case TERM_CMD_DECSLE:
                return screen_DECSLE(screen, seq);
        case TERM_CMD_DECSLPP:
                return screen_DECSLPP(screen, seq);
        case TERM_CMD_DECSLRM_OR_SC:
                return screen_DECSLRM_OR_SC(screen, seq);
        case TERM_CMD_DECSMBV:
                return screen_DECSMBV(screen, seq);
        case TERM_CMD_DECSMKR:
                return screen_DECSMKR(screen, seq);
        case TERM_CMD_DECSNLS:
                return screen_DECSNLS(screen, seq);
        case TERM_CMD_DECSPP:
                return screen_DECSPP(screen, seq);
        case TERM_CMD_DECSPPCS:
                return screen_DECSPPCS(screen, seq);
        case TERM_CMD_DECSPRTT:
                return screen_DECSPRTT(screen, seq);
        case TERM_CMD_DECSR:
                return screen_DECSR(screen, seq);
        case TERM_CMD_DECSRFR:
                return screen_DECSRFR(screen, seq);
        case TERM_CMD_DECSSCLS:
                return screen_DECSSCLS(screen, seq);
        case TERM_CMD_DECSSDT:
                return screen_DECSSDT(screen, seq);
        case TERM_CMD_DECSSL:
                return screen_DECSSL(screen, seq);
        case TERM_CMD_DECST8C:
                return screen_DECST8C(screen, seq);
        case TERM_CMD_DECSTBM:
                return screen_DECSTBM(screen, seq);
        case TERM_CMD_DECSTR:
                return screen_DECSTR(screen, seq);
        case TERM_CMD_DECSTRL:
                return screen_DECSTRL(screen, seq);
        case TERM_CMD_DECSWBV:
                return screen_DECSWBV(screen, seq);
        case TERM_CMD_DECSWL:
                return screen_DECSWL(screen, seq);
        case TERM_CMD_DECTID:
                return screen_DECTID(screen, seq);
        case TERM_CMD_DECTME:
                return screen_DECTME(screen, seq);
        case TERM_CMD_DECTST:
                return screen_DECTST(screen, seq);
        case TERM_CMD_DL:
                return screen_DL(screen, seq);
        case TERM_CMD_DSR_ANSI:
                return screen_DSR_ANSI(screen, seq);
        case TERM_CMD_DSR_DEC:
                return screen_DSR_DEC(screen, seq);
        case TERM_CMD_ECH:
                return screen_ECH(screen, seq);
        case TERM_CMD_ED:
                return screen_ED(screen, seq);
        case TERM_CMD_EL:
                return screen_EL(screen, seq);
        case TERM_CMD_ENQ:
                return screen_ENQ(screen, seq);
        case TERM_CMD_EPA:
                return screen_EPA(screen, seq);
        case TERM_CMD_FF:
                return screen_FF(screen, seq);
        case TERM_CMD_HPA:
                return screen_HPA(screen, seq);
        case TERM_CMD_HPR:
                return screen_HPR(screen, seq);
        case TERM_CMD_HT:
                return screen_HT(screen, seq);
        case TERM_CMD_HTS:
                return screen_HTS(screen, seq);
        case TERM_CMD_HVP:
                return screen_HVP(screen, seq);
        case TERM_CMD_ICH:
                return screen_ICH(screen, seq);
        case TERM_CMD_IL:
                return screen_IL(screen, seq);
        case TERM_CMD_IND:
                return screen_IND(screen, seq);
        case TERM_CMD_LF:
                return screen_LF(screen, seq);
        case TERM_CMD_LS1R:
                return screen_LS1R(screen, seq);
        case TERM_CMD_LS2:
                return screen_LS2(screen, seq);
        case TERM_CMD_LS2R:
                return screen_LS2R(screen, seq);
        case TERM_CMD_LS3:
                return screen_LS3(screen, seq);
        case TERM_CMD_LS3R:
                return screen_LS3R(screen, seq);
        case TERM_CMD_MC_ANSI:
                return screen_MC_ANSI(screen, seq);
        case TERM_CMD_MC_DEC:
                return screen_MC_DEC(screen, seq);
        case TERM_CMD_NEL:
                return screen_NEL(screen, seq);
        case TERM_CMD_NP:
                return screen_NP(screen, seq);
        case TERM_CMD_NULL:
                return screen_NULL(screen, seq);
        case TERM_CMD_PP:
                return screen_PP(screen, seq);
        case TERM_CMD_PPA:
                return screen_PPA(screen, seq);
        case TERM_CMD_PPB:
                return screen_PPB(screen, seq);
        case TERM_CMD_PPR:
                return screen_PPR(screen, seq);
        case TERM_CMD_RC:
                return screen_RC(screen, seq);
        case TERM_CMD_REP:
                return screen_REP(screen, seq);
        case TERM_CMD_RI:
                return screen_RI(screen, seq);
        case TERM_CMD_RIS:
                return screen_RIS(screen, seq);
        case TERM_CMD_RM_ANSI:
                return screen_RM_ANSI(screen, seq);
        case TERM_CMD_RM_DEC:
                return screen_RM_DEC(screen, seq);
        case TERM_CMD_S7C1T:
                return screen_S7C1T(screen, seq);
        case TERM_CMD_S8C1T:
                return screen_S8C1T(screen, seq);
        case TERM_CMD_SCS:
                return screen_SCS(screen, seq);
        case TERM_CMD_SD:
                return screen_SD(screen, seq);
        case TERM_CMD_SGR:
                return screen_SGR(screen, seq);
        case TERM_CMD_SI:
                return screen_SI(screen, seq);
        case TERM_CMD_SM_ANSI:
                return screen_SM_ANSI(screen, seq);
        case TERM_CMD_SM_DEC:
                return screen_SM_DEC(screen, seq);
        case TERM_CMD_SO:
                return screen_SO(screen, seq);
        case TERM_CMD_SPA:
                return screen_SPA(screen, seq);
        case TERM_CMD_SS2:
                return screen_SS2(screen, seq);
        case TERM_CMD_SS3:
                return screen_SS3(screen, seq);
        case TERM_CMD_ST:
                return screen_ST(screen, seq);
        case TERM_CMD_SU:
                return screen_SU(screen, seq);
        case TERM_CMD_SUB:
                return screen_SUB(screen, seq);
        case TERM_CMD_TBC:
                return screen_TBC(screen, seq);
        case TERM_CMD_VPA:
                return screen_VPA(screen, seq);
        case TERM_CMD_VPR:
                return screen_VPR(screen, seq);
        case TERM_CMD_VT:
                return screen_VT(screen, seq);
        case TERM_CMD_XTERM_CLLHP:
                return screen_XTERM_CLLHP(screen, seq);
        case TERM_CMD_XTERM_IHMT:
                return screen_XTERM_IHMT(screen, seq);
        case TERM_CMD_XTERM_MLHP:
                return screen_XTERM_MLHP(screen, seq);
        case TERM_CMD_XTERM_MUHP:
                return screen_XTERM_MUHP(screen, seq);
        case TERM_CMD_XTERM_RPM:
                return screen_XTERM_RPM(screen, seq);
        case TERM_CMD_XTERM_RRV:
                return screen_XTERM_RRV(screen, seq);
        case TERM_CMD_XTERM_RTM:
                return screen_XTERM_RTM(screen, seq);
        case TERM_CMD_XTERM_SACL1:
                return screen_XTERM_SACL1(screen, seq);
        case TERM_CMD_XTERM_SACL2:
                return screen_XTERM_SACL2(screen, seq);
        case TERM_CMD_XTERM_SACL3:
                return screen_XTERM_SACL3(screen, seq);
        case TERM_CMD_XTERM_SDCS:
                return screen_XTERM_SDCS(screen, seq);
        case TERM_CMD_XTERM_SGFX:
                return screen_XTERM_SGFX(screen, seq);
        case TERM_CMD_XTERM_SPM:
                return screen_XTERM_SPM(screen, seq);
        case TERM_CMD_XTERM_SRV:
                return screen_XTERM_SRV(screen, seq);
        case TERM_CMD_XTERM_STM:
                return screen_XTERM_STM(screen, seq);
        case TERM_CMD_XTERM_SUCS:
                return screen_XTERM_SUCS(screen, seq);
        case TERM_CMD_XTERM_WM:
                return screen_XTERM_WM(screen, seq);
        }

        return 0;
}

unsigned int term_screen_get_width(term_screen *screen) {
        assert_return(screen, -EINVAL);

        return screen->page->width;
}

unsigned int term_screen_get_height(term_screen *screen) {
        assert_return(screen, -EINVAL);

        return screen->page->height;
}

uint64_t term_screen_get_age(term_screen *screen) {
        assert_return(screen, 0);

        return screen->age;
}

int term_screen_feed_text(term_screen *screen, const uint8_t *in, size_t size) {
        uint32_t *ucs4_str;
        size_t i, j, ucs4_len;
        const term_seq *seq;
        int r;

        assert_return(screen, -EINVAL);

        ++screen->age;

        /* Feed bytes into utf8 decoder and handle parsed ucs4 chars. We always
         * treat data as UTF-8, but the parser makes sure to fall back to raw
         * 8bit mode if the stream is not valid UTF-8. This should be more than
         * enough to support old 7bit/8bit modes. */
        for (i = 0; i < size; ++i) {
                ucs4_len = term_utf8_decode(&screen->utf8, &ucs4_str, in[i]);
                for (j = 0; j < ucs4_len; ++j) {
                        r = term_parser_feed(screen->parser, &seq, ucs4_str[j]);
                        if (r < 0) {
                                return r;
                        } else if (r != TERM_SEQ_NONE) {
                                r = screen_feed_cmd(screen, seq);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        return 0;
}

static char *screen_map_key(term_screen *screen,
                            char *p,
                            const uint32_t *keysyms,
                            size_t n_syms,
                            uint32_t ascii,
                            const uint32_t *ucs4,
                            unsigned int mods) {
        char ch, ch2, ch_mods;
        uint32_t v;
        size_t i;

        /* TODO: All these key-mappings need to be verified. Public information
         * on those mappings is pretty scarce and every emulator seems to do it
         * slightly differently.
         * A lot of mappings are also missing. */

        if (n_syms < 1)
                return p;

        if (n_syms == 1)
                v = keysyms[0];
        else
                v = XKB_KEY_NoSymbol;

        /* In some mappings, the modifiers are encoded as CSI parameters. The
         * encoding is rather arbitrary, but seems to work. */
        ch_mods = 0;
        switch (mods & (TERM_KBDMOD_SHIFT | TERM_KBDMOD_ALT | TERM_KBDMOD_CTRL)) {
        case TERM_KBDMOD_SHIFT:
                ch_mods = '2';
                break;
        case TERM_KBDMOD_ALT:
                ch_mods = '3';
                break;
        case TERM_KBDMOD_SHIFT | TERM_KBDMOD_ALT:
                ch_mods = '4';
                break;
        case TERM_KBDMOD_CTRL:
                ch_mods = '5';
                break;
        case TERM_KBDMOD_CTRL | TERM_KBDMOD_SHIFT:
                ch_mods = '6';
                break;
        case TERM_KBDMOD_CTRL | TERM_KBDMOD_ALT:
                ch_mods = '7';
                break;
        case TERM_KBDMOD_CTRL | TERM_KBDMOD_SHIFT | TERM_KBDMOD_ALT:
                ch_mods = '8';
                break;
        }

        /* A user might actually use multiple layouts for keyboard
         * input. @keysyms[0] contains the actual keysym that the user
         * used. But if this keysym is not in the ascii range, the
         * input handler does check all other layouts that the user
         * specified whether one of them maps the key to some ASCII
         * keysym and provides this via @ascii. We always use the real
         * keysym except when handling CTRL+<XY> shortcuts we use the
         * ascii keysym. This is for compatibility to xterm et. al. so
         * ctrl+c always works regardless of the currently active
         * keyboard layout. But if no ascii-sym is found, we still use
         * the real keysym. */
        if (ascii == XKB_KEY_NoSymbol)
                ascii = v;

        /* map CTRL+<ascii> */
        if (mods & TERM_KBDMOD_CTRL) {
                switch (ascii) {
                case 0x60 ... 0x7e:
                        /* Right hand side is mapped to the left and then
                         * treated equally. Fall through to left-hand side.. */
                        ascii -= 0x20;
                case 0x20 ... 0x5f:
                        /* Printable ASCII is mapped 1-1 in XKB and in
                         * combination with CTRL bit 7 is flipped. This
                         * is equivalent to the caret-notation. */
                        *p++ = ascii ^ 0x40;
                        return p;
                }
        }

        /* map cursor keys */
        ch = 0;
        switch (v) {
        case XKB_KEY_Up:
                ch = 'A';
                break;
        case XKB_KEY_Down:
                ch = 'B';
                break;
        case XKB_KEY_Right:
                ch = 'C';
                break;
        case XKB_KEY_Left:
                ch = 'D';
                break;
        case XKB_KEY_Home:
                ch = 'H';
                break;
        case XKB_KEY_End:
                ch = 'F';
                break;
        }
        if (ch) {
                *p++ = 0x1b;
                if (screen->flags & TERM_FLAG_CURSOR_KEYS)
                        *p++ = 'O';
                else
                        *p++ = '[';
                if (ch_mods) {
                        *p++ = '1';
                        *p++ = ';';
                        *p++ = ch_mods;
                }
                *p++ = ch;
                return p;
        }

        /* map action keys */
        ch = 0;
        switch (v) {
        case XKB_KEY_Find:
                ch = '1';
                break;
        case XKB_KEY_Insert:
                ch = '2';
                break;
        case XKB_KEY_Delete:
                ch = '3';
                break;
        case XKB_KEY_Select:
                ch = '4';
                break;
        case XKB_KEY_Page_Up:
                ch = '5';
                break;
        case XKB_KEY_Page_Down:
                ch = '6';
                break;
        }
        if (ch) {
                *p++ = 0x1b;
                *p++ = '[';
                *p++ = ch;
                if (ch_mods) {
                        *p++ = ';';
                        *p++ = ch_mods;
                }
                *p++ = '~';
                return p;
        }

        /* map lower function keys */
        ch = 0;
        switch (v) {
        case XKB_KEY_F1:
                ch = 'P';
                break;
        case XKB_KEY_F2:
                ch = 'Q';
                break;
        case XKB_KEY_F3:
                ch = 'R';
                break;
        case XKB_KEY_F4:
                ch = 'S';
                break;
        }
        if (ch) {
                if (ch_mods) {
                        *p++ = 0x1b;
                        *p++ = '[';
                        *p++ = '1';
                        *p++ = ';';
                        *p++ = ch_mods;
                        *p++ = ch;
                } else {
                        *p++ = 0x1b;
                        *p++ = 'O';
                        *p++ = ch;
                }

                return p;
        }

        /* map upper function keys */
        ch = 0;
        ch2 = 0;
        switch (v) {
        case XKB_KEY_F5:
                ch = '1';
                ch2 = '5';
                break;
        case XKB_KEY_F6:
                ch = '1';
                ch2 = '7';
                break;
        case XKB_KEY_F7:
                ch = '1';
                ch2 = '8';
                break;
        case XKB_KEY_F8:
                ch = '1';
                ch2 = '9';
                break;
        case XKB_KEY_F9:
                ch = '2';
                ch2 = '0';
                break;
        case XKB_KEY_F10:
                ch = '2';
                ch2 = '1';
                break;
        case XKB_KEY_F11:
                ch = '2';
                ch2 = '2';
                break;
        case XKB_KEY_F12:
                ch = '2';
                ch2 = '3';
                break;
        }
        if (ch) {
                *p++ = 0x1b;
                *p++ = '[';
                *p++ = ch;
                if (ch2)
                        *p++ = ch2;
                if (ch_mods) {
                        *p++ = ';';
                        *p++ = ch_mods;
                }
                *p++ = '~';
                return p;
        }

        /* map special keys */
        switch (v) {
        case 0xff08: /* XKB_KEY_BackSpace */
        case 0xff09: /* XKB_KEY_Tab */
        case 0xff0a: /* XKB_KEY_Linefeed */
        case 0xff0b: /* XKB_KEY_Clear */
        case 0xff15: /* XKB_KEY_Sys_Req */
        case 0xff1b: /* XKB_KEY_Escape */
        case 0xffff: /* XKB_KEY_Delete */
                *p++ = v - 0xff00;
                return p;
        case 0xff13: /* XKB_KEY_Pause */
                /* TODO: What should we do with this key?
                 * Sending XOFF is awful as there is no simple
                 * way on modern keyboards to send XON again.
                 * If someone wants this, we can re-eanble
                 * optionally. */
                return p;
        case 0xff14: /* XKB_KEY_Scroll_Lock */
                /* TODO: What should we do on scroll-lock?
                 * Sending 0x14 is what the specs say but it is
                 * not used today the way most users would
                 * expect so we disable it. If someone wants
                 * this, we can re-enable it (optionally). */
                return p;
        case XKB_KEY_Return:
                *p++ = 0x0d;
                if (screen->flags & TERM_FLAG_NEWLINE_MODE)
                        *p++ = 0x0a;
                return p;
        case XKB_KEY_ISO_Left_Tab:
                *p++ = 0x09;
                return p;
        }

        /* map unicode keys */
        for (i = 0; i < n_syms; ++i)
                p += utf8_encode_unichar(p, ucs4[i]);

        return p;
}

int term_screen_feed_keyboard(term_screen *screen,
                              const uint32_t *keysyms,
                              size_t n_syms,
                              uint32_t ascii,
                              const uint32_t *ucs4,
                              unsigned int mods) {
        _cleanup_free_ char *dyn = NULL;
        static const size_t padding = 1;
        char buf[128], *start, *p;

        assert_return(screen, -EINVAL);

        /* allocate buffer if too small */
        start = buf;
        if (4 * n_syms + padding > sizeof(buf)) {
                dyn = malloc(4 * n_syms + padding);
                if (!dyn)
                        return -ENOMEM;

                start = dyn;
        }

        /* reserve prefix space */
        start += padding;
        p = start;

        p = screen_map_key(screen, p, keysyms, n_syms, ascii, ucs4, mods);
        if (!p || p - start < 1)
                return 0;

        /* The ALT modifier causes ESC to be prepended to any key-stroke. We
         * already accounted for that buffer space above, so simply prepend it
         * here.
         * TODO: is altSendsEscape a suitable default? What are the semantics
         * exactly? Is it used in C0/C1 conversion? Is it prepended if there
         * already is an escape character? */
        if (mods & TERM_KBDMOD_ALT && *start != 0x1b)
                *--start = 0x1b;

        /* turn C0 into C1 */
        if (!(screen->flags & TERM_FLAG_7BIT_MODE) && p - start >= 2)
                if (start[0] == 0x1b && start[1] >= 0x40 && start[1] <= 0x5f)
                        *++start ^= 0x40;

        return screen_write(screen, start, p - start);
}

int term_screen_resize(term_screen *screen, unsigned int x, unsigned int y) {
        unsigned int i;
        uint8_t *t;
        int r;

        assert_return(screen, -EINVAL);

        r = term_page_reserve(screen->page_main, x, y, &screen->state.attr, screen->age);
        if (r < 0)
                return r;

        r = term_page_reserve(screen->page_alt, x, y, &screen->state.attr, screen->age);
        if (r < 0)
                return r;

        if (x > screen->n_tabs) {
                t = realloc(screen->tabs, (x + 7) / 8);
                if (!t)
                        return -ENOMEM;

                screen->tabs = t;
                screen->n_tabs = x;
        }

        for (i = (screen->page->width + 7) / 8 * 8; i < x; i += 8)
                screen->tabs[i / 8] = 0x1;

        term_page_resize(screen->page_main, x, y, &screen->state.attr, screen->age, screen->history);
        term_page_resize(screen->page_alt, x, y, &screen->state.attr, screen->age, NULL);

        screen->state.cursor_x = screen_clamp_x(screen, screen->state.cursor_x);
        screen->state.cursor_y = screen_clamp_x(screen, screen->state.cursor_y);
        screen_cursor_clear_wrap(screen);

        return 0;
}

void term_screen_soft_reset(term_screen *screen) {
        unsigned int i;

        assert(screen);

        screen->g0 = &term_unicode_lower;
        screen->g1 = &term_unicode_upper;
        screen->g2 = &term_unicode_lower;
        screen->g3 = &term_unicode_upper;
        screen->state.attr = screen->default_attr;
        screen->state.gl = &screen->g0;
        screen->state.gr = &screen->g1;
        screen->state.glt = NULL;
        screen->state.grt = NULL;
        screen->state.auto_wrap = 0;
        screen->state.origin_mode = 0;

        screen->saved = screen->state;
        screen->saved.cursor_x = 0;
        screen->saved.cursor_y = 0;
        screen->saved_alt = screen->saved;

        screen->page = screen->page_main;
        screen->history = screen->history_main;
        screen->flags = TERM_FLAG_7BIT_MODE;
        screen->conformance_level = TERM_CONFORMANCE_LEVEL_VT400;

        for (i = 0; i < screen->page->width; i += 8)
                screen->tabs[i / 8] = 0x1;

        term_page_set_scroll_region(screen->page_main, 0, screen->page->height);
        term_page_set_scroll_region(screen->page_alt, 0, screen->page->height);
}

void term_screen_hard_reset(term_screen *screen) {
        assert(screen);

        term_screen_soft_reset(screen);
        zero(screen->utf8);
        screen->state.cursor_x = 0;
        screen->state.cursor_y = 0;
        term_page_erase(screen->page_main, 0, 0, screen->page->width, screen->page->height, &screen->state.attr, screen->age, false);
        term_page_erase(screen->page_alt, 0, 0, screen->page->width, screen->page->height, &screen->state.attr, screen->age, false);
}

int term_screen_set_answerback(term_screen *screen, const char *answerback) {
        char *t = NULL;

        assert_return(screen, -EINVAL);

        if (answerback) {
                t = strdup(answerback);
                if (!t)
                        return -ENOMEM;
        }

        free(screen->answerback);
        screen->answerback = t;

        return 0;
}

int term_screen_draw(term_screen *screen,
                     int (*draw_fn) (term_screen *screen,
                                     void *userdata,
                                     unsigned int x,
                                     unsigned int y,
                                     const term_attr *attr,
                                     const uint32_t *ch,
                                     size_t n_ch,
                                     unsigned int ch_width),
                     void *userdata,
                     uint64_t *fb_age) {
        uint64_t cell_age, line_age, age = 0;
        term_charbuf_t ch_buf;
        const uint32_t *ch_str;
        unsigned int i, j, cw;
        term_page *page;
        term_line *line;
        term_cell *cell;
        size_t ch_n;
        int r;

        assert(screen);
        assert(draw_fn);

        if (fb_age)
                age = *fb_age;

        page = screen->page;

        for (j = 0; j < page->height; ++j) {
                line = page->lines[j];
                line_age = MAX(line->age, page->age);

                for (i = 0; i < page->width; ++i) {
                        term_attr attr;

                        cell = &line->cells[i];
                        cell_age = MAX(cell->age, line_age);

                        if (age != 0 && cell_age <= age)
                                continue;

                        ch_str = term_char_resolve(cell->ch, &ch_n, &ch_buf);

                        /* Character-width of 0 is used for cleared cells.
                         * Always treat this as single-cell character, so
                         * renderers can assume ch_width is set properpy. */
                        cw = MAX(cell->cwidth, 1U);

                        attr = cell->attr;
                        if (i == screen->state.cursor_x && j == screen->state.cursor_y &&
                            !(screen->flags & TERM_FLAG_HIDE_CURSOR))
                                attr.inverse ^= 1;

                        r = draw_fn(screen,
                                    userdata,
                                    i,
                                    j,
                                    &attr,
                                    ch_str,
                                    ch_n,
                                    cw);
                        if (r != 0)
                                return r;
                }
        }

        if (fb_age)
                *fb_age = screen->age;

        return 0;
}
