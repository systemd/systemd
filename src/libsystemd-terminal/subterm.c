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
 * Stacked Terminal-Emulator
 * This is an interactive test of the term_screen implementation. It runs a
 * fully-fletched terminal-emulator inside of a parent TTY. That is, instead of
 * rendering the terminal as X11-window, it renders it as sub-window in the
 * parent TTY. Think of this like what "GNU-screen" does.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include "sd-event.h"
#include "macro.h"
#include "pty.h"
#include "ring.h"
#include "signal-util.h"
#include "utf8.h"
#include "util.h"
#include "term-internal.h"

typedef struct Output Output;
typedef struct Terminal Terminal;

struct Output {
        int fd;
        unsigned int width;
        unsigned int height;
        unsigned int in_width;
        unsigned int in_height;
        unsigned int cursor_x;
        unsigned int cursor_y;

        char obuf[4096];
        size_t n_obuf;

        bool resized : 1;
        bool in_menu : 1;
};

struct Terminal {
        sd_event *event;
        sd_event_source *frame_timer;
        Output *output;
        term_utf8 utf8;
        term_parser *parser;
        term_screen *screen;

        int in_fd;
        int out_fd;
        struct termios saved_in_attr;
        struct termios saved_out_attr;

        Pty *pty;
        Ring out_ring;

        bool is_scheduled : 1;
        bool is_dirty : 1;
        bool is_menu : 1;
};

/*
 * Output Handling
 */

#define BORDER_HORIZ            "\xe2\x94\x81"
#define BORDER_VERT             "\xe2\x94\x83"
#define BORDER_VERT_RIGHT       "\xe2\x94\xa3"
#define BORDER_VERT_LEFT        "\xe2\x94\xab"
#define BORDER_DOWN_RIGHT       "\xe2\x94\x8f"
#define BORDER_DOWN_LEFT        "\xe2\x94\x93"
#define BORDER_UP_RIGHT         "\xe2\x94\x97"
#define BORDER_UP_LEFT          "\xe2\x94\x9b"

static int output_winch(Output *o) {
        struct winsize wsz = { };
        int r;

        assert_return(o, -EINVAL);

        r = ioctl(o->fd, TIOCGWINSZ, &wsz);
        if (r < 0)
                return log_error_errno(errno, "error: cannot read window-size: %m");

        if (wsz.ws_col != o->width || wsz.ws_row != o->height) {
                o->width = wsz.ws_col;
                o->height = wsz.ws_row;
                o->in_width = MAX(o->width, 2U) - 2;
                o->in_height = MAX(o->height, 6U) - 6;
                o->resized = true;
        }

        return 0;
}

static int output_flush(Output *o) {
        int r;

        if (o->n_obuf < 1)
                return 0;

        r = loop_write(o->fd, o->obuf, o->n_obuf, false);
        if (r < 0)
                return log_error_errno(r, "error: cannot write to TTY: %m");

        o->n_obuf = 0;

        return 0;
}

static int output_write(Output *o, const void *buf, size_t size) {
        ssize_t len;
        int r;

        assert_return(o, -EINVAL);
        assert_return(buf || size < 1, -EINVAL);

        if (size < 1)
                return 0;

        if (o->n_obuf + size > o->n_obuf && o->n_obuf + size <= sizeof(o->obuf)) {
                memcpy(o->obuf + o->n_obuf, buf, size);
                o->n_obuf += size;
                return 0;
        }

        r = output_flush(o);
        if (r < 0)
                return r;

        len = loop_write(o->fd, buf, size, false);
        if (len < 0)
                return log_error_errno(len, "error: cannot write to TTY (%zd): %m", len);

        return 0;
}

_printf_(3,0)
static int output_vnprintf(Output *o, size_t max, const char *format, va_list args) {
        char buf[max];
        int r;

        assert_return(o, -EINVAL);
        assert_return(format, -EINVAL);
        assert_return(max <= 4096, -EINVAL);

        r = MIN(vsnprintf(buf, max, format, args), (int) max);

        return output_write(o, buf, r);
}

_printf_(3,4)
static int output_nprintf(Output *o, size_t max, const char *format, ...) {
        va_list args;
        int r;

        va_start(args, format);
        r = output_vnprintf(o, max, format, args);
        va_end(args);

        return r;
}

_printf_(2,0)
static int output_vprintf(Output *o, const char *format, va_list args) {
        char buf[4096];
        int r;

        assert_return(o, -EINVAL);
        assert_return(format, -EINVAL);

        r = vsnprintf(buf, sizeof(buf), format, args);

        assert_return(r < (ssize_t)sizeof(buf), -ENOBUFS);

        return output_write(o, buf, r);
}

_printf_(2,3)
static int output_printf(Output *o, const char *format, ...) {
        va_list args;
        int r;

        va_start(args, format);
        r = output_vprintf(o, format, args);
        va_end(args);

        return r;
}

static int output_move_to(Output *o, unsigned int x, unsigned int y) {
        int r;

        assert_return(o, -EINVAL);

        /* force the \e[H code as o->cursor_x/y might be out-of-date */

        r = output_printf(o, "\e[%u;%uH", y + 1, x + 1);
        if (r < 0)
                return r;

        o->cursor_x = x;
        o->cursor_y = y;
        return 0;
}

static int output_print_line(Output *o, size_t len) {
        const char line[] =
                BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ
                BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ
                BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ
                BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ
                BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ
                BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ
                BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ BORDER_HORIZ;
        const size_t max = (sizeof(line) - 1) / (sizeof(BORDER_HORIZ) - 1);
        size_t i;
        int r = 0;

        assert_return(o, -EINVAL);

        for ( ; len > 0; len -= i) {
                i = (len > max) ? max : len;
                r = output_write(o, line, i * (sizeof(BORDER_HORIZ) - 1));
                if (r < 0)
                        break;
        }

        return r;
}

_printf_(2,3)
static int output_frame_printl(Output *o, const char *format, ...) {
        va_list args;
        int r;

        assert(o);
        assert(format);

        /* out of frame? */
        if (o->cursor_y < 3 || o->cursor_y >= o->height - 3)
                return 0;

        va_start(args, format);
        r = output_vnprintf(o, o->width - 2, format, args);
        va_end(args);

        if (r < 0)
                return r;

        return output_move_to(o, 1, o->cursor_y + 1);
}

static Output *output_free(Output *o) {
        if (!o)
                return NULL;

        /* re-enable cursor */
        output_printf(o, "\e[?25h");
        /* disable alternate screen buffer */
        output_printf(o, "\e[?1049l");
        output_flush(o);

        /* o->fd is owned by the caller */
        free(o);

        return NULL;
}

static int output_new(Output **out, int fd) {
        Output *o;
        int r;

        assert_return(out, -EINVAL);

        o = new0(Output, 1);
        if (!o)
                return log_oom();

        o->fd = fd;

        r = output_winch(o);
        if (r < 0)
                goto error;

        /* enable alternate screen buffer */
        r = output_printf(o, "\e[?1049h");
        if (r < 0)
                goto error;

        /* always hide cursor */
        r = output_printf(o, "\e[?25l");
        if (r < 0)
                goto error;

        r = output_flush(o);
        if (r < 0)
                goto error;

        *out = o;
        return 0;

error:
        output_free(o);
        return r;
}

static void output_draw_frame(Output *o) {
        unsigned int i;

        assert(o);

        /* print header-frame */

        output_printf(o, BORDER_DOWN_RIGHT);
        output_print_line(o, o->width - 2);
        output_printf(o, BORDER_DOWN_LEFT
                         "\r\n"
                         BORDER_VERT
                         "\e[2;%uH"    /* cursor-position: 2/x */
                         BORDER_VERT
                         "\r\n"
                         BORDER_VERT_RIGHT,
                      o->width);
        output_print_line(o, o->width - 2);
        output_printf(o, BORDER_VERT_LEFT
                         "\r\n");

        /* print body-frame */

        for (i = 0; i < o->in_height; ++i) {
                output_printf(o, BORDER_VERT
                                 "\e[%u;%uH"    /* cursor-position: 2/x */
                                 BORDER_VERT
                                 "\r\n",
                              i + 4, o->width);
        }

        /* print footer-frame */

        output_printf(o, BORDER_VERT_RIGHT);
        output_print_line(o, o->width - 2);
        output_printf(o, BORDER_VERT_LEFT
                         "\r\n"
                         BORDER_VERT
                         "\e[%u;%uH"    /* cursor-position: 2/x */
                         BORDER_VERT
                         "\r\n"
                         BORDER_UP_RIGHT,
                      o->height - 1, o->width);
        output_print_line(o, o->width - 2);
        output_printf(o, BORDER_UP_LEFT);

        /* print header/footer text */

        output_printf(o, "\e[2;3H");
        output_nprintf(o, o->width - 4, "systemd - embedded terminal emulator");
        output_printf(o, "\e[%u;3H", o->height - 1);
        output_nprintf(o, o->width - 4, "press ^C to enter menu");
}

static void output_draw_menu(Output *o) {
        assert(o);

        output_frame_printl(o, "%s", "");
        output_frame_printl(o, "    Menu: (the following keys are recognized)");
        output_frame_printl(o, "      q: quit");
        output_frame_printl(o, "     ^C: send ^C to the PTY");
}

static int output_draw_cell_fn(term_screen *screen,
                               void *userdata,
                               unsigned int x,
                               unsigned int y,
                               const term_attr *attr,
                               const uint32_t *ch,
                               size_t n_ch,
                               unsigned int ch_width) {
        Output *o = userdata;
        size_t k, ulen;
        char utf8[4];

        if (x >= o->in_width || y >= o->in_height)
                return 0;

        if (x == 0 && y != 0)
                output_printf(o, "\e[m\r\n" BORDER_VERT);

        switch (attr->fg.ccode) {
        case TERM_CCODE_DEFAULT:
                output_printf(o, "\e[39m");
                break;
        case TERM_CCODE_256:
                output_printf(o, "\e[38;5;%um", attr->fg.c256);
                break;
        case TERM_CCODE_RGB:
                output_printf(o, "\e[38;2;%u;%u;%um", attr->fg.red, attr->fg.green, attr->fg.blue);
                break;
        case TERM_CCODE_BLACK ... TERM_CCODE_WHITE:
                output_printf(o, "\e[%um", attr->fg.ccode - TERM_CCODE_BLACK + 30);
                break;
        case TERM_CCODE_LIGHT_BLACK ... TERM_CCODE_LIGHT_WHITE:
                output_printf(o, "\e[%um", attr->fg.ccode - TERM_CCODE_LIGHT_BLACK + 90);
                break;
        }

        switch (attr->bg.ccode) {
        case TERM_CCODE_DEFAULT:
                output_printf(o, "\e[49m");
                break;
        case TERM_CCODE_256:
                output_printf(o, "\e[48;5;%um", attr->bg.c256);
                break;
        case TERM_CCODE_RGB:
                output_printf(o, "\e[48;2;%u;%u;%um", attr->bg.red, attr->bg.green, attr->bg.blue);
                break;
        case TERM_CCODE_BLACK ... TERM_CCODE_WHITE:
                output_printf(o, "\e[%um", attr->bg.ccode - TERM_CCODE_BLACK + 40);
                break;
        case TERM_CCODE_LIGHT_BLACK ... TERM_CCODE_LIGHT_WHITE:
                output_printf(o, "\e[%um", attr->bg.ccode - TERM_CCODE_LIGHT_BLACK + 100);
                break;
        }

        output_printf(o, "\e[%u;%u;%u;%u;%u;%um",
                      attr->bold ? 1 : 22,
                      attr->italic ? 3 : 23,
                      attr->underline ? 4 : 24,
                      attr->inverse ? 7 : 27,
                      attr->blink ? 5 : 25,
                      attr->hidden ? 8 : 28);

        if (n_ch < 1) {
                output_printf(o, " ");
        } else {
                for (k = 0; k < n_ch; ++k) {
                        ulen = utf8_encode_unichar(utf8, ch[k]);
                        output_write(o, utf8, ulen);
                }
        }

        return 0;
}

static void output_draw_screen(Output *o, term_screen *s) {
        assert(o);
        assert(s);

        term_screen_draw(s, output_draw_cell_fn, o, NULL);

        output_printf(o, "\e[m");
}

static void output_draw(Output *o, bool menu, term_screen *screen) {
        assert(o);

        /*
         * This renders the contenst of the terminal. The layout contains a
         * header, the main body and a footer. Around all areas we draw a
         * border. It looks something like this:
         *
         *     +----------------------------------------------------+
         *     |                      Header                        |
         *     +----------------------------------------------------+
         *     |                                                    |
         *     |                                                    |
         *     |                                                    |
         *     |                       Body                         |
         *     |                                                    |
         *     |                                                    |
         *     ~                                                    ~
         *     ~                                                    ~
         *     +----------------------------------------------------+
         *     |                      Footer                        |
         *     +----------------------------------------------------+
         *
         * The body is the part that grows vertically.
         *
         * We need at least 6 vertical lines to render the screen. This would
         * leave 0 lines for the body. Therefore, we require 7 lines so there's
         * at least one body line. Similarly, we need 2 horizontal cells for the
         * frame, so we require 3.
         * If the window is too small, we print an error message instead.
         */

        if (o->in_width < 1 || o->in_height < 1) {
                output_printf(o, "\e[2J"         /* erase-in-display: whole screen */
                                 "\e[H");        /* cursor-position: home */
                output_printf(o, "error: screen too small, need at least 3x7 cells");
                output_flush(o);
                return;
        }

        /* hide cursor */
        output_printf(o, "\e[?25l");

        /* frame-content is contant; only resizes can change it */
        if (o->resized || o->in_menu != menu) {
                output_printf(o, "\e[2J"         /* erase-in-display: whole screen */
                                 "\e[H");        /* cursor-position: home */
                output_draw_frame(o);
                o->resized = false;
                o->in_menu = menu;
        }

        /* move cursor to child's position */
        output_move_to(o, 1, 3);

        if (menu)
                output_draw_menu(o);
        else
                output_draw_screen(o, screen);

        /*
         * Hack: sd-term was not written to support TTY as output-objects, thus
         * expects callers to use term_screen_feed_keyboard(). However, we
         * forward TTY input directly. Hence, we're not notified about keypad
         * changes. Update the related modes djring redraw to keep them at least
         * in sync.
         */
        if (screen->flags & TERM_FLAG_CURSOR_KEYS)
                output_printf(o, "\e[?1h");
        else
                output_printf(o, "\e[?1l");

        if (screen->flags & TERM_FLAG_KEYPAD_MODE)
                output_printf(o, "\e=");
        else
                output_printf(o, "\e>");

        output_flush(o);
}

/*
 * Terminal Handling
 */

static void terminal_dirty(Terminal *t) {
        usec_t usec;
        int r;

        assert(t);

        if (t->is_scheduled) {
                t->is_dirty = true;
                return;
        }

        /* 16ms timer */
        r = sd_event_now(t->event, CLOCK_MONOTONIC, &usec);
        assert(r >= 0);

        usec += 16 * USEC_PER_MSEC;
        r = sd_event_source_set_time(t->frame_timer, usec);
        if (r >= 0) {
                r = sd_event_source_set_enabled(t->frame_timer, SD_EVENT_ONESHOT);
                if (r >= 0)
                        t->is_scheduled = true;
        }

        t->is_dirty = false;
        output_draw(t->output, t->is_menu, t->screen);
}

static int terminal_frame_timer_fn(sd_event_source *source, uint64_t usec, void *userdata) {
        Terminal *t = userdata;

        t->is_scheduled = false;
        if (t->is_dirty)
                terminal_dirty(t);

        return 0;
}

static int terminal_winch_fn(sd_event_source *source, const struct signalfd_siginfo *ssi, void *userdata) {
        Terminal *t = userdata;
        int r;

        output_winch(t->output);

        if (t->pty) {
                r = pty_resize(t->pty, t->output->in_width, t->output->in_height);
                if (r < 0)
                        log_error_errno(r, "error: pty_resize() (%d): %m", r);
        }

        r = term_screen_resize(t->screen, t->output->in_width, t->output->in_height);
        if (r < 0)
                log_error_errno(r, "error: term_screen_resize() (%d): %m", r);

        terminal_dirty(t);

        return 0;
}

static int terminal_push_tmp(Terminal *t, uint32_t ucs4) {
        char buf[4];
        size_t len;
        int r;

        assert(t);

        len = utf8_encode_unichar(buf, ucs4);
        if (len < 1)
                return 0;

        r = ring_push(&t->out_ring, buf, len);
        if (r < 0)
                log_oom();

        return r;
}

static int terminal_write_tmp(Terminal *t) {
        struct iovec vec[2];
        size_t num, i;
        int r;

        assert(t);

        num = ring_peek(&t->out_ring, vec);
        if (num < 1)
                return 0;

        if (t->pty) {
                for (i = 0; i < num; ++i) {
                        r = pty_write(t->pty, vec[i].iov_base, vec[i].iov_len);
                        if (r < 0)
                                return log_error_errno(r, "error: cannot write to PTY (%d): %m", r);
                }
        }

        ring_flush(&t->out_ring);
        return 0;
}

static void terminal_discard_tmp(Terminal *t) {
        assert(t);

        ring_flush(&t->out_ring);
}

static int terminal_menu(Terminal *t, const term_seq *seq) {
        switch (seq->type) {
        case TERM_SEQ_IGNORE:
                break;
        case TERM_SEQ_GRAPHIC:
                switch (seq->terminator) {
                case 'q':
                        sd_event_exit(t->event, 0);
                        return 0;
                }

                break;
        case TERM_SEQ_CONTROL:
                switch (seq->terminator) {
                case 0x03:
                        terminal_push_tmp(t, 0x03);
                        terminal_write_tmp(t);
                        break;
                }

                break;
        }

        t->is_menu = false;
        terminal_dirty(t);

        return 0;
}

static int terminal_io_fn(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Terminal *t = userdata;
        char buf[4096];
        ssize_t len, i;
        int r, type;

        len = read(fd, buf, sizeof(buf));
        if (len < 0) {
                if (errno == EAGAIN || errno == EINTR)
                        return 0;

                log_error_errno(errno, "error: cannot read from TTY (%d): %m", -errno);
                return -errno;
        }

        for (i = 0; i < len; ++i) {
                const term_seq *seq;
                uint32_t *str;
                size_t n_str, j;

                n_str = term_utf8_decode(&t->utf8, &str, buf[i]);
                for (j = 0; j < n_str; ++j) {
                        type = term_parser_feed(t->parser, &seq, str[j]);
                        if (type < 0)
                                return log_error_errno(type, "error: term_parser_feed() (%d): %m", type);

                        if (!t->is_menu) {
                                r = terminal_push_tmp(t, str[j]);
                                if (r < 0)
                                        return r;
                        }

                        if (type == TERM_SEQ_NONE) {
                                /* We only intercept one-char sequences, so in
                                 * case term_parser_feed() couldn't parse a
                                 * sequence, it is waiting for more data. We
                                 * know it can never be a one-char sequence
                                 * then, so we can safely forward the data.
                                 * This avoids withholding ESC or other values
                                 * that may be one-shot depending on the
                                 * application. */
                                r = terminal_write_tmp(t);
                                if (r < 0)
                                        return r;
                        } else if (t->is_menu) {
                                r = terminal_menu(t, seq);
                                if (r < 0)
                                        return r;
                        } else if (seq->type == TERM_SEQ_CONTROL && seq->terminator == 0x03) { /* ^C opens the menu */
                                terminal_discard_tmp(t);
                                t->is_menu = true;
                                terminal_dirty(t);
                        } else {
                                r = terminal_write_tmp(t);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        return 0;
}

static int terminal_pty_fn(Pty *pty, void *userdata, unsigned int event, const void *ptr, size_t size) {
        Terminal *t = userdata;
        int r;

        switch (event) {
        case PTY_CHILD:
                sd_event_exit(t->event, 0);
                break;
        case PTY_DATA:
                r = term_screen_feed_text(t->screen, ptr, size);
                if (r < 0)
                        return log_error_errno(r, "error: term_screen_feed_text() (%d): %m", r);

                terminal_dirty(t);
                break;
        }

        return 0;
}

static int terminal_write_fn(term_screen *screen, void *userdata, const void *buf, size_t size) {
        Terminal *t = userdata;
        int r;

        if (!t->pty)
                return 0;

        r = ring_push(&t->out_ring, buf, size);
        if (r < 0)
                log_oom();

        return r;
}

static int terminal_cmd_fn(term_screen *screen, void *userdata, unsigned int cmd, const term_seq *seq) {
        return 0;
}

static Terminal *terminal_free(Terminal *t) {
        if (!t)
                return NULL;

        ring_clear(&t->out_ring);
        term_screen_unref(t->screen);
        term_parser_free(t->parser);
        output_free(t->output);
        sd_event_source_unref(t->frame_timer);
        sd_event_unref(t->event);
        tcsetattr(t->in_fd, TCSANOW, &t->saved_in_attr);
        tcsetattr(t->out_fd, TCSANOW, &t->saved_out_attr);
        free(t);

        return NULL;
}

static int terminal_new(Terminal **out, int in_fd, int out_fd) {
        struct termios in_attr, out_attr;
        Terminal *t;
        int r;

        assert_return(out, -EINVAL);

        r = tcgetattr(in_fd, &in_attr);
        if (r < 0)
                return log_error_errno(errno, "error: tcgetattr() (%d): %m", -errno);

        r = tcgetattr(out_fd, &out_attr);
        if (r < 0)
                return log_error_errno(errno, "error: tcgetattr() (%d): %m", -errno);

        t = new0(Terminal, 1);
        if (!t)
                return log_oom();

        t->in_fd = in_fd;
        t->out_fd = out_fd;
        memcpy(&t->saved_in_attr, &in_attr, sizeof(in_attr));
        memcpy(&t->saved_out_attr, &out_attr, sizeof(out_attr));

        cfmakeraw(&in_attr);
        cfmakeraw(&out_attr);

        r = tcsetattr(t->in_fd, TCSANOW, &in_attr);
        if (r < 0) {
                log_error_errno(r, "error: tcsetattr() (%d): %m", r);
                goto error;
        }

        r = tcsetattr(t->out_fd, TCSANOW, &out_attr);
        if (r < 0) {
                log_error_errno(r, "error: tcsetattr() (%d): %m", r);
                goto error;
        }

        r = sd_event_default(&t->event);
        if (r < 0) {
                log_error_errno(r, "error: sd_event_default() (%d): %m", r);
                goto error;
        }

        r = sigprocmask_many(SIG_BLOCK, NULL, SIGINT, SIGQUIT, SIGTERM, SIGWINCH, SIGCHLD, -1);
        if (r < 0) {
                log_error_errno(r, "error: sigprocmask_many() (%d): %m", r);
                goto error;
        }

        r = sd_event_add_signal(t->event, NULL, SIGINT, NULL, NULL);
        if (r < 0) {
                log_error_errno(r, "error: sd_event_add_signal() (%d): %m", r);
                goto error;
        }

        r = sd_event_add_signal(t->event, NULL, SIGQUIT, NULL, NULL);
        if (r < 0) {
                log_error_errno(r, "error: sd_event_add_signal() (%d): %m", r);
                goto error;
        }

        r = sd_event_add_signal(t->event, NULL, SIGTERM, NULL, NULL);
        if (r < 0) {
                log_error_errno(r, "error: sd_event_add_signal() (%d): %m", r);
                goto error;
        }

        r = sd_event_add_signal(t->event, NULL, SIGWINCH, terminal_winch_fn, t);
        if (r < 0) {
                log_error_errno(r, "error: sd_event_add_signal() (%d): %m", r);
                goto error;
        }

        /* force initial redraw on event-loop enter */
        t->is_dirty = true;
        r = sd_event_add_time(t->event, &t->frame_timer, CLOCK_MONOTONIC, 0, 0, terminal_frame_timer_fn, t);
        if (r < 0) {
                log_error_errno(r, "error: sd_event_add_time() (%d): %m", r);
                goto error;
        }

        r = output_new(&t->output, out_fd);
        if (r < 0)
                goto error;

        r = term_parser_new(&t->parser, true);
        if (r < 0)
                goto error;

        r = term_screen_new(&t->screen, terminal_write_fn, t, terminal_cmd_fn, t);
        if (r < 0)
                goto error;

        r = term_screen_set_answerback(t->screen, "systemd-subterm");
        if (r < 0)
                goto error;

        r = term_screen_resize(t->screen, t->output->in_width, t->output->in_height);
        if (r < 0) {
                log_error_errno(r, "error: term_screen_resize() (%d): %m", r);
                goto error;
        }

        r = sd_event_add_io(t->event, NULL, in_fd, EPOLLIN, terminal_io_fn, t);
        if (r < 0)
                goto error;

        *out = t;
        return 0;

error:
        terminal_free(t);
        return r;
}

static int terminal_run(Terminal *t) {
        pid_t pid;

        assert_return(t, -EINVAL);

        pid = pty_fork(&t->pty, t->event, terminal_pty_fn, t, t->output->in_width, t->output->in_height);
        if (pid < 0)
                return log_error_errno(pid, "error: cannot fork PTY (%d): %m", pid);
        else if (pid == 0) {
                /* child */

                char **argv = (char*[]){
                        (char*)getenv("SHELL") ? : (char*)_PATH_BSHELL,
                        NULL
                };

                setenv("TERM", "xterm-256color", 1);
                setenv("COLORTERM", "systemd-subterm", 1);

                execve(argv[0], argv, environ);
                log_error_errno(errno, "error: cannot exec %s (%d): %m", argv[0], -errno);
                _exit(1);
        }

        /* parent */

        return sd_event_loop(t->event);
}

/*
 * Context Handling
 */

int main(int argc, char *argv[]) {
        Terminal *t = NULL;
        int r;

        r = terminal_new(&t, 0, 1);
        if (r < 0)
                goto out;

        r = terminal_run(t);
        if (r < 0)
                goto out;

out:
        if (r < 0)
                log_error_errno(r, "error: terminal failed (%d): %m", r);
        terminal_free(t);
        return -r;
}
