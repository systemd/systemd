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

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "util.h"

typedef struct term_color term_color;
typedef struct term_attr term_attr;

typedef struct term_utf8 term_utf8;
typedef struct term_seq term_seq;
typedef struct term_parser term_parser;

typedef struct term_screen term_screen;

/*
 * Ageing
 */

typedef uint64_t term_age_t;

#define TERM_AGE_NULL 0

/*
 * Attributes
 */

enum {
        /* special color-codes */
        TERM_CCODE_DEFAULT,                                             /* default foreground/background color */
        TERM_CCODE_256,                                                 /* 256color code */
        TERM_CCODE_RGB,                                                 /* color is specified as RGB */

        /* dark color-codes */
        TERM_CCODE_BLACK,
        TERM_CCODE_RED,
        TERM_CCODE_GREEN,
        TERM_CCODE_YELLOW,
        TERM_CCODE_BLUE,
        TERM_CCODE_MAGENTA,
        TERM_CCODE_CYAN,
        TERM_CCODE_WHITE,                                               /* technically: light grey */

        /* light color-codes */
        TERM_CCODE_LIGHT_BLACK          = TERM_CCODE_BLACK + 8,         /* technically: dark grey */
        TERM_CCODE_LIGHT_RED            = TERM_CCODE_RED + 8,
        TERM_CCODE_LIGHT_GREEN          = TERM_CCODE_GREEN + 8,
        TERM_CCODE_LIGHT_YELLOW         = TERM_CCODE_YELLOW + 8,
        TERM_CCODE_LIGHT_BLUE           = TERM_CCODE_BLUE + 8,
        TERM_CCODE_LIGHT_MAGENTA        = TERM_CCODE_MAGENTA + 8,
        TERM_CCODE_LIGHT_CYAN           = TERM_CCODE_CYAN + 8,
        TERM_CCODE_LIGHT_WHITE          = TERM_CCODE_WHITE + 8,

        TERM_CCODE_CNT,
};

struct term_color {
        uint8_t ccode;
        uint8_t c256;
        uint8_t red;
        uint8_t green;
        uint8_t blue;
};

struct term_attr {
        term_color fg;                          /* foreground color */
        term_color bg;                          /* background color */

        unsigned int bold : 1;                  /* bold font */
        unsigned int italic : 1;                /* italic font */
        unsigned int underline : 1;             /* underline text */
        unsigned int inverse : 1;               /* inverse fg/bg */
        unsigned int protect : 1;               /* protect from erase */
        unsigned int blink : 1;                 /* blink text */
        unsigned int hidden : 1;                /* hidden */
};

void term_attr_to_argb32(const term_attr *attr, uint32_t *fg, uint32_t *bg, const uint8_t *palette);

/*
 * UTF-8
 */

struct term_utf8 {
        uint32_t chars[5];
        uint32_t ucs4;

        unsigned int i_bytes : 3;
        unsigned int n_bytes : 3;
        unsigned int valid : 1;
};

size_t term_utf8_decode(term_utf8 *p, uint32_t **out_buf, char c);

/*
 * Parsers
 */

int term_parser_new(term_parser **out, bool host);
term_parser *term_parser_free(term_parser *parser);
int term_parser_feed(term_parser *parser, const term_seq **seq_out, uint32_t raw);

#define _term_parser_free_ _cleanup_(term_parser_freep)
DEFINE_TRIVIAL_CLEANUP_FUNC(term_parser*, term_parser_free);

/*
 * Screens
 */

enum {
        TERM_KBDMOD_IDX_SHIFT,
        TERM_KBDMOD_IDX_CTRL,
        TERM_KBDMOD_IDX_ALT,
        TERM_KBDMOD_IDX_LINUX,
        TERM_KBDMOD_IDX_CAPS,
        TERM_KBDMOD_CNT,

        TERM_KBDMOD_SHIFT               = 1 << TERM_KBDMOD_IDX_SHIFT,
        TERM_KBDMOD_CTRL                = 1 << TERM_KBDMOD_IDX_CTRL,
        TERM_KBDMOD_ALT                 = 1 << TERM_KBDMOD_IDX_ALT,
        TERM_KBDMOD_LINUX               = 1 << TERM_KBDMOD_IDX_LINUX,
        TERM_KBDMOD_CAPS                = 1 << TERM_KBDMOD_IDX_CAPS,
};

typedef int (*term_screen_write_fn) (term_screen *screen, void *userdata, const void *buf, size_t size);
typedef int (*term_screen_cmd_fn) (term_screen *screen, void *userdata, unsigned int cmd, const term_seq *seq);

int term_screen_new(term_screen **out, term_screen_write_fn write_fn, void *write_fn_data, term_screen_cmd_fn cmd_fn, void *cmd_fn_data);
term_screen *term_screen_ref(term_screen *screen);
term_screen *term_screen_unref(term_screen *screen);

DEFINE_TRIVIAL_CLEANUP_FUNC(term_screen*, term_screen_unref);

unsigned int term_screen_get_width(term_screen *screen);
unsigned int term_screen_get_height(term_screen *screen);
uint64_t term_screen_get_age(term_screen *screen);

int term_screen_feed_text(term_screen *screen, const uint8_t *in, size_t size);
int term_screen_feed_keyboard(term_screen *screen,
                              const uint32_t *keysyms,
                              size_t n_syms,
                              uint32_t ascii,
                              const uint32_t *ucs4,
                              unsigned int mods);
int term_screen_resize(term_screen *screen, unsigned int width, unsigned int height);
void term_screen_soft_reset(term_screen *screen);
void term_screen_hard_reset(term_screen *screen);

int term_screen_set_answerback(term_screen *screen, const char *answerback);

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
                     uint64_t *fb_age);
