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

typedef struct term_char term_char_t;
typedef struct term_charbuf term_charbuf_t;

typedef struct term_color term_color;
typedef struct term_attr term_attr;
typedef struct term_cell term_cell;
typedef struct term_line term_line;

typedef struct term_page term_page;
typedef struct term_history term_history;

/*
 * Miscellaneous
 * Sundry things and external helpers.
 */

int mk_wcwidth(wchar_t ucs4);
int mk_wcwidth_cjk(wchar_t ucs4);
int mk_wcswidth(const wchar_t *str, size_t len);
int mk_wcswidth_cjk(const wchar_t *str, size_t len);

/*
 * Ageing
 * Redrawing terminals is quite expensive. Therefore, we avoid redrawing on
 * each single modification and mark modified cells instead. This way, we know
 * which cells to redraw on the next frame. However, a single DIRTY flag is not
 * enough for double/triple buffered screens, hence, we use an AGE field for
 * each cell. If the cell is modified, we simply increase the age by one. Each
 * framebuffer can then remember its last rendered age and request an update of
 * all newer cells.
 * TERM_AGE_NULL is special. If used as cell age, the cell must always be
 * redrawn (forced update). If used as framebuffer age, all cells are drawn.
 * This way, we can allow integer wrap-arounds.
 */

typedef uint64_t term_age_t;

#define TERM_AGE_NULL 0

/*
 * Characters
 * Each cell in a terminal page contains only a single character. This is
 * usually a single UCS-4 value. However, Unicode allows combining-characters,
 * therefore, the number of UCS-4 characters per cell must be unlimited. The
 * term_char_t object wraps the internal combining char API so it can be
 * treated as a single object.
 */

struct term_char {
        /* never access this value directly */
        uint64_t _value;
};

struct term_charbuf {
        /* 3 bytes + zero-terminator */
        uint32_t buf[4];
};

#define TERM_CHAR_INIT(_val) ((term_char_t){ ._value = (_val) })
#define TERM_CHAR_NULL TERM_CHAR_INIT(0)

term_char_t term_char_set(term_char_t previous, uint32_t append_ucs4);
term_char_t term_char_merge(term_char_t base, uint32_t append_ucs4);
term_char_t term_char_dup(term_char_t ch);
term_char_t term_char_dup_append(term_char_t base, uint32_t append_ucs4);

const uint32_t *term_char_resolve(term_char_t ch, size_t *s, term_charbuf_t *b);
unsigned int term_char_lookup_width(term_char_t ch);

/* true if @ch is TERM_CHAR_NULL, otherwise false */
static inline bool term_char_is_null(term_char_t ch) {
        return ch._value == 0;
}

/* true if @ch is dynamically allocated and needs to be freed */
static inline bool term_char_is_allocated(term_char_t ch) {
        return !term_char_is_null(ch) && !(ch._value & 0x1);
}

/* true if (a == b), otherwise false; this is (a == b), NOT (*a == *b) */
static inline bool term_char_same(term_char_t a, term_char_t b) {
        return a._value == b._value;
}

/* true if (*a == *b), otherwise false; this is implied by (a == b) */
static inline bool term_char_equal(term_char_t a, term_char_t b) {
        const uint32_t *sa, *sb;
        term_charbuf_t ca, cb;
        size_t na, nb;

        sa = term_char_resolve(a, &na, &ca);
        sb = term_char_resolve(b, &nb, &cb);
        return na == nb && !memcmp(sa, sb, sizeof(*sa) * na);
}

/* free @ch in case it is dynamically allocated */
static inline term_char_t term_char_free(term_char_t ch) {
        if (term_char_is_allocated(ch))
                term_char_set(ch, 0);

        return TERM_CHAR_NULL;
}

/* gcc _cleanup_ helpers */
#define _term_char_free_ _cleanup_(term_char_freep)
static inline void term_char_freep(term_char_t *p) {
        term_char_free(*p);
}

/*
 * Attributes
 * Each cell in a terminal page can have its own set of attributes. These alter
 * the behavior of the renderer for this single cell. We use term_attr to
 * specify attributes.
 * The only non-obvious field is "ccode" for foreground and background colors.
 * This field contains the terminal color-code in case no full RGB information
 * was given by the host. It is also required for dynamic color palettes. If it
 * is set to TERM_CCODE_RGB, the "red", "green" and "blue" fields contain the
 * full RGB color.
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

/*
 * Cells
 * The term_cell structure respresents a single cell in a terminal page. It
 * contains the stored character, the age of the cell and all its attributes.
 */

struct term_cell {
        term_char_t ch;         /* stored char or TERM_CHAR_NULL */
        term_age_t age;         /* cell age or TERM_AGE_NULL */
        term_attr attr;         /* cell attributes */
        unsigned int cwidth;    /* cached term_char_lookup_width(cell->ch) */
};

/*
 * Lines
 * Instead of storing cells in a 2D array, we store them in an array of
 * dynamically allocated lines. This way, scrolling can be implemented very
 * fast without moving any cells at all. Similarly, the scrollback-buffer is
 * much simpler to implement.
 * We use term_line to store a single line. It contains an array of cells, a
 * fill-state which remembers the amount of blanks on the right side, a
 * separate age just for the line which can overwrite the age for all cells,
 * and some management data.
 */

struct term_line {
        term_line *lines_next;          /* linked-list for histories */
        term_line *lines_prev;          /* linked-list for histories */

        unsigned int width;             /* visible width of line */
        unsigned int n_cells;           /* # of allocated cells */
        term_cell *cells;               /* cell-array */

        term_age_t age;                 /* line age */
        unsigned int fill;              /* # of valid cells; starting left */
};

int term_line_new(term_line **out);
term_line *term_line_free(term_line *line);

#define _term_line_free_ _cleanup_(term_line_freep)
DEFINE_TRIVIAL_CLEANUP_FUNC(term_line*, term_line_free);

int term_line_reserve(term_line *line, unsigned int width, const term_attr *attr, term_age_t age, unsigned int protect_width);
void term_line_set_width(term_line *line, unsigned int width);
void term_line_write(term_line *line, unsigned int pos_x, term_char_t ch, unsigned int cwidth, const term_attr *attr, term_age_t age, bool insert_mode);
void term_line_insert(term_line *line, unsigned int from, unsigned int num, const term_attr *attr, term_age_t age);
void term_line_delete(term_line *line, unsigned int from, unsigned int num, const term_attr *attr, term_age_t age);
void term_line_append_combchar(term_line *line, unsigned int pos_x, uint32_t ucs4, term_age_t age);
void term_line_erase(term_line *line, unsigned int from, unsigned int num, const term_attr *attr, term_age_t age, bool keep_protected);
void term_line_reset(term_line *line, const term_attr *attr, term_age_t age);

void term_line_link(term_line *line, term_line **first, term_line **last);
void term_line_link_tail(term_line *line, term_line **first, term_line **last);
void term_line_unlink(term_line *line, term_line **first, term_line **last);

#define TERM_LINE_LINK(_line, _head) term_line_link((_line), &(_head)->lines_first, &(_head)->lines_last)
#define TERM_LINE_LINK_TAIL(_line, _head) term_line_link_tail((_line), &(_head)->lines_first, &(_head)->lines_last)
#define TERM_LINE_UNLINK(_line, _head) term_line_unlink((_line), &(_head)->lines_first, &(_head)->lines_last)

/*
 * Pages
 * A page represents the 2D table containing all cells of a terminal. It stores
 * lines as an array of pointers so scrolling becomes a simple line-shuffle
 * operation.
 * Scrolling is always targeted only at the scroll-region defined via scroll_idx
 * and scroll_num. The fill-state keeps track of the number of touched lines in
 * the scroll-region. @width and @height describe the visible region of the page
 * and are guaranteed to be allocated at all times.
 */

struct term_page {
        term_age_t age;                 /* page age */

        term_line **lines;              /* array of line-pointers */
        term_line **line_cache;         /* cache for temporary operations */
        unsigned int n_lines;           /* # of allocated lines */

        unsigned int width;             /* width of visible area */
        unsigned int height;            /* height of visible area */
        unsigned int scroll_idx;        /* scrolling-region start index */
        unsigned int scroll_num;        /* scrolling-region length in lines */
        unsigned int scroll_fill;       /* # of valid scroll-lines */
};

int term_page_new(term_page **out);
term_page *term_page_free(term_page *page);

#define _term_page_free_ _cleanup_(term_page_freep)
DEFINE_TRIVIAL_CLEANUP_FUNC(term_page*, term_page_free);

term_cell *term_page_get_cell(term_page *page, unsigned int x, unsigned int y);

int term_page_reserve(term_page *page, unsigned int cols, unsigned int rows, const term_attr *attr, term_age_t age);
void term_page_resize(term_page *page, unsigned int cols, unsigned int rows, const term_attr *attr, term_age_t age, term_history *history);
void term_page_write(term_page *page, unsigned int pos_x, unsigned int pos_y, term_char_t ch, unsigned int cwidth, const term_attr *attr, term_age_t age, bool insert_mode);
void term_page_insert_cells(term_page *page, unsigned int from_x, unsigned int from_y, unsigned int num, const term_attr *attr, term_age_t age);
void term_page_delete_cells(term_page *page, unsigned int from_x, unsigned int from_y, unsigned int num, const term_attr *attr, term_age_t age);
void term_page_append_combchar(term_page *page, unsigned int pos_x, unsigned int pos_y, uint32_t ucs4, term_age_t age);
void term_page_erase(term_page *page, unsigned int from_x, unsigned int from_y, unsigned int to_x, unsigned int to_y, const term_attr *attr, term_age_t age, bool keep_protected);
void term_page_reset(term_page *page, const term_attr *attr, term_age_t age);

void term_page_set_scroll_region(term_page *page, unsigned int idx, unsigned int num);
void term_page_scroll_up(term_page *page, unsigned int num, const term_attr *attr, term_age_t age, term_history *history);
void term_page_scroll_down(term_page *page, unsigned int num, const term_attr *attr, term_age_t age, term_history *history);
void term_page_insert_lines(term_page *page, unsigned int pos_y, unsigned int num, const term_attr *attr, term_age_t age);
void term_page_delete_lines(term_page *page, unsigned int pos_y, unsigned int num, const term_attr *attr, term_age_t age);

/*
 * Histories
 * Scroll-back buffers use term_history objects to store scroll-back lines. A
 * page is independent of the history used. All page operations that modify a
 * history take it as separate argument. You're free to pass NULL at all times
 * if no history should be used.
 * Lines are stored in a linked list as no complex operations are ever done on
 * history lines, besides pushing/poping. Note that history lines do not have a
 * guaranteed minimum length. Any kind of line might be stored there. Missing
 * cells should be cleared to the background color.
 */

struct term_history {
        term_line *lines_first;
        term_line *lines_last;
        unsigned int n_lines;
        unsigned int max_lines;
};

int term_history_new(term_history **out);
term_history *term_history_free(term_history *history);

#define _term_history_free_ _cleanup_(term_history_freep)
DEFINE_TRIVIAL_CLEANUP_FUNC(term_history*, term_history_free);

void term_history_clear(term_history *history);
void term_history_trim(term_history *history, unsigned int max);
void term_history_push(term_history *history, term_line *line);
term_line *term_history_pop(term_history *history, unsigned int reserve_width, const term_attr *attr, term_age_t age);
unsigned int term_history_peek(term_history *history, unsigned int max, unsigned int reserve_width, const term_attr *attr, term_age_t age);
