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
 * Terminal Page/Line/Cell/Char Tests
 * This tests internals of terminal page, line, cell and char handling. It
 * relies on some implementation details, so it might need to be updated if
 * those internals are changed. They should be fairly obvious, though.
 */

#include <stdio.h>
#include <string.h>
#include "macro.h"
#include "term-internal.h"

#define MY_ASSERT_VALS __FILE__, __LINE__, __PRETTY_FUNCTION__
#define MY_ASSERT_FORW _FILE, _LINE, _FUNC
#define MY_ASSERT_ARGS const char *_FILE, int _LINE, const char *_FUNC
#define MY_ASSERT(expr)                                                 \
        do {                                                            \
                if (_unlikely_(!(expr)))                                \
                        log_assert_failed(#expr, _FILE, _LINE, _FUNC);  \
        } while (false)                                                 \

/*
 * Character Tests
 *
 * These tests rely on some implementation details of term_char_t, including
 * the way we pack characters and the internal layout of "term_char_t". These
 * tests have to be updated once we change the implementation.
 */

#define PACK(v1, v2, v3) \
                TERM_CHAR_INIT( \
                        (((((uint64_t)v1) & 0x1fffffULL) << 43) | \
                         ((((uint64_t)v2) & 0x1fffffULL) << 22) | \
                         ((((uint64_t)v3) & 0x1fffffULL) <<  1) | \
                         0x1) \
                )
#define PACK1(v1) PACK2((v1), 0x110000)
#define PACK2(v1, v2) PACK3((v1), (v2), 0x110000)
#define PACK3(v1, v2, v3) PACK((v1), (v2), (v3))

static void test_term_char_misc(void) {
        term_char_t c, t;

        /* test TERM_CHAR_NULL handling */

        c = TERM_CHAR_NULL;                     /* c is NULL */
        assert_se(term_char_same(c, TERM_CHAR_NULL));
        assert_se(term_char_equal(c, TERM_CHAR_NULL));
        assert_se(term_char_is_null(c));
        assert_se(term_char_is_null(TERM_CHAR_NULL));
        assert_se(!term_char_is_allocated(c));

        /* test single char handling */

        t = term_char_dup_append(c, 'A');       /* t is >A< now */
        assert_se(!term_char_same(c, t));
        assert_se(!term_char_equal(c, t));
        assert_se(!term_char_is_allocated(t));
        assert_se(!term_char_is_null(t));

        /* test basic combined char handling */

        t = term_char_dup_append(t, '~');
        t = term_char_dup_append(t, '^');       /* t is >A~^< now */
        assert_se(!term_char_same(c, t));
        assert_se(!term_char_is_allocated(t));
        assert_se(!term_char_is_null(t));

        c = term_char_dup_append(c, 'A');
        c = term_char_dup_append(c, '~');
        c = term_char_dup_append(c, '^');       /* c is >A~^< now */
        assert_se(term_char_same(c, t));
        assert_se(term_char_equal(c, t));

        /* test more than 2 comb-chars so the chars are allocated */

        t = term_char_dup_append(t, '`');       /* t is >A~^`< now */
        c = term_char_dup_append(c, '`');       /* c is >A~^`< now */
        assert_se(!term_char_same(c, t));
        assert_se(term_char_equal(c, t));

        /* test dup_append() on allocated chars */

        term_char_free(t);
        t = term_char_dup_append(c, '"');       /* t is >A~^`"< now */
        assert_se(!term_char_same(c, t));
        assert_se(!term_char_equal(c, t));
        c = term_char_merge(c, '"');            /* c is >A~^`"< now */
        assert_se(!term_char_same(c, t));
        assert_se(term_char_equal(c, t));

        term_char_free(t);
        term_char_free(c);
}

static void test_term_char_packing(void)  {
        uint32_t seqs[][1024] = {
                { -1 },
                { 0, -1 },
                { 'A', '~', -1 },
                { 'A', '~', 0, -1 },
                { 'A', '~', 'a', -1 },
        };
        term_char_t res[] = {
                TERM_CHAR_NULL,
                PACK1(0),
                PACK2('A', '~'),
                PACK3('A', '~', 0),
                PACK3('A', '~', 'a'),
        };
        uint32_t next;
        unsigned int i, j;
        term_char_t c = TERM_CHAR_NULL;

        /*
         * This creates term_char_t objects based on the data in @seqs and
         * compares the result to @res. Only basic packed types are tested, no
         * allocations are done.
         */

        for (i = 0; i < ELEMENTSOF(seqs); ++i) {
                for (j = 0; j < ELEMENTSOF(seqs[i]); ++j) {
                        next = seqs[i][j];
                        if (next == (uint32_t)-1)
                                break;

                        c = term_char_merge(c, next);
                }

                assert_se(!memcmp(&c, &res[i], sizeof(c)));
                c = term_char_free(c);
        }
}

static void test_term_char_allocating(void) {
        uint32_t seqs[][1024] = {
                { 0, -1 },
                { 'A', '~', -1 },
                { 'A', '~', 0, -1 },
                { 'A', '~', 'a', -1 },
                { 'A', '~', 'a', 'b', 'c', 'd', -1 },
                { 'A', '~', 'a', 'b', 'c', 'd', 0, '^', -1 },
                /* exceeding implementation-defined soft-limit of 64 */
                { 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
                  'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
                  'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
                  'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
                  'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
                  'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
                  'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
                  'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', -1 },
        };
        term_char_t res[] = {
                PACK1(0),
                PACK2('A', '~'),
                PACK3('A', '~', 0),
                PACK3('A', '~', 'a'),
                TERM_CHAR_NULL,                 /* allocated */
                TERM_CHAR_NULL,                 /* allocated */
                TERM_CHAR_NULL,                 /* allocated */
        };
        uint32_t str[][1024] = {
                { 0, -1 },
                { 'A', '~', -1 },
                { 'A', '~', 0, -1 },
                { 'A', '~', 'a', -1 },
                { 'A', '~', 'a', 'b', 'c', 'd', -1 },
                { 'A', '~', 'a', 'b', 'c', 'd', 0, '^', -1 },
                { 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
                  'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
                  'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
                  'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
                  'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
                  'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
                  'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
                  'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', -1 },
        };
        size_t n;
        uint32_t next;
        unsigned int i, j;
        const uint32_t *t;

        /*
         * This builds term_char_t objects based on the data in @seqs. It
         * compares the result to @res for packed chars, otherwise it requires
         * them to be allocated.
         * After that, we resolve the UCS-4 string and compare it to the
         * expected strings in @str.
         */

        for (i = 0; i < ELEMENTSOF(seqs); ++i) {
                _term_char_free_ term_char_t c = TERM_CHAR_NULL;

                for (j = 0; j < ELEMENTSOF(seqs[i]); ++j) {
                        next = seqs[i][j];
                        if (next == (uint32_t)-1)
                                break;

                        c = term_char_merge(c, next);
                }

                /* we use TERM_CHAR_NULL as marker for allocated chars here */
                if (term_char_is_null(res[i]))
                        assert_se(term_char_is_allocated(c));
                else
                        assert_se(!memcmp(&c, &res[i], sizeof(c)));

                t = term_char_resolve(c, &n, NULL);
                for (j = 0; j < ELEMENTSOF(str[i]); ++j) {
                        next = str[i][j];
                        if (next == (uint32_t)-1)
                                break;

                        assert_se(t[j] == next);
                }

                assert_se(n == j);
        }
}

/*
 * Line Tests
 *
 * The following tests work on term_line objects and verify their behavior when
 * we modify them. To verify and set line layouts, we have two simple helpers
 * to avoid harcoding the cell-verification all the time:
 *   line_set(): Set a line to a given layout
 *   line_assert(): Verify that a line has a given layout
 *
 * These functions take the line-layout encoded as a string and verify it
 * against, or set it on, a term_line object. The format used to describe a
 * line looks like this:
 *       example: "|   | A |   |   |   |   |   | 10 *AB* |"
 *
 * The string describes the contents of all cells of a line, separated by
 * pipe-symbols ('|'). Whitespace are ignored, the leading pipe-symbol is
 * optional.
 * The description of each cell can contain an arbitrary amount of characters
 * in the range 'A'-'Z', 'a'-'z'. All those are combined and used as term_char_t
 * on this cell. Any numbers in the description are combined and are used as
 * cell-age.
 * The occurrence of a '*'-symbol marks the cell as bold, '/' marks it as italic.
 * You can use those characters multiple times, but only the first one has an
 * effect.
 * For further symbols, see parse_attr().
 *
 * Therefore, the following descriptions are equivalent:
 *       1) "|   | /A*   |   |   |   |   |   | 10 *AB*  |"
 *       2) "|   | /A**  |   |   |   |   |   | 10 *AB*  |"
 *       3) "|   | A* // |   |   |   |   |   | 10 *AB*  |"
 *       4) "|   | A* // |   |   |   |   |   | 1 *AB* 0 |"
 *       5) "|   | A* // |   |   |   |   |   | A1B0*    |"
 *
 * The parser isn't very strict about placement of alpha/numerical characters,
 * but simply appends all found chars. Don't make use of that feature! It's
 * just a stupid parser to simplify these tests. Make them readable!
 */

static void parse_attr(char c, term_char_t *ch, term_attr *attr, term_age_t *age) {
        switch (c) {
        case ' ':
                /* ignore */
                break;
        case '0' ... '9':
                /* increase age */
                *age = *age * 10;
                *age = *age + c - '0';
                break;
        case 'A' ... 'Z':
        case 'a' ... 'z':
                /* add to character */
                *ch = term_char_merge(*ch, c);
                break;
        case '*':
                attr->bold = true;
                break;
        case '/':
                attr->italic = true;
                break;
        default:
                assert_se(0);
                break;
        }
}

static void cell_assert(MY_ASSERT_ARGS, term_cell *c, term_char_t ch, const term_attr *attr, term_age_t age) {
        MY_ASSERT(term_char_equal(c->ch, ch));
        MY_ASSERT(!memcmp(&c->attr, attr, sizeof(*attr)));
        MY_ASSERT(c->age == age);
}
#define CELL_ASSERT(_cell, _ch, _attr, _age) cell_assert(MY_ASSERT_VALS, (_cell), (_ch), (_attr), (_age))

static void line_assert(MY_ASSERT_ARGS, term_line *l, const char *str, unsigned int fill) {
        unsigned int cell_i;
        term_char_t ch = TERM_CHAR_NULL;
        term_attr attr = { };
        term_age_t age = TERM_AGE_NULL;
        char c;

        assert_se(l->fill == fill);

        /* skip leading whitespace */
        while (*str == ' ')
                ++str;

        /* skip leading '|' */
        if (*str == '|')
                ++str;

        cell_i = 0;
        while ((c = *str++)) {
                switch (c) {
                case '|':
                        /* end of cell-description; compare it */
                        assert_se(cell_i < l->n_cells);
                        cell_assert(MY_ASSERT_FORW,
                                    &l->cells[cell_i],
                                    ch,
                                    &attr,
                                    age);

                        ++cell_i;
                        ch = term_char_free(ch);
                        zero(attr);
                        age = TERM_AGE_NULL;
                        break;
                default:
                        parse_attr(c, &ch, &attr, &age);
                        break;
                }
        }

        assert_se(cell_i == l->n_cells);
}
#define LINE_ASSERT(_line, _str, _fill) line_assert(MY_ASSERT_VALS, (_line), (_str), (_fill))

static void line_set(term_line *l, unsigned int pos, const char *str, bool insert_mode) {
        term_char_t ch = TERM_CHAR_NULL;
        term_attr attr = { };
        term_age_t age = TERM_AGE_NULL;
        char c;

        while ((c = *str++))
                parse_attr(c, &ch, &attr, &age);

        term_line_write(l, pos, ch, 1, &attr, age, insert_mode);
}

static void line_resize(term_line *l, unsigned int width, const term_attr *attr, term_age_t age) {
        assert_se(term_line_reserve(l, width, attr, age, width) >= 0);
        term_line_set_width(l, width);
}

static void test_term_line_misc(void) {
        term_line *l;

        assert_se(term_line_new(&l) >= 0);
        assert_se(!term_line_free(l));

        assert_se(term_line_new(NULL) < 0);
        assert_se(!term_line_free(NULL));

        assert_se(term_line_new(&l) >= 0);
        assert_se(l->n_cells == 0);
        assert_se(l->fill == 0);
        assert_se(term_line_reserve(l, 16, NULL, 0, 0) >= 0);
        assert_se(l->n_cells == 16);
        assert_se(l->fill == 0);
        assert_se(term_line_reserve(l, 512, NULL, 0, 0) >= 0);
        assert_se(l->n_cells == 512);
        assert_se(l->fill == 0);
        assert_se(term_line_reserve(l, 16, NULL, 0, 0) >= 0);
        assert_se(l->n_cells == 512);
        assert_se(l->fill == 0);
        assert_se(!term_line_free(l));
}

static void test_term_line_ops(void) {
        term_line *l;
        term_attr attr_regular = { };
        term_attr attr_bold = { .bold = true };
        term_attr attr_italic = { .italic = true };

        assert_se(term_line_new(&l) >= 0);
        line_resize(l, 8, NULL, 0);
        assert_se(l->n_cells == 8);

        LINE_ASSERT(l, "| | | | | | | | |", 0);

        term_line_write(l, 4, TERM_CHAR_NULL, 0, NULL, TERM_AGE_NULL, 0);
        LINE_ASSERT(l, "| | | | | | | | |", 5);

        term_line_write(l, 1, PACK1('A'), 1, NULL, TERM_AGE_NULL, 0);
        LINE_ASSERT(l, "| |A| | | | | | |", 5);

        term_line_write(l, 8, PACK2('A', 'B'), 1, NULL, TERM_AGE_NULL, 0);
        LINE_ASSERT(l, "| |A| | | | | | |", 5);

        term_line_write(l, 7, PACK2('A', 'B'), 1, &attr_regular, 10, 0);
        LINE_ASSERT(l, "| |A| | | | | | 10 AB |", 8);

        term_line_write(l, 7, PACK2('A', 'B'), 1, &attr_bold, 10, 0);
        LINE_ASSERT(l, "| |A| | | | | | 10 *AB* |", 8);

        term_line_reset(l, NULL, TERM_AGE_NULL);

        LINE_ASSERT(l, "|   |   |          |          |          |   |   |   |", 0);
        line_set(l, 2, "*wxyz* 8", 0);
        line_set(l, 3, "/wxyz/ 8", 0);
        LINE_ASSERT(l, "|   |   | *wxyz* 8 | /wxyz/ 8 |          |   |   |   |", 4);
        line_set(l, 2, "*abc* 9", true);
        LINE_ASSERT(l, "|   |   | *abc* 9  | *wxyz* 9 | /wxyz/ 9 | 9 | 9 | 9 |", 5);
        line_set(l, 7, "*abc* 10", true);
        LINE_ASSERT(l, "|   |   | *abc* 9  | *wxyz* 9 | /wxyz/ 9 | 9 | 9 | *abc* 10 |", 8);

        term_line_erase(l, 6, 1, NULL, 11, 0);
        LINE_ASSERT(l, "|   |   | *abc* 9  | *wxyz* 9 | /wxyz/ 9 | 9 | 11 | *abc* 10 |", 8);
        term_line_erase(l, 6, 2, &attr_italic, 12, 0);
        LINE_ASSERT(l, "|   |   | *abc* 9  | *wxyz* 9 | /wxyz/ 9 | 9 | 12 // | 12 // |", 6);
        term_line_erase(l, 7, 2, &attr_regular, 13, 0);
        LINE_ASSERT(l, "|   |   | *abc* 9  | *wxyz* 9 | /wxyz/ 9 | 9 | 12 // | 13 |", 6);
        term_line_delete(l, 1, 3, &attr_bold, 14);
        LINE_ASSERT(l, "|   | /wxyz/ 14 | 14 | 14 // | 14 | 14 ** | 14 ** | 14 ** |", 3);
        term_line_insert(l, 2, 2, &attr_regular, 15);
        LINE_ASSERT(l, "|   | /wxyz/ 14 | 15 | 15 | 15 | 15 // | 15 | 15 ** |", 5);

        assert_se(!term_line_free(l));
}

int main(int argc, char *argv[]) {
        test_term_char_misc();
        test_term_char_packing();
        test_term_char_allocating();

        test_term_line_misc();
        test_term_line_ops();

        return 0;
}
