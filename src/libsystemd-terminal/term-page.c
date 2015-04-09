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
 * Terminal Page/Line/Cell/Char Handling
 * This file implements page handling of a terminal. It is split into pages,
 * lines, cells and characters. Each object is independent of the next upper
 * object.
 *
 * The Terminal layer keeps each line of a terminal separate and dynamically
 * allocated. This allows us to move lines from main-screen to history-buffers
 * very fast. Same is true for scrolling, top/bottom borders and other buffer
 * operations.
 *
 * While lines are dynamically allocated, cells are not. This would be a waste
 * of memory and causes heavy fragmentation. Furthermore, cells are moved much
 * less frequently than lines so the performance-penalty is pretty small.
 * However, to support combining-characters, we have to initialize and cleanup
 * cells properly and cannot just release the underlying memory. Therefore,
 * cells are treated as proper objects despite being allocated in arrays.
 *
 * Each cell has a set of attributes and a stored character. This is usually a
 * single Unicode character stored as 32bit UCS-4 char. However, we need to
 * support Unicode combining-characters, therefore this gets more complicated.
 * Characters themselves are represented by a "term_char_t" object. It
 * should be treated as a normal integer and passed by value. The
 * surrounding struct is just to hide the internals. A term-char can contain a
 * base character together with up to 2 combining-chars in a single integer.
 * Only if you need more combining-chars (very unlikely!) a term-char is a
 * pointer to an allocated storage. This requires you to always free term-char
 * objects once no longer used (even though this is a no-op most of the time).
 * Furthermore, term-char objects are not ref-counted so you must duplicate them
 * in case you want to store it somewhere and retain a copy yourself. By
 * convention, all functions that take a term-char object will not duplicate
 * it but implicitly take ownership of the passed value. It's up to the caller
 * to duplicate it beforehand, in case it wants to retain a copy.
 *
 * If it turns out, that more than 2 comb-chars become common in specific
 * languages, we can try to optimize this. One idea is to ref-count allocated
 * characters and store them in a hash-table (like gnome's libvte3 does). This
 * way we will never have two allocated chars for the same content. Or we can
 * simply put two uint64_t into a "term_char_t". This will slow down operations
 * on systems that don't need that many comb-chars, but avoid the dynamic
 * allocations on others.
 * Anyhow, until we have proper benchmarks, we will keep the current code. It
 * seems to compete very well with other solutions so far.
 *
 * The page-layer is a one-dimensional array of lines. Considering that each
 * line is a one-dimensional array of cells, the page layer provides the
 * two-dimensional cell-page required for terminals. The page itself only
 * operates on lines. All cell-related operations are forwarded to the correct
 * line.
 * A page does not contain any cursor tracking. It only provides the raw
 * operations to shuffle lines and modify the page.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "macro.h"
#include "term-internal.h"
#include "util.h"

/* maximum UCS-4 character */
#define CHAR_UCS4_MAX (0x10ffff)
/* mask for valid UCS-4 characters (21bit) */
#define CHAR_UCS4_MASK (0x1fffff)
/* UCS-4 replacement character */
#define CHAR_UCS4_REPLACEMENT (0xfffd)

/* real storage behind "term_char_t" in case it's not packed */
typedef struct term_character {
        uint8_t n;
        uint32_t codepoints[];
} term_character;

/*
 * char_pack() takes 3 UCS-4 values and packs them into a term_char_t object.
 * Note that UCS-4 chars only take 21 bits, so we still have the LSB as marker.
 * We set it to 1 so others can distinguish it from pointers.
 */
static inline term_char_t char_pack(uint32_t v1, uint32_t v2, uint32_t v3) {
        uint64_t packed, u1, u2, u3;

        u1 = v1;
        u2 = v2;
        u3 = v3;

        packed = 0x01;
        packed |= (u1 & (uint64_t)CHAR_UCS4_MASK) << 43;
        packed |= (u2 & (uint64_t)CHAR_UCS4_MASK) << 22;
        packed |= (u3 & (uint64_t)CHAR_UCS4_MASK) <<  1;

        return TERM_CHAR_INIT(packed);
}

#define char_pack1(_v1) char_pack2((_v1), CHAR_UCS4_MAX + 1)
#define char_pack2(_v1, _v2) char_pack3((_v1), (_v2), CHAR_UCS4_MAX + 1)
#define char_pack3(_v1, _v2, _v3) char_pack((_v1), (_v2), (_v3))

/*
 * char_unpack() is the inverse of char_pack(). It extracts the 3 stored UCS-4
 * characters and returns them. Note that this does not validate the passed
 * term_char_t. That's the responsibility of the caller.
 * This returns the number of characters actually packed. This obviously is a
 * number between 0 and 3 (inclusive).
 */
static inline uint8_t char_unpack(term_char_t packed, uint32_t *out_v1, uint32_t *out_v2, uint32_t *out_v3) {
        uint32_t v1, v2, v3;

        v1 = (packed._value >> 43) & (uint64_t)CHAR_UCS4_MASK;
        v2 = (packed._value >> 22) & (uint64_t)CHAR_UCS4_MASK;
        v3 = (packed._value >>  1) & (uint64_t)CHAR_UCS4_MASK;

        if (out_v1)
                *out_v1 = v1;
        if (out_v2)
                *out_v2 = v2;
        if (out_v3)
                *out_v3 = v3;

        return (v1 > CHAR_UCS4_MAX) ? 0 :
              ((v2 > CHAR_UCS4_MAX) ? 1 :
              ((v3 > CHAR_UCS4_MAX) ? 2 :
                                      3));
}

/* cast a term_char_t to a term_character* */
static inline term_character *char_to_ptr(term_char_t ch) {
        return (term_character*)(unsigned long)ch._value;
}

/* cast a term_character* to a term_char_t */
static inline term_char_t char_from_ptr(term_character *c) {
        return TERM_CHAR_INIT((unsigned long)c);
}

/*
 * char_alloc() allocates a properly aligned term_character object and returns
 * a pointer to it. NULL is returned on allocation errors. The object will have
 * enough room for @n following UCS-4 chars.
 * Note that we allocate (n+1) characters and set the last one to 0 in case
 * anyone prints this string for debugging.
 */
static term_character *char_alloc(uint8_t n) {
        term_character *c;
        int r;

        r = posix_memalign((void**)&c,
                           MAX(sizeof(void*), (size_t)2),
                           sizeof(*c) + sizeof(*c->codepoints) * (n + 1));
        if (r)
                return NULL;

        c->n = n;
        c->codepoints[n] = 0;

        return c;
}

/*
 * char_free() frees the memory allocated via char_alloc(). It is safe to call
 * this on any term_char_t, only allocated characters are freed.
 */
static inline void char_free(term_char_t ch) {
        if (term_char_is_allocated(ch))
                free(char_to_ptr(ch));
}

/*
 * This appends @append_ucs4 to the existing character @base and returns
 * it as a new character. In case that's not possible, @base is returned. The
 * caller can use term_char_same() to test whether the returned character was
 * freshly allocated or not.
 */
static term_char_t char_build(term_char_t base, uint32_t append_ucs4) {
        /* soft-limit for combining-chars; hard-limit is currently 255 */
        const size_t climit = 64;
        term_character *c;
        uint32_t buf[3], *t;
        uint8_t n;

        /* ignore invalid UCS-4 */
        if (append_ucs4 > CHAR_UCS4_MAX)
                return base;

        if (term_char_is_null(base)) {
                return char_pack1(append_ucs4);
        } else if (!term_char_is_allocated(base)) {
                /* unpack and try extending the packed character */
                n = char_unpack(base, &buf[0], &buf[1], &buf[2]);

                switch (n) {
                case 0:
                        return char_pack1(append_ucs4);
                case 1:
                        if (climit < 2)
                                return base;

                        return char_pack2(buf[0], append_ucs4);
                case 2:
                        if (climit < 3)
                                return base;

                        return char_pack3(buf[0], buf[1], append_ucs4);
                default:
                        /* fallthrough */
                        break;
                }

                /* already fully packed, we need to allocate a new one */
                t = buf;
        } else {
                /* already an allocated type, we need to allocate a new one */
                c = char_to_ptr(base);
                t = c->codepoints;
                n = c->n;
        }

        /* bail out if soft-limit is reached */
        if (n >= climit)
                return base;

        /* allocate new char */
        c = char_alloc(n + 1);
        if (!c)
                return base;

        memcpy(c->codepoints, t, sizeof(*t) * n);
        c->codepoints[n] = append_ucs4;

        return char_from_ptr(c);
}

/**
 * term_char_set() - Reset character to a single UCS-4 character
 * @previous: term-char to reset
 * @append_ucs4: UCS-4 char to set
 *
 * This frees all resources in @previous and re-initializes it to @append_ucs4.
 * The new char is returned.
 *
 * Usually, this is used like this:
 *   obj->ch = term_char_set(obj->ch, ucs4);
 *
 * Returns: The previous character reset to @append_ucs4.
 */
term_char_t term_char_set(term_char_t previous, uint32_t append_ucs4) {
        char_free(previous);
        return char_build(TERM_CHAR_NULL, append_ucs4);
}

/**
 * term_char_merge() - Merge UCS-4 char at the end of an existing char
 * @base: existing term-char
 * @append_ucs4: UCS-4 character to append
 *
 * This appends @append_ucs4 to @base and returns the result. @base is
 * invalidated by this function and must no longer be used. The returned value
 * replaces the old one.
 *
 * Usually, this is used like this:
 *   obj->ch = term_char_merge(obj->ch, ucs4);
 *
 * Returns: The new merged character.
 */
term_char_t term_char_merge(term_char_t base, uint32_t append_ucs4) {
        term_char_t ch;

        ch = char_build(base, append_ucs4);
        if (!term_char_same(ch, base))
                term_char_free(base);

        return ch;
}

/**
 * term_char_dup() - Duplicate character
 * @ch: character to duplicate
 *
 * This duplicates a term-character. In case the character is not allocated,
 * nothing is done. Otherwise, the underlying memory is copied and returned. You
 * need to call term_char_free() on the returned character to release it again.
 * On allocation errors, a replacement character is returned. Therefore, the
 * caller can safely assume that this function always succeeds.
 *
 * Returns: The duplicated term-character.
 */
term_char_t term_char_dup(term_char_t ch) {
        term_character *c, *newc;

        if (!term_char_is_allocated(ch))
                return ch;

        c = char_to_ptr(ch);
        newc = char_alloc(c->n);
        if (!newc)
                return char_pack1(CHAR_UCS4_REPLACEMENT);

        memcpy(newc->codepoints, c->codepoints, sizeof(*c->codepoints) * c->n);
        return char_from_ptr(newc);
}

/**
 * term_char_dup_append() - Duplicate tsm-char with UCS-4 character appended
 * @base: existing term-char
 * @append_ucs4: UCS-4 character to append
 *
 * This is similar to term_char_merge(), but it returns a separately allocated
 * character. That is, @base will stay valid after this returns and is not
 * touched. In case the append-operation fails, @base is duplicated and
 * returned. That is, the returned char is always independent of @base.
 *
 * Returns: Newly allocated character with @append_ucs4 appended to @base.
 */
term_char_t term_char_dup_append(term_char_t base, uint32_t append_ucs4) {
        term_char_t ch;

        ch = char_build(base, append_ucs4);
        if (term_char_same(ch, base))
                ch = term_char_dup(base);

        return ch;
}

/**
 * term_char_resolve() - Retrieve the UCS-4 string for a term-char
 * @ch: character to resolve
 * @s: storage for size of string or NULL
 * @b: storage for string or NULL
 *
 * This takes a term-character and returns the UCS-4 string associated with it.
 * In case @ch is not allocated, the string is stored in @b (in case @b is NULL
 * static storage is used). Otherwise, a pointer to the allocated storage is
 * returned.
 *
 * The returned string is only valid as long as @ch and @b are valid. The string
 * is zero-terminated and can safely be printed via long-character printf().
 * The length of the string excluding the zero-character is returned in @s.
 *
 * This never returns NULL. Even if the size is 0, this points to a buffer of at
 * least a zero-terminator.
 *
 * Returns: The UCS-4 string-representation of @ch, and its size in @s.
 */
const uint32_t *term_char_resolve(term_char_t ch, size_t *s, term_charbuf_t *b) {
        static term_charbuf_t static_b;
        term_character *c;
        uint32_t *cache;
        size_t len;

        if (b)
                cache = b->buf;
        else
                cache = static_b.buf;

        if (term_char_is_null(ch)) {
                len = 0;
                cache[0] = 0;
        } else if (term_char_is_allocated(ch)) {
                c = char_to_ptr(ch);
                len = c->n;
                cache = c->codepoints;
        } else {
                len = char_unpack(ch, &cache[0], &cache[1], &cache[2]);
                cache[len] = 0;
        }

        if (s)
                *s = len;

        return cache;
}

/**
 * term_char_lookup_width() - Lookup cell-width of a character
 * @ch: character to return cell-width for
 *
 * This is an equivalent of wcwidth() for term_char_t. It can deal directly
 * with UCS-4 and combining-characters and avoids the mess that is wchar_t and
 * locale handling.
 *
 * Returns: 0 for unprintable characters, >0 for everything else.
 */
unsigned int term_char_lookup_width(term_char_t ch) {
        term_charbuf_t b;
        const uint32_t *str;
        unsigned int max;
        size_t i, len;
        int r;

        max = 0;
        str = term_char_resolve(ch, &len, &b);

        for (i = 0; i < len; ++i) {
                /*
                 * Oh god, C99 locale handling strikes again: wcwidth() expects
                 * wchar_t, but there is no way for us to know the
                 * internal encoding of wchar_t. Moreover, it is nearly
                 * impossible to convert UCS-4 into wchar_t (except for iconv,
                 * which is way too much overhead).
                 * Therefore, we use our own copy of wcwidth(). Lets just hope
                 * that glibc will one day export it's internal UCS-4 and UTF-8
                 * helpers for direct use.
                 */
                assert_cc(sizeof(wchar_t) >= 4);
                r = mk_wcwidth((wchar_t)str[i]);
                if (r > 0 && (unsigned int)r > max)
                        max = r;
        }

        return max;
}

/**
 * term_cell_init() - Initialize a new cell
 * @cell: cell to initialize
 * @ch: character to set on the cell or TERM_CHAR_NULL
 * @cwidth: character width of @ch
 * @attr: attributes to set on the cell or NULL
 * @age: age to set on the cell or TERM_AGE_NULL
 *
 * This initializes a new cell. The backing-memory of the cell must be allocated
 * by the caller beforehand. The caller is responsible to destroy the cell via
 * term_cell_destroy() before freeing the backing-memory.
 *
 * It is safe (and supported!) to use:
 *   zero(*c);
 * instead of:
 *   term_cell_init(c, TERM_CHAR_NULL, NULL, TERM_AGE_NULL);
 *
 * Note that this call takes ownership of @ch. If you want to use it yourself
 * after this call, you need to duplicate it before calling this.
 */
static void term_cell_init(term_cell *cell, term_char_t ch, unsigned int cwidth, const term_attr *attr, term_age_t age) {
        assert(cell);

        cell->ch = ch;
        cell->cwidth = cwidth;
        cell->age = age;

        if (attr)
                memcpy(&cell->attr, attr, sizeof(*attr));
        else
                zero(cell->attr);
}

/**
 * term_cell_destroy() - Destroy previously initialized cell
 * @cell: cell to destroy or NULL
 *
 * This releases all resources associated with a cell. The backing memory is
 * kept as-is. It's the responsibility of the caller to manage it.
 *
 * You must not call any other cell operations on this cell after this call
 * returns. You must re-initialize the cell via term_cell_init() before you can
 * use it again.
 *
 * If @cell is NULL, this is a no-op.
 */
static void term_cell_destroy(term_cell *cell) {
        if (!cell)
                return;

        term_char_free(cell->ch);
}

/**
 * term_cell_set() - Change contents of a cell
 * @cell: cell to modify
 * @ch: character to set on the cell or cell->ch
 * @cwidth: character width of @ch or cell->cwidth
 * @attr: attributes to set on the cell or NULL
 * @age: age to set on the cell or cell->age
 *
 * This changes the contents of a cell. It can be used to change the character,
 * attributes and age. To keep the current character, pass cell->ch as @ch. To
 * reset the current attributes, pass NULL. To keep the current age, pass
 * cell->age.
 *
 * This call takes ownership of @ch. You need to duplicate it first, in case you
 * want to use it for your own purposes after this call.
 *
 * The cell must have been initialized properly before calling this. See
 * term_cell_init().
 */
static void term_cell_set(term_cell *cell, term_char_t ch, unsigned int cwidth, const term_attr *attr, term_age_t age) {
        assert(cell);

        if (!term_char_same(ch, cell->ch)) {
                term_char_free(cell->ch);
                cell->ch = ch;
        }

        cell->cwidth = cwidth;
        cell->age = age;

        if (attr)
                memcpy(&cell->attr, attr, sizeof(*attr));
        else
                zero(cell->attr);
}

/**
 * term_cell_append() - Append a combining-char to a cell
 * @cell: cell to modify
 * @ucs4: UCS-4 character to append to the cell
 * @age: new age to set on the cell or cell->age
 *
 * This appends a combining-character to a cell. No validation of the UCS-4
 * character is done, so this can be used to append any character. Additionally,
 * this can update the age of the cell.
 *
 * The cell must have been initialized properly before calling this. See
 * term_cell_init().
 */
static void term_cell_append(term_cell *cell, uint32_t ucs4, term_age_t age) {
        assert(cell);

        cell->ch = term_char_merge(cell->ch, ucs4);
        cell->age = age;
}

/**
 * term_cell_init_n() - Initialize an array of cells
 * @cells: pointer to an array of cells to initialize
 * @n: number of cells
 * @attr: attributes to set on all cells or NULL
 * @age: age to set on all cells
 *
 * This is the same as term_cell_init() but initializes an array of cells.
 * Furthermore, this always sets the character to TERM_CHAR_NULL.
 * If you want to set a specific characters on all cells, you need to hard-code
 * this loop and duplicate the character for each cell.
 */
static void term_cell_init_n(term_cell *cells, unsigned int n, const term_attr *attr, term_age_t age) {
        for ( ; n > 0; --n, ++cells)
                term_cell_init(cells, TERM_CHAR_NULL, 0, attr, age);
}

/**
 * term_cell_destroy_n() - Destroy an array of cells
 * @cells: pointer to an array of cells to destroy
 * @n: number of cells
 *
 * This is the same as term_cell_destroy() but destroys an array of cells.
 */
static void term_cell_destroy_n(term_cell *cells, unsigned int n) {
        for ( ; n > 0; --n, ++cells)
                term_cell_destroy(cells);
}

/**
 * term_cell_clear_n() - Clear contents of an array of cells
 * @cells: pointer to an array of cells to modify
 * @n: number of cells
 * @attr: attributes to set on all cells or NULL
 * @age: age to set on all cells
 *
 * This is the same as term_cell_set() but operates on an array of cells. Note
 * that all characters are always set to TERM_CHAR_NULL, unlike term_cell_set()
 * which takes the character as argument.
 * If you want to set a specific characters on all cells, you need to hard-code
 * this loop and duplicate the character for each cell.
 */
static void term_cell_clear_n(term_cell *cells, unsigned int n, const term_attr *attr, term_age_t age) {
        for ( ; n > 0; --n, ++cells)
                term_cell_set(cells, TERM_CHAR_NULL, 0, attr, age);
}

/**
 * term_line_new() - Allocate a new line
 * @out: place to store pointer to new line
 *
 * This allocates and initialized a new line. The line is unlinked and
 * independent of any page. It can be used for any purpose. The initial
 * cell-count is set to 0.
 *
 * The line has to be freed via term_line_free() once it's no longer needed.
 *
 * Returns: 0 on success, negative error code on failure.
 */
int term_line_new(term_line **out) {
        _term_line_free_ term_line *line = NULL;

        assert_return(out, -EINVAL);

        line = new0(term_line, 1);
        if (!line)
                return -ENOMEM;

        *out = line;
        line = NULL;
        return 0;
}

/**
 * term_line_free() - Free a line
 * @line: line to free or NULL
 *
 * This frees a line that was previously allocated via term_line_free(). All its
 * cells are released, too.
 *
 * If @line is NULL, this is a no-op.
 */
term_line *term_line_free(term_line *line) {
        if (!line)
                return NULL;

        term_cell_destroy_n(line->cells, line->n_cells);
        free(line->cells);
        free(line);

        return NULL;
}

/**
 * term_line_reserve() - Pre-allocate cells for a line
 * @line: line to pre-allocate cells for
 * @width: numbers of cells the line shall have pre-allocated
 * @attr: attribute for all allocated cells or NULL
 * @age: current age for all modifications
 * @protect_width: width to protect from erasure
 *
 * This pre-allocates cells for this line. Please note that @width is the number
 * of cells the line is guaranteed to have allocated after this call returns.
 * It's not the number of cells that are added, neither is it the new width of
 * the line.
 *
 * This function never frees memory. That is, reducing the line-width will
 * always succeed, same is true for increasing the width to a previously set
 * width.
 *
 * @attr and @age are used to initialize new cells. Additionally, any
 * existing cell outside of the protected area specified by @protect_width are
 * cleared and reset with @attr and @age.
 *
 * Returns: 0 on success, negative error code on failure.
 */
int term_line_reserve(term_line *line, unsigned int width, const term_attr *attr, term_age_t age, unsigned int protect_width) {
        unsigned int min_width;
        term_cell *t;

        assert_return(line, -EINVAL);

        /* reset existing cells if required */
        min_width = MIN(line->n_cells, width);
        if (min_width > protect_width)
                term_cell_clear_n(line->cells + protect_width,
                                  min_width - protect_width,
                                  attr,
                                  age);

        /* allocate new cells if required */

        if (width > line->n_cells) {
                t = realloc_multiply(line->cells, sizeof(*t), width);
                if (!t)
                        return -ENOMEM;

                if (!attr && !age)
                        memzero(t + line->n_cells,
                                sizeof(*t) * (width - line->n_cells));
                else
                        term_cell_init_n(t + line->n_cells,
                                         width - line->n_cells,
                                         attr,
                                         age);

                line->cells = t;
                line->n_cells = width;
        }

        line->fill = MIN(line->fill, protect_width);

        return 0;
}

/**
 * term_line_set_width() - Change width of a line
 * @line: line to modify
 * @width: new width
 *
 * This changes the actual width of a line. It is the caller's responsibility
 * to use term_line_reserve() to make sure enough space is allocated. If @width
 * is greater than the allocated size, it is cropped.
 *
 * This does not modify any cells. Use term_line_reserve() or term_line_erase()
 * to clear any newly added cells.
 *
 * NOTE: The fill state is cropped at line->width. Therefore, if you increase
 *       the line-width afterwards, but there is a multi-cell character at the
 *       end of the line that got cropped, then the fill-state will _not_ be
 *       adjusted.
 *       This means, the fill-state always includes the cells up to the start
 *       of the right-most character, but it might or might not cover it until
 *       its end. This should be totally fine, though. You should never access
 *       multi-cell tails directly, anyway.
 */
void term_line_set_width(term_line *line, unsigned int width) {
        assert(line);

        if (width > line->n_cells)
                width = line->n_cells;

        line->width = width;
        line->fill = MIN(line->fill, width);
}

/**
 * line_insert() - Insert characters and move existing cells to the right
 * @from: position to insert cells at
 * @num: number of cells to insert
 * @head_char: character that is set on the first cell
 * @head_cwidth: character-length of @head_char
 * @attr: attribute for all inserted cells or NULL
 * @age: current age for all modifications
 *
 * The INSERT operation (or writes with INSERT_MODE) writes data at a specific
 * position on a line and shifts the existing cells to the right. Cells that are
 * moved beyond the right hand border are discarded.
 *
 * This helper contains the actual INSERT implementation which is independent of
 * the data written. It works on cells, not on characters. The first cell is set
 * to @head_char, all others are reset to TERM_CHAR_NULL. See each caller for a
 * more detailed description.
 */
static inline void line_insert(term_line *line, unsigned int from, unsigned int num, term_char_t head_char, unsigned int head_cwidth, const term_attr *attr, term_age_t age) {
        unsigned int i, rem, move;

        if (from >= line->width)
                return;
        if (from + num < from || from + num > line->width)
                num = line->width - from;
        if (!num)
                return;

        move = line->width - from - num;
        rem = MIN(num, move);

        if (rem > 0) {
                /*
                 * Make room for @num cells; shift cells to the right if
                 * required. @rem is the number of remaining cells that we will
                 * knock off on the right and overwrite during the right shift.
                 *
                 * For INSERT_MODE, @num/@rem are usually 1 or 2, @move is 50%
                 * of the line on average. Therefore, the actual move is quite
                 * heavy and we can safely invalidate cells manually instead of
                 * the whole line.
                 * However, for INSERT operations, any parameters are
                 * possible. But we cannot place any assumption on its usage
                 * across applications, so we just handle it the same as
                 * INSERT_MODE and do per-cell invalidation.
                 */

                /* destroy cells that are knocked off on the right */
                term_cell_destroy_n(line->cells + line->width - rem, rem);

                /* move remaining bulk of cells */
                memmove(line->cells + from + num,
                        line->cells + from,
                        sizeof(*line->cells) * move);

                /* invalidate cells */
                for (i = 0; i < move; ++i)
                        line->cells[from + num + i].age = age;

                /* initialize fresh head-cell */
                term_cell_init(line->cells + from,
                               head_char,
                               head_cwidth,
                               attr,
                               age);

                /* initialize fresh tail-cells */
                term_cell_init_n(line->cells + from + 1,
                                 num - 1,
                                 attr,
                                 age);

                /* adjust fill-state */
                line->fill = MIN(line->width,
                                 MAX(line->fill + num,
                                     from + num));
        } else {
                /* modify head-cell */
                term_cell_set(line->cells + from,
                              head_char,
                              head_cwidth,
                              attr,
                              age);

                /* reset tail-cells */
                term_cell_clear_n(line->cells + from + 1,
                                  num - 1,
                                  attr,
                                  age);

                /* adjust fill-state */
                line->fill = line->width;
        }
}

/**
 * term_line_write() - Write to a single, specific cell
 * @line: line to write to
 * @pos_x: x-position of cell in @line to write to
 * @ch: character to write to the cell
 * @cwidth: character width of @ch
 * @attr: attributes to set on the cell or NULL
 * @age: current age for all modifications
 * @insert_mode: true if INSERT-MODE is enabled
 *
 * This writes to a specific cell in a line. The cell is addressed by its
 * X-position @pos_x. If that cell does not exist, this is a no-op.
 *
 * @ch and @attr are set on this cell.
 *
 * If @insert_mode is true, this inserts the character instead of overwriting
 * existing data (existing data is now moved to the right before writing).
 *
 * This function is the low-level handler of normal writes to a terminal.
 */
void term_line_write(term_line *line, unsigned int pos_x, term_char_t ch, unsigned int cwidth, const term_attr *attr, term_age_t age, bool insert_mode) {
        unsigned int len;

        assert(line);

        if (pos_x >= line->width)
                return;

        len = MAX(1U, cwidth);
        if (pos_x + len < pos_x || pos_x + len > line->width)
                len = line->width - pos_x;
        if (!len)
                return;

        if (insert_mode) {
                /* Use line_insert() to insert the character-head and fill
                 * the remains with NULLs. */
                line_insert(line, pos_x, len, ch, cwidth, attr, age);
        } else {
                /* modify head-cell */
                term_cell_set(line->cells + pos_x, ch, cwidth, attr, age);

                /* reset tail-cells */
                term_cell_clear_n(line->cells + pos_x + 1,
                                  len - 1,
                                  attr,
                                  age);

                /* adjust fill-state */
                line->fill = MIN(line->width,
                                 MAX(line->fill,
                                     pos_x + len));
        }
}

/**
 * term_line_insert() - Insert empty cells
 * @line: line to insert empty cells into
 * @from: x-position where to insert cells
 * @num: number of cells to insert
 * @attr: attributes to set on the cells or NULL
 * @age: current age for all modifications
 *
 * This inserts @num empty cells at position @from in line @line. All existing
 * cells to the right are shifted to make room for the new cells. Cells that get
 * pushed beyond the right hand border are discarded.
 */
void term_line_insert(term_line *line, unsigned int from, unsigned int num, const term_attr *attr, term_age_t age) {
        /* use line_insert() to insert @num empty cells */
        return line_insert(line, from, num, TERM_CHAR_NULL, 0, attr, age);
}

/**
 * term_line_delete() - Delete cells from line
 * @line: line to delete cells from
 * @from: position to delete cells at
 * @num: number of cells to delete
 * @attr: attributes to set on any new cells
 * @age: current age for all modifications
 *
 * Delete cells from a line. All cells to the right of the deleted cells are
 * shifted to the left to fill the empty space. New cells appearing on the right
 * hand border are cleared and initialized with @attr.
 */
void term_line_delete(term_line *line, unsigned int from, unsigned int num, const term_attr *attr, term_age_t age) {
        unsigned int rem, move, i;

        assert(line);

        if (from >= line->width)
                return;
        if (from + num < from || from + num > line->width)
                num = line->width - from;
        if (!num)
                return;

        /* destroy and move as many upfront as possible */
        move = line->width - from - num;
        rem = MIN(num, move);
        if (rem > 0) {
                /* destroy to be removed cells */
                term_cell_destroy_n(line->cells + from, rem);

                /* move tail upfront */
                memmove(line->cells + from,
                        line->cells + from + num,
                        sizeof(*line->cells) * move);

                /* invalidate copied cells */
                for (i = 0; i < move; ++i)
                        line->cells[from + i].age = age;

                /* initialize tail that was moved away */
                term_cell_init_n(line->cells + line->width - rem,
                                 rem,
                                 attr,
                                 age);

                /* reset remaining cells in case the move was too small */
                if (num > move)
                        term_cell_clear_n(line->cells + from + move,
                                          num - move,
                                          attr,
                                          age);
        } else {
                /* reset cells */
                term_cell_clear_n(line->cells + from,
                                  num,
                                  attr,
                                  age);
        }

        /* adjust fill-state */
        if (from + num < line->fill)
                line->fill -= num;
        else if (from < line->fill)
                line->fill = from;
}

/**
 * term_line_append_combchar() - Append combining char to existing cell
 * @line: line to modify
 * @pos_x: position of cell to append combining char to
 * @ucs4: combining character to append
 * @age: current age for all modifications
 *
 * Unicode allows trailing combining characters, which belong to the
 * char in front of them. The caller is responsible of detecting
 * combining characters and calling term_line_append_combchar() instead of
 * term_line_write(). This simply appends the char to the correct cell then.
 * If the cell is not in the visible area, this call is skipped.
 *
 * Note that control-sequences are not 100% compatible with combining
 * characters as they require delayed parsing. However, we must handle
 * control-sequences immediately. Therefore, there might be trailing
 * combining chars that should be discarded by the parser.
 * However, to prevent programming errors, we're also being pedantic
 * here and discard weirdly placed combining chars. This prevents
 * situations were invalid content is parsed into the terminal and you
 * might end up with cells containing only combining chars.
 *
 * Long story short: To get combining-characters working with old-fashioned
 * terminal-emulation, we parse them exclusively for direct cell-writes. Other
 * combining-characters are usually simply discarded and ignored.
 */
void term_line_append_combchar(term_line *line, unsigned int pos_x, uint32_t ucs4, term_age_t age) {
        assert(line);

        if (pos_x >= line->width)
                return;

        /* Unused cell? Skip appending any combining chars then. */
        if (term_char_is_null(line->cells[pos_x].ch))
                return;

        term_cell_append(line->cells + pos_x, ucs4, age);
}

/**
 * term_line_erase() - Erase parts of a line
 * @line: line to modify
 * @from: position to start the erase
 * @num: number of cells to erase
 * @attr: attributes to initialize erased cells with
 * @age: current age for all modifications
 * @keep_protected: true if protected cells should be kept
 *
 * This is the standard erase operation. It clears all cells in the targeted
 * area and re-initializes them. Cells to the right are not shifted left, you
 * must use DELETE to achieve that. Cells outside the visible area are skipped.
 *
 * If @keep_protected is true, protected cells will not be erased.
 */
void term_line_erase(term_line *line, unsigned int from, unsigned int num, const term_attr *attr, term_age_t age, bool keep_protected) {
        term_cell *cell;
        unsigned int i, last_protected;

        assert(line);

        if (from >= line->width)
                return;
        if (from + num < from || from + num > line->width)
                num = line->width - from;
        if (!num)
                return;

        last_protected = 0;
        for (i = 0; i < num; ++i) {
                cell = line->cells + from + i;
                if (keep_protected && cell->attr.protect) {
                        /* only count protected-cells inside the fill-region */
                        if (from + i < line->fill)
                                last_protected = from + i;

                        continue;
                }

                term_cell_set(cell, TERM_CHAR_NULL, 0, attr, age);
        }

        /* Adjust fill-state. This is a bit tricks, we can only adjust it in
         * case the erase-region starts inside the fill-region and ends at the
         * tail or beyond the fill-region. Otherwise, the current fill-state
         * stays as it was.
         * Furthermore, we must account for protected cells. The loop above
         * ensures that protected-cells are only accounted for if they're
         * inside the fill-region. */
        if (from < line->fill && from + num >= line->fill)
                line->fill = MAX(from, last_protected);
}

/**
 * term_line_reset() - Reset a line
 * @line: line to reset
 * @attr: attributes to initialize all cells with
 * @age: current age for all modifications
 *
 * This resets all visible cells of a line and sets their attributes and ages
 * to @attr and @age. This is equivalent to erasing a whole line via
 * term_line_erase().
 */
void term_line_reset(term_line *line, const term_attr *attr, term_age_t age) {
        assert(line);

        return term_line_erase(line, 0, line->width, attr, age, 0);
}

/**
 * term_line_link() - Link line in front of a list
 * @line: line to link
 * @first: member pointing to first entry
 * @last: member pointing to last entry
 *
 * This links a line into a list of lines. The line is inserted at the front and
 * must not be linked, yet. See the TERM_LINE_LINK() macro for an easier usage of
 * this.
 */
void term_line_link(term_line *line, term_line **first, term_line **last) {
        assert(line);
        assert(first);
        assert(last);
        assert(!line->lines_prev);
        assert(!line->lines_next);

        line->lines_prev = NULL;
        line->lines_next = *first;
        if (*first)
                (*first)->lines_prev = line;
        else
                *last = line;
        *first = line;
}

/**
 * term_line_link_tail() - Link line at tail of a list
 * @line: line to link
 * @first: member pointing to first entry
 * @last: member pointing to last entry
 *
 * Same as term_line_link() but links the line at the tail.
 */
void term_line_link_tail(term_line *line, term_line **first, term_line **last) {
        assert(line);
        assert(first);
        assert(last);
        assert(!line->lines_prev);
        assert(!line->lines_next);

        line->lines_next = NULL;
        line->lines_prev = *last;
        if (*last)
                (*last)->lines_next = line;
        else
                *first = line;
        *last = line;
}

/**
 * term_line_unlink() - Unlink line from a list
 * @line: line to unlink
 * @first: member pointing to first entry
 * @last: member pointing to last entry
 *
 * This unlinks a previously linked line. See TERM_LINE_UNLINK() for an easier to
 * use macro.
 */
void term_line_unlink(term_line *line, term_line **first, term_line **last) {
        assert(line);
        assert(first);
        assert(last);

        if (line->lines_prev)
                line->lines_prev->lines_next = line->lines_next;
        else
                *first = line->lines_next;
        if (line->lines_next)
                line->lines_next->lines_prev = line->lines_prev;
        else
                *last = line->lines_prev;

        line->lines_prev = NULL;
        line->lines_next = NULL;
}

/**
 * term_page_new() - Allocate new page
 * @out: storage for pointer to new page
 *
 * Allocate a new page. The initial dimensions are 0/0.
 *
 * Returns: 0 on success, negative error code on failure.
 */
int term_page_new(term_page **out) {
        _term_page_free_ term_page *page = NULL;

        assert_return(out, -EINVAL);

        page = new0(term_page, 1);
        if (!page)
                return -ENOMEM;

        *out = page;
        page = NULL;
        return 0;
}

/**
 * term_page_free() - Free page
 * @page: page to free or NULL
 *
 * Free a previously allocated page and all associated data. If @page is NULL,
 * this is a no-op.
 *
 * Returns: NULL
 */
term_page *term_page_free(term_page *page) {
        unsigned int i;

        if (!page)
                return NULL;

        for (i = 0; i < page->n_lines; ++i)
                term_line_free(page->lines[i]);

        free(page->line_cache);
        free(page->lines);
        free(page);

        return NULL;
}

/**
 * term_page_get_cell() - Return pointer to requested cell
 * @page: page to operate on
 * @x: x-position of cell
 * @y: y-position of cell
 *
 * This returns a pointer to the cell at position @x/@y. You're free to modify
 * this cell as much as you like. However, once you call any other function on
 * the page, you must drop the pointer to the cell.
 *
 * Returns: Pointer to the cell or NULL if out of the visible area.
 */
term_cell *term_page_get_cell(term_page *page, unsigned int x, unsigned int y) {
        assert_return(page, NULL);

        if (x >= page->width)
                return NULL;
        if (y >= page->height)
                return NULL;

        return &page->lines[y]->cells[x];
}

/**
 * page_scroll_up() - Scroll up
 * @page: page to operate on
 * @new_width: width to use for any new line moved into the visible area
 * @num: number of lines to scroll up
 * @attr: attributes to set on new lines
 * @age: age to use for all modifications
 * @history: history to use for old lines or NULL
 *
 * This scrolls the scroll-region by @num lines. New lines are cleared and reset
 * with the given attributes. Old lines are moved into the history if non-NULL.
 * If a new line is allocated, moved from the history buffer or moved from
 * outside the visible region into the visible region, this call makes sure it
 * has at least @width cells allocated. If a possible memory-allocation fails,
 * the previous line is reused. This has the side effect, that it will not be
 * linked into the history buffer.
 *
 * If the scroll-region is empty, this is a no-op.
 */
static void page_scroll_up(term_page *page, unsigned int new_width, unsigned int num, const term_attr *attr, term_age_t age, term_history *history) {
        term_line *line, **cache;
        unsigned int i;
        int r;

        assert(page);

        if (num > page->scroll_num)
                num = page->scroll_num;
        if (num < 1)
                return;

        /* Better safe than sorry: avoid under-allocating lines, even when
         * resizing. */
        new_width = MAX(new_width, page->width);

        cache = page->line_cache;

        /* Try moving lines into history and allocate new lines for each moved
         * line. In case allocation fails, or if we have no history, reuse the
         * line.
         * We keep the lines in the line-cache so we can safely move the
         * remaining lines around. */
        for (i = 0; i < num; ++i) {
                line = page->lines[page->scroll_idx + i];

                r = -EAGAIN;
                if (history) {
                        r = term_line_new(&cache[i]);
                        if (r >= 0) {
                                r = term_line_reserve(cache[i],
                                                      new_width,
                                                      attr,
                                                      age,
                                                      0);
                                if (r < 0)
                                        term_line_free(cache[i]);
                                else
                                        term_line_set_width(cache[i], page->width);
                        }
                }

                if (r >= 0) {
                        term_history_push(history, line);
                } else {
                        cache[i] = line;
                        term_line_reset(line, attr, age);
                }
        }

        if (num < page->scroll_num) {
                memmove(page->lines + page->scroll_idx,
                        page->lines + page->scroll_idx + num,
                        sizeof(*page->lines) * (page->scroll_num - num));

                /* update age of moved lines */
                for (i = 0; i < page->scroll_num - num; ++i)
                        page->lines[page->scroll_idx + i]->age = age;
        }

        /* copy remaining lines from cache; age is already updated */
        memcpy(page->lines + page->scroll_idx + page->scroll_num - num,
               cache,
               sizeof(*cache) * num);

        /* update fill */
        page->scroll_fill -= MIN(page->scroll_fill, num);
}

/**
 * page_scroll_down() - Scroll down
 * @page: page to operate on
 * @new_width: width to use for any new line moved into the visible area
 * @num: number of lines to scroll down
 * @attr: attributes to set on new lines
 * @age: age to use for all modifications
 * @history: history to use for new lines or NULL
 *
 * This scrolls the scroll-region by @num lines. New lines are retrieved from
 * the history or cleared if the history is empty or NULL.
 *
 * Usually, scroll-down implies that new lines are cleared. Therefore, you're
 * highly encouraged to set @history to NULL. However, if you resize a terminal,
 * you might want to include history-lines in the new area. In that case, you
 * should set @history to non-NULL.
 *
 * If a new line is allocated, moved from the history buffer or moved from
 * outside the visible region into the visible region, this call makes sure it
 * has at least @width cells allocated. If a possible memory-allocation fails,
 * the previous line is reused. This will have the side-effect that lines from
 * the history will not get visible on-screen but kept in history.
 *
 * If the scroll-region is empty, this is a no-op.
 */
static void page_scroll_down(term_page *page, unsigned int new_width, unsigned int num, const term_attr *attr, term_age_t age, term_history *history) {
        term_line *line, **cache, *t;
        unsigned int i, last_idx;

        assert(page);

        if (num > page->scroll_num)
                num = page->scroll_num;
        if (num < 1)
                return;

        /* Better safe than sorry: avoid under-allocating lines, even when
         * resizing. */
        new_width = MAX(new_width, page->width);

        cache = page->line_cache;
        last_idx = page->scroll_idx + page->scroll_num - 1;

        /* Try pulling out lines from history; if history is empty or if no
         * history is given, we reuse the to-be-removed lines. Otherwise, those
         * lines are released. */
        for (i = 0; i < num; ++i) {
                line = page->lines[last_idx - i];

                t = NULL;
                if (history)
                        t = term_history_pop(history, new_width, attr, age);

                if (t) {
                        cache[num - 1 - i] = t;
                        term_line_free(line);
                } else {
                        cache[num - 1 - i] = line;
                        term_line_reset(line, attr, age);
                }
        }

        if (num < page->scroll_num) {
                memmove(page->lines + page->scroll_idx + num,
                        page->lines + page->scroll_idx,
                        sizeof(*page->lines) * (page->scroll_num - num));

                /* update age of moved lines */
                for (i = 0; i < page->scroll_num - num; ++i)
                        page->lines[page->scroll_idx + num + i]->age = age;
        }

        /* copy remaining lines from cache; age is already updated */
        memcpy(page->lines + page->scroll_idx,
               cache,
               sizeof(*cache) * num);

        /* update fill; but only if there's already content in it */
        if (page->scroll_fill > 0)
                page->scroll_fill = MIN(page->scroll_num,
                                        page->scroll_fill + num);
}

/**
 * page_reserve() - Reserve page area
 * @page: page to modify
 * @cols: required columns (width)
 * @rows: required rows (height)
 * @attr: attributes for newly allocated cells
 * @age: age to set on any modified cells
 *
 * This allocates the required amount of lines and cells to guarantee that the
 * page has at least the demanded dimensions of @cols x @rows. Note that this
 * never shrinks the page-memory. We keep cells allocated for performance
 * reasons.
 *
 * Additionally to allocating lines, this also clears any newly added cells so
 * you can safely change the size afterwards without clearing new cells.
 *
 * Note that you must be careful what operations you call on the page between
 * page_reserve() and updating page->width/height. Any newly allocated line (or
 * shifted line) might not meet your new width/height expectations.
 *
 * Returns: 0 on success, negative error code on failure.
 */
int term_page_reserve(term_page *page, unsigned int cols, unsigned int rows, const term_attr *attr, term_age_t age) {
        _term_line_free_ term_line *line = NULL;
        unsigned int i, min_lines;
        term_line **t;
        int r;

        assert_return(page, -EINVAL);

        /*
         * First make sure the first MIN(page->n_lines, rows) lines have at
         * least the required width of @cols. This does not modify any visible
         * cells in the existing @page->width x @page->height area, therefore,
         * we can safely bail out afterwards in case anything else fails.
         * Note that lines in between page->height and page->n_lines might be
         * shorter than page->width. Hence, we need to resize them all, but we
         * can skip some of them for better performance.
         */
        min_lines = MIN(page->n_lines, rows);
        for (i = 0; i < min_lines; ++i) {
                /* lines below page->height have at least page->width cells */
                if (cols < page->width && i < page->height)
                        continue;

                r = term_line_reserve(page->lines[i],
                                      cols,
                                      attr,
                                      age,
                                      (i < page->height) ? page->width : 0);
                if (r < 0)
                        return r;
        }

        /*
         * We now know the first @min_lines lines have at least width @cols and
         * are prepared for resizing. We now only have to allocate any
         * additional lines below @min_lines in case @rows is greater than
         * page->n_lines.
         */
        if (rows > page->n_lines) {
                t = realloc_multiply(page->lines, sizeof(*t), rows);
                if (!t)
                        return -ENOMEM;
                page->lines = t;

                t = realloc_multiply(page->line_cache, sizeof(*t), rows);
                if (!t)
                        return -ENOMEM;
                page->line_cache = t;

                while (page->n_lines < rows) {
                        r = term_line_new(&line);
                        if (r < 0)
                                return r;

                        r = term_line_reserve(line, cols, attr, age, 0);
                        if (r < 0)
                                return r;

                        page->lines[page->n_lines++] = line;
                        line = NULL;
                }
        }

        return 0;
}

/**
 * term_page_resize() - Resize page
 * @page: page to modify
 * @cols: number of columns (width)
 * @rows: number of rows (height)
 * @attr: attributes for newly allocated cells
 * @age: age to set on any modified cells
 * @history: history buffer to use for new/old lines or NULL
 *
 * This changes the visible dimensions of a page. You must have called
 * term_page_reserve() beforehand, otherwise, this will fail.
 *
 * Returns: 0 on success, negative error code on failure.
 */
void term_page_resize(term_page *page, unsigned int cols, unsigned int rows, const term_attr *attr, term_age_t age, term_history *history) {
        unsigned int i, num, empty, max, old_height;
        term_line *line;

        assert(page);
        assert(page->n_lines >= rows);

        old_height = page->height;

        if (rows < old_height) {
                /*
                 * If we decrease the terminal-height, we emulate a scroll-up.
                 * This way, existing data from the scroll-area is moved into
                 * the history, making space at the bottom to reduce the screen
                 * height. In case the scroll-fill indicates empty lines, we
                 * reduce the amount of scrolled lines.
                 * Once scrolled, we have to move the lower margin from below
                 * the scroll area up so it is preserved.
                 */

                /* move lines to history if scroll region is filled */
                num = old_height - rows;
                empty = page->scroll_num - page->scroll_fill;
                if (num > empty)
                        page_scroll_up(page,
                                       cols,
                                       num - empty,
                                       attr,
                                       age,
                                       history);

                /* move lower margin up; drop its lines if not enough space */
                num = LESS_BY(old_height, page->scroll_idx + page->scroll_num);
                max = LESS_BY(rows, page->scroll_idx);
                num = MIN(num, max);
                if (num > 0) {
                        unsigned int top, bottom;

                        top = rows - num;
                        bottom = page->scroll_idx + page->scroll_num;

                        /* might overlap; must run topdown, not bottomup */
                        for (i = 0; i < num; ++i) {
                                line = page->lines[top + i];
                                page->lines[top + i] = page->lines[bottom + i];
                                page->lines[bottom + i] = line;
                        }
                }

                /* update vertical extents */
                page->height = rows;
                page->scroll_idx = MIN(page->scroll_idx, rows);
                page->scroll_num -= MIN(page->scroll_num, old_height - rows);
                /* fill is already up-to-date or 0 due to scroll-up */
        } else if (rows > old_height) {
                /*
                 * If we increase the terminal-height, we emulate a scroll-down
                 * and fetch new lines from the history.
                 * New lines are always accounted to the scroll-region. Thus we
                 * have to preserve the lower margin first, by moving it down.
                 */

                /* move lower margin down */
                num = LESS_BY(old_height, page->scroll_idx + page->scroll_num);
                if (num > 0) {
                        unsigned int top, bottom;

                        top = page->scroll_idx + page->scroll_num;
                        bottom = top + (rows - old_height);

                        /* might overlap; must run bottomup, not topdown */
                        for (i = num; i-- > 0; ) {
                                line = page->lines[top + i];
                                page->lines[top + i] = page->lines[bottom + i];
                                page->lines[bottom + i] = line;
                        }
                }

                /* update vertical extents */
                page->height = rows;
                page->scroll_num = MIN(LESS_BY(rows, page->scroll_idx),
                                       page->scroll_num + (rows - old_height));

                /* check how many lines can be received from history */
                if (history)
                        num = term_history_peek(history,
                                                rows - old_height,
                                                cols,
                                                attr,
                                                age);
                else
                        num = 0;

                /* retrieve new lines from history if available */
                if (num > 0)
                        page_scroll_down(page,
                                         cols,
                                         num,
                                         attr,
                                         age,
                                         history);
        }

        /* set horizontal extents */
        page->width = cols;
        for (i = 0; i < page->height; ++i)
                term_line_set_width(page->lines[i], cols);
}

/**
 * term_page_write() - Write to a single cell
 * @page: page to operate on
 * @pos_x: x-position of cell to write to
 * @pos_y: y-position of cell to write to
 * @ch: character to write
 * @cwidth: character-width of @ch
 * @attr: attributes to set on the cell or NULL
 * @age: age to use for all modifications
 * @insert_mode: true if INSERT-MODE is enabled
 *
 * This writes a character to a specific cell. If the cell is beyond bounds,
 * this is a no-op. @attr and @age are used to update the cell. @flags can be
 * used to alter the behavior of this function.
 *
 * This is a wrapper around term_line_write().
 *
 * This call does not wrap around lines. That is, this only operates on a single
 * line.
 */
void term_page_write(term_page *page, unsigned int pos_x, unsigned int pos_y, term_char_t ch, unsigned int cwidth, const term_attr *attr, term_age_t age, bool insert_mode) {
        assert(page);

        if (pos_y >= page->height)
                return;

        term_line_write(page->lines[pos_y], pos_x, ch, cwidth, attr, age, insert_mode);
}

/**
 * term_page_insert_cells() - Insert cells into a line
 * @page: page to operate on
 * @from_x: x-position where to insert new cells
 * @from_y: y-position where to insert new cells
 * @num: number of cells to insert
 * @attr: attributes to set on new cells or NULL
 * @age: age to use for all modifications
 *
 * This inserts new cells into a given line. This is a wrapper around
 * term_line_insert().
 *
 * This call does not wrap around lines. That is, this only operates on a single
 * line.
 */
void term_page_insert_cells(term_page *page, unsigned int from_x, unsigned int from_y, unsigned int num, const term_attr *attr, term_age_t age) {
        assert(page);

        if (from_y >= page->height)
                return;

        term_line_insert(page->lines[from_y], from_x, num, attr, age);
}

/**
 * term_page_delete_cells() - Delete cells from a line
 * @page: page to operate on
 * @from_x: x-position where to delete cells
 * @from_y: y-position where to delete cells
 * @num: number of cells to delete
 * @attr: attributes to set on new cells or NULL
 * @age: age to use for all modifications
 *
 * This deletes cells from a given line. This is a wrapper around
 * term_line_delete().
 *
 * This call does not wrap around lines. That is, this only operates on a single
 * line.
 */
void term_page_delete_cells(term_page *page, unsigned int from_x, unsigned int from_y, unsigned int num, const term_attr *attr, term_age_t age) {
        assert(page);

        if (from_y >= page->height)
                return;

        term_line_delete(page->lines[from_y], from_x, num, attr, age);
}

/**
 * term_page_append_combchar() - Append combining-character to a cell
 * @page: page to operate on
 * @pos_x: x-position of target cell
 * @pos_y: y-position of target cell
 * @ucs4: combining character to append
 * @age: age to use for all modifications
 *
 * This appends a combining-character to a specific cell. This is a wrapper
 * around term_line_append_combchar().
 */
void term_page_append_combchar(term_page *page, unsigned int pos_x, unsigned int pos_y, uint32_t ucs4, term_age_t age) {
        assert(page);

        if (pos_y >= page->height)
                return;

        term_line_append_combchar(page->lines[pos_y], pos_x, ucs4, age);
}

/**
 * term_page_erase() - Erase parts of a page
 * @page: page to operate on
 * @from_x: x-position where to start erasure (inclusive)
 * @from_y: y-position where to start erasure (inclusive)
 * @to_x: x-position where to stop erasure (inclusive)
 * @to_y: y-position where to stop erasure (inclusive)
 * @attr: attributes to set on cells
 * @age: age to use for all modifications
 * @keep_protected: true if protected cells should be kept
 *
 * This erases all cells starting at @from_x/@from_y up to @to_x/@to_y. Note
 * that this wraps around line-boundaries so lines between @from_y and @to_y
 * are cleared entirely.
 *
 * Lines outside the visible area are left untouched.
 */
void term_page_erase(term_page *page, unsigned int from_x, unsigned int from_y, unsigned int to_x, unsigned int to_y, const term_attr *attr, term_age_t age, bool keep_protected) {
        unsigned int i, from, to;

        assert(page);

        for (i = from_y; i <= to_y && i < page->height; ++i) {
                from = 0;
                to = page->width;

                if (i == from_y)
                        from = from_x;
                if (i == to_y)
                        to = to_x;

                term_line_erase(page->lines[i],
                                from,
                                LESS_BY(to, from),
                                attr,
                                age,
                                keep_protected);
        }
}

/**
 * term_page_reset() - Reset page
 * @page: page to modify
 * @attr: attributes to set on cells
 * @age: age to use for all modifications
 *
 * This erases the whole visible page. See term_page_erase().
 */
void term_page_reset(term_page *page, const term_attr *attr, term_age_t age) {
        assert(page);

        return term_page_erase(page,
                               0, 0,
                               page->width - 1, page->height - 1,
                               attr,
                               age,
                               0);
}

/**
 * term_page_set_scroll_region() - Set scroll region
 * @page: page to operate on
 * @idx: start-index of scroll region
 * @num: number of lines in scroll region
 *
 * This sets the scroll region of a page. Whenever an operation needs to scroll
 * lines, it scrolls them inside of that region. Lines outside the region are
 * left untouched. In case a scroll-operation is targeted outside of this
 * region, it will implicitly get a scroll-region of only one line (i.e., no
 * scroll region at all).
 *
 * Note that the scroll-region is clipped to the current page-extents. Growing
 * or shrinking the page always accounts new/old lines to the scroll region and
 * moves top/bottom margins accordingly so they're preserved.
 */
void term_page_set_scroll_region(term_page *page, unsigned int idx, unsigned int num) {
        assert(page);

        if (page->height < 1) {
                page->scroll_idx = 0;
                page->scroll_num = 0;
        } else {
                page->scroll_idx = MIN(idx, page->height - 1);
                page->scroll_num = MIN(num, page->height - page->scroll_idx);
        }
}

/**
 * term_page_scroll_up() - Scroll up
 * @page: page to operate on
 * @num: number of lines to scroll up
 * @attr: attributes to set on new lines
 * @age: age to use for all modifications
 * @history: history to use for old lines or NULL
 *
 * This scrolls the scroll-region by @num lines. New lines are cleared and reset
 * with the given attributes. Old lines are moved into the history if non-NULL.
 *
 * If the scroll-region is empty, this is a no-op.
 */
void term_page_scroll_up(term_page *page, unsigned int num, const term_attr *attr, term_age_t age, term_history *history) {
        page_scroll_up(page, page->width, num, attr, age, history);
}

/**
 * term_page_scroll_down() - Scroll down
 * @page: page to operate on
 * @num: number of lines to scroll down
 * @attr: attributes to set on new lines
 * @age: age to use for all modifications
 * @history: history to use for new lines or NULL
 *
 * This scrolls the scroll-region by @num lines. New lines are retrieved from
 * the history or cleared if the history is empty or NULL.
 *
 * Usually, scroll-down implies that new lines are cleared. Therefore, you're
 * highly encouraged to set @history to NULL. However, if you resize a terminal,
 * you might want to include history-lines in the new area. In that case, you
 * should set @history to non-NULL.
 *
 * If the scroll-region is empty, this is a no-op.
 */
void term_page_scroll_down(term_page *page, unsigned int num, const term_attr *attr, term_age_t age, term_history *history) {
        page_scroll_down(page, page->width, num, attr, age, history);
}

/**
 * term_page_insert_lines() - Insert new lines
 * @page: page to operate on
 * @pos_y: y-position where to insert new lines
 * @num: number of lines to insert
 * @attr: attributes to set on new lines
 * @age: age to use for all modifications
 *
 * This inserts @num new lines at position @pos_y. If @pos_y is beyond
 * boundaries or @num is 0, this is a no-op.
 * All lines below @pos_y are moved down to make space for the new lines. Lines
 * on the bottom are dropped. Note that this only moves lines above or inside
 * the scroll-region. If @pos_y is below the scroll-region, a scroll-region of
 * one line is implied (which means the line is simply cleared).
 */
void term_page_insert_lines(term_page *page, unsigned int pos_y, unsigned int num, const term_attr *attr, term_age_t age) {
        unsigned int scroll_idx, scroll_num;

        assert(page);

        if (pos_y >= page->height)
                return;
        if (num >= page->height)
                num = page->height;

        /* remember scroll-region */
        scroll_idx = page->scroll_idx;
        scroll_num = page->scroll_num;

        /* set scroll-region temporarily so we can reuse scroll_down() */
        {
                page->scroll_idx = pos_y;
                if (pos_y >= scroll_idx + scroll_num)
                        page->scroll_num = 1;
                else if (pos_y >= scroll_idx)
                        page->scroll_num -= pos_y - scroll_idx;
                else
                        page->scroll_num += scroll_idx - pos_y;

                term_page_scroll_down(page, num, attr, age, NULL);
        }

        /* reset scroll-region */
        page->scroll_idx = scroll_idx;
        page->scroll_num = scroll_num;
}

/**
 * term_page_delete_lines() - Delete lines
 * @page: page to operate on
 * @pos_y: y-position where to delete lines
 * @num: number of lines to delete
 * @attr: attributes to set on new lines
 * @age: age to use for all modifications
 *
 * This deletes @num lines at position @pos_y. If @pos_y is beyond boundaries or
 * @num is 0, this is a no-op.
 * All lines below @pos_y are moved up into the newly made space. New lines
 * on the bottom are clear. Note that this only moves lines above or inside
 * the scroll-region. If @pos_y is below the scroll-region, a scroll-region of
 * one line is implied (which means the line is simply cleared).
 */
void term_page_delete_lines(term_page *page, unsigned int pos_y, unsigned int num, const term_attr *attr, term_age_t age) {
        unsigned int scroll_idx, scroll_num;

        assert(page);

        if (pos_y >= page->height)
                return;
        if (num >= page->height)
                num = page->height;

        /* remember scroll-region */
        scroll_idx = page->scroll_idx;
        scroll_num = page->scroll_num;

        /* set scroll-region temporarily so we can reuse scroll_up() */
        {
                page->scroll_idx = pos_y;
                if (pos_y >= scroll_idx + scroll_num)
                        page->scroll_num = 1;
                else if (pos_y > scroll_idx)
                        page->scroll_num -= pos_y - scroll_idx;
                else
                        page->scroll_num += scroll_idx - pos_y;

                term_page_scroll_up(page, num, attr, age, NULL);
        }

        /* reset scroll-region */
        page->scroll_idx = scroll_idx;
        page->scroll_num = scroll_num;
}

/**
 * term_history_new() - Create new history object
 * @out: storage for pointer to new history
 *
 * Create a new history object. Histories are used to store scrollback-lines
 * from VTE pages. You're highly recommended to set a history-limit on
 * history->max_lines and trim it via term_history_trim(), otherwise history
 * allocations are unlimited.
 *
 * Returns: 0 on success, negative error code on failure.
 */
int term_history_new(term_history **out) {
        _term_history_free_ term_history *history = NULL;

        assert_return(out, -EINVAL);

        history = new0(term_history, 1);
        if (!history)
                return -ENOMEM;

        history->max_lines = 4096;

        *out = history;
        history = NULL;
        return 0;
}

/**
 * term_history_free() - Free history
 * @history: history to free
 *
 * Clear and free history. You must not access the object afterwards.
 *
 * Returns: NULL
 */
term_history *term_history_free(term_history *history) {
        if (!history)
                return NULL;

        term_history_clear(history);
        free(history);
        return NULL;
}

/**
 * term_history_clear() - Clear history
 * @history: history to clear
 *
 * Remove all linked lines from a history and reset it to its initial state.
 */
void term_history_clear(term_history *history) {
        return term_history_trim(history, 0);
}

/**
 * term_history_trim() - Trim history
 * @history: history to trim
 * @max: maximum number of lines to be left in history
 *
 * This removes lines from the history until it is smaller than @max. Lines are
 * removed from the top.
 */
void term_history_trim(term_history *history, unsigned int max) {
        term_line *line;

        if (!history)
                return;

        while (history->n_lines > max && (line = history->lines_first)) {
                TERM_LINE_UNLINK(line, history);
                term_line_free(line);
                --history->n_lines;
        }
}

/**
 * term_history_push() - Push line into history
 * @history: history to work on
 * @line: line to push into history
 *
 * This pushes a line into the given history. It is linked at the tail. In case
 * the history is limited, the top-most line might be freed.
 */
void term_history_push(term_history *history, term_line *line) {
        assert(history);
        assert(line);

        TERM_LINE_LINK_TAIL(line, history);
        if (history->max_lines > 0 && history->n_lines >= history->max_lines) {
                line = history->lines_first;
                TERM_LINE_UNLINK(line, history);
                term_line_free(line);
        } else {
                ++history->n_lines;
        }
}

/**
 * term_history_pop() - Retrieve last line from history
 * @history: history to work on
 * @new_width: width to reserve and set on the line
 * @attr: attributes to use for cell reservation
 * @age: age to use for cell reservation
 *
 * This unlinks the last linked line of the history and returns it. This also
 * makes sure the line has the given width pre-allocated (see
 * term_line_reserve()). If the pre-allocation fails, this returns NULL, so it
 * is treated like there's no line in history left. This simplifies
 * history-handling on the caller's side in case of allocation errors. No need
 * to throw lines away just because the reservation failed. We can keep them in
 * history safely, and make them available as scrollback.
 *
 * Returns: Line from history or NULL
 */
term_line *term_history_pop(term_history *history, unsigned int new_width, const term_attr *attr, term_age_t age) {
        term_line *line;
        int r;

        assert_return(history, NULL);

        line = history->lines_last;
        if (!line)
                return NULL;

        r = term_line_reserve(line, new_width, attr, age, line->width);
        if (r < 0)
                return NULL;

        term_line_set_width(line, new_width);
        TERM_LINE_UNLINK(line, history);
        --history->n_lines;

        return line;
}

/**
 * term_history_peek() - Return number of available history-lines
 * @history: history to work on
 * @max: maximum number of lines to look at
 * @reserve_width: width to reserve on the line
 * @attr: attributes to use for cell reservation
 * @age: age to use for cell reservation
 *
 * This returns the number of available lines in the history given as @history.
 * It returns at most @max. For each line that is looked at, the line is
 * verified to have at least @reserve_width cells. Valid cells are preserved,
 * new cells are initialized with @attr and @age. In case an allocation fails,
 * we bail out and return the number of lines that are valid so far.
 *
 * Usually, this function should be used before running a loop on
 * term_history_pop(). This function guarantees that term_history_pop() (with
 * the same arguments) will succeed at least the returned number of times.
 *
 * Returns: Number of valid lines that can be received via term_history_pop().
 */
unsigned int term_history_peek(term_history *history, unsigned int max, unsigned int reserve_width, const term_attr *attr, term_age_t age) {
        unsigned int num;
        term_line *line;
        int r;

        assert(history);

        num = 0;
        line = history->lines_last;

        while (num < max && line) {
                r = term_line_reserve(line, reserve_width, attr, age, line->width);
                if (r < 0)
                        break;

                ++num;
                line = line->lines_prev;
        }

        return num;
}
