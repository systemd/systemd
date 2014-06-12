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
 * sorrounding struct is just to hide the internals. A term-char can contain a
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
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <wchar.h>
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
                DISABLE_WARNING_SHADOW;
                line->fill = MIN(line->width,
                                 MAX(line->fill + num,
                                     from + num));
                REENABLE_WARNING;
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
                DISABLE_WARNING_SHADOW;
                line->fill = MIN(line->width,
                                 MAX(line->fill,
                                     pos_x + len));
                REENABLE_WARNING;
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
 * This is the standard erase operation. It clears all cells in the targetted
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
