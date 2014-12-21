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
 * Terminal Parser
 * This file contains a bunch of UTF-8 helpers and the main ctlseq-parser. The
 * parser is a simple state-machine that correctly parses all CSI, DCS, OSC, ST
 * control sequences and generic escape sequences.
 * The parser itself does not perform any actions but lets the caller react to
 * detected sequences.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "macro.h"
#include "term-internal.h"
#include "util.h"

static const uint8_t default_palette[18][3] = {
        {   0,   0,   0 }, /* black */
        { 205,   0,   0 }, /* red */
        {   0, 205,   0 }, /* green */
        { 205, 205,   0 }, /* yellow */
        {   0,   0, 238 }, /* blue */
        { 205,   0, 205 }, /* magenta */
        {   0, 205, 205 }, /* cyan */
        { 229, 229, 229 }, /* light grey */
        { 127, 127, 127 }, /* dark grey */
        { 255,   0,   0 }, /* light red */
        {   0, 255,   0 }, /* light green */
        { 255, 255,   0 }, /* light yellow */
        {  92,  92, 255 }, /* light blue */
        { 255,   0, 255 }, /* light magenta */
        {   0, 255, 255 }, /* light cyan */
        { 255, 255, 255 }, /* white */

        { 229, 229, 229 }, /* light grey */
        {   0,   0,   0 }, /* black */
};

static uint32_t term_color_to_argb32(const term_color *color, const term_attr *attr, const uint8_t *palette) {
        static const uint8_t bval[] = {
                0x00, 0x5f, 0x87,
                0xaf, 0xd7, 0xff,
        };
        uint8_t r, g, b, t;

        assert(color);

        if (!palette)
                palette = (void*)default_palette;

        switch (color->ccode) {
        case TERM_CCODE_RGB:
                r = color->red;
                g = color->green;
                b = color->blue;

                break;
        case TERM_CCODE_256:
                t = color->c256;
                if (t < 16) {
                        r = palette[t * 3 + 0];
                        g = palette[t * 3 + 1];
                        b = palette[t * 3 + 2];
                } else if (t < 232) {
                        t -= 16;
                        b = bval[t % 6];
                        t /= 6;
                        g = bval[t % 6];
                        t /= 6;
                        r = bval[t % 6];
                } else {
                        t = (t - 232) * 10 + 8;
                        r = t;
                        g = t;
                        b = t;
                }

                break;
        case TERM_CCODE_BLACK ... TERM_CCODE_LIGHT_WHITE:
                t = color->ccode - TERM_CCODE_BLACK;

                /* bold causes light colors (only for foreground colors) */
                if (t < 8 && attr->bold && color == &attr->fg)
                        t += 8;

                r = palette[t * 3 + 0];
                g = palette[t * 3 + 1];
                b = palette[t * 3 + 2];
                break;
        case TERM_CCODE_DEFAULT:
                /* fallthrough */
        default:
                t = 16 + !(color == &attr->fg);
                r = palette[t * 3 + 0];
                g = palette[t * 3 + 1];
                b = palette[t * 3 + 2];
                break;
        }

        return (0xff << 24) | (r << 16) | (g << 8) | b;
}

/**
 * term_attr_to_argb32() - Encode terminal colors as native ARGB32 value
 * @color: Terminal attributes to work on
 * @fg: Storage for foreground color (or NULL)
 * @bg: Storage for background color (or NULL)
 * @palette: The color palette to use (or NULL for default)
 *
 * This encodes the colors attr->fg and attr->bg as native-endian ARGB32 values
 * and returns them. Any color conversions are automatically applied.
 */
void term_attr_to_argb32(const term_attr *attr, uint32_t *fg, uint32_t *bg, const uint8_t *palette) {
        uint32_t f, b, t;

        assert(attr);

        f = term_color_to_argb32(&attr->fg, attr, palette);
        b = term_color_to_argb32(&attr->bg, attr, palette);

        if (attr->inverse) {
                t = f;
                f = b;
                b = t;
        }

        if (fg)
                *fg = f;
        if (bg)
                *bg = b;
}

/**
 * term_utf8_decode() - Try decoding the next UCS-4 character
 * @p: decoder object to operate on or NULL
 * @out_len: output storage for pointer to decoded UCS-4 string or NULL
 * @c: next char to push into decoder
 *
 * This decodes a UTF-8 stream. It must be called for each input-byte of the
 * UTF-8 stream and returns a UCS-4 stream. A pointer to the parsed UCS-4
 * string is stored in @out_buf if non-NULL. The length of this string (number
 * of parsed UCS4 characters) is returned as result. The string is not
 * zero-terminated! Furthermore, the string is only valid until the next
 * invocation of this function. It is also bound to the parser state @p and
 * must not be freed nor written to by the caller.
 *
 * This function is highly optimized to work with terminal-emulators. Instead
 * of being strict about UTF-8 validity, this tries to perform a fallback to
 * ISO-8859-1 in case a wrong series was detected. Therefore, this function
 * might return multiple UCS-4 characters by parsing just a single UTF-8 byte.
 *
 * The parser state @p should be allocated and managed by the caller. There're
 * no helpers to do that for you. To initialize it, simply reset it to all
 * zero. You can reset or free the object at any point in time.
 *
 * Returns: Number of parsed UCS4 characters
 */
size_t term_utf8_decode(term_utf8 *p, uint32_t **out_buf, char c) {
        static uint32_t ucs4_null = 0;
        uint32_t t, *res = NULL;
        uint8_t byte;
        size_t len = 0;

        if (!p)
                goto out;

        byte = c;

        if (!p->valid || p->i_bytes >= p->n_bytes) {
                /*
                 * If the previous sequence was invalid or fully parsed, start
                 * parsing a fresh new sequence.
                 */

                if ((byte & 0xE0) == 0xC0) {
                        /* start of two byte sequence */
                        t = byte & 0x1F;
                        p->n_bytes = 2;
                        p->i_bytes = 1;
                        p->valid = 1;
                } else if ((byte & 0xF0) == 0xE0) {
                        /* start of three byte sequence */
                        t = byte & 0x0F;
                        p->n_bytes = 3;
                        p->i_bytes = 1;
                        p->valid = 1;
                } else if ((byte & 0xF8) == 0xF0) {
                        /* start of four byte sequence */
                        t = byte & 0x07;
                        p->n_bytes = 4;
                        p->i_bytes = 1;
                        p->valid = 1;
                } else {
                        /* Either of:
                         *  - single ASCII 7-bit char
                         *  - out-of-sync continuation byte
                         *  - overlong encoding
                         * All of them are treated as single byte ISO-8859-1 */
                        t = byte;
                        p->n_bytes = 1;
                        p->i_bytes = 1;
                        p->valid = 0;
                }

                p->chars[0] = byte;
                p->ucs4 = t << (6 * (p->n_bytes - p->i_bytes));
        } else {
                /*
                 * ..otherwise, try to continue the previous sequence..
                 */

                if ((byte & 0xC0) == 0x80) {
                        /*
                         * Valid continuation byte. Append to sequence and
                         * update the ucs4 cache accordingly.
                         */

                        t = byte & 0x3F;
                        p->chars[p->i_bytes++] = byte;
                        p->ucs4 |= t << (6 * (p->n_bytes - p->i_bytes));
                } else {
                        /*
                         * Invalid continuation? Treat cached sequence as
                         * ISO-8859-1, but parse the new char as valid new
                         * starting character. If it's a new single-byte UTF-8
                         * sequence, we immediately return it in the same run,
                         * otherwise, we might suffer from starvation.
                         */

                        if ((byte & 0xE0) == 0xC0 ||
                            (byte & 0xF0) == 0xE0 ||
                            (byte & 0xF8) == 0xF0) {
                                /*
                                 * New multi-byte sequence. Move to-be-returned
                                 * data at the end and start new sequence. Only
                                 * return the old sequence.
                                 */

                                memmove(p->chars + 1,
                                        p->chars,
                                        sizeof(*p->chars) * p->i_bytes);
                                res = p->chars + 1;
                                len = p->i_bytes;

                                if ((byte & 0xE0) == 0xC0) {
                                        /* start of two byte sequence */
                                        t = byte & 0x1F;
                                        p->n_bytes = 2;
                                        p->i_bytes = 1;
                                        p->valid = 1;
                                } else if ((byte & 0xF0) == 0xE0) {
                                        /* start of three byte sequence */
                                        t = byte & 0x0F;
                                        p->n_bytes = 3;
                                        p->i_bytes = 1;
                                        p->valid = 1;
                                } else if ((byte & 0xF8) == 0xF0) {
                                        /* start of four byte sequence */
                                        t = byte & 0x07;
                                        p->n_bytes = 4;
                                        p->i_bytes = 1;
                                        p->valid = 1;
                                } else
                                        assert_not_reached("Should not happen");

                                p->chars[0] = byte;
                                p->ucs4 = t << (6 * (p->n_bytes - p->i_bytes));

                                goto out;
                        } else {
                                /*
                                 * New single byte sequence, append to output
                                 * and return combined sequence.
                                 */

                                p->chars[p->i_bytes++] = byte;
                                p->valid = 0;
                        }
                }
        }

        /*
         * Check whether a full sequence (valid or invalid) has been parsed and
         * then return it. Otherwise, return nothing.
         */
        if (p->valid) {
                /* still parsing? then bail out */
                if (p->i_bytes < p->n_bytes)
                        goto out;

                res = &p->ucs4;
                len = 1;
        } else {
                res = p->chars;
                len = p->i_bytes;
        }

        p->valid = 0;
        p->i_bytes = 0;
        p->n_bytes = 0;

out:
        if (out_buf)
                *out_buf = res ? : &ucs4_null;
        return len;
}

/*
 * Command Parser
 * The ctl-seq parser "term_parser" only detects whole sequences, it does not
 * detect the specific command. Once a sequence is parsed, the command-parsers
 * are used to figure out their meaning. Note that this depends on whether we
 * run on the host or terminal side.
 */

static unsigned int term_parse_host_control(const term_seq *seq) {
        assert_return(seq, TERM_CMD_NONE);

        switch (seq->terminator) {
        case 0x00: /* NUL */
                return TERM_CMD_NULL;
        case 0x05: /* ENQ */
                return TERM_CMD_ENQ;
        case 0x07: /* BEL */
                return TERM_CMD_BEL;
        case 0x08: /* BS */
                return TERM_CMD_BS;
        case 0x09: /* HT */
                return TERM_CMD_HT;
        case 0x0a: /* LF */
                return TERM_CMD_LF;
        case 0x0b: /* VT */
                return TERM_CMD_VT;
        case 0x0c: /* FF */
                return TERM_CMD_FF;
        case 0x0d: /* CR */
                return TERM_CMD_CR;
        case 0x0e: /* SO */
                return TERM_CMD_SO;
        case 0x0f: /* SI */
                return TERM_CMD_SI;
        case 0x11: /* DC1 */
                return TERM_CMD_DC1;
        case 0x13: /* DC3 */
                return TERM_CMD_DC3;
        case 0x18: /* CAN */
                /* this is already handled by the state-machine */
                break;
        case 0x1a: /* SUB */
                return TERM_CMD_SUB;
        case 0x1b: /* ESC */
                /* this is already handled by the state-machine */
                break;
        case 0x1f: /* DEL */
                /* this is already handled by the state-machine */
                break;
        case 0x84: /* IND */
                return TERM_CMD_IND;
        case 0x85: /* NEL */
                return TERM_CMD_NEL;
        case 0x88: /* HTS */
                return TERM_CMD_HTS;
        case 0x8d: /* RI */
                return TERM_CMD_RI;
        case 0x8e: /* SS2 */
                return TERM_CMD_SS2;
        case 0x8f: /* SS3 */
                return TERM_CMD_SS3;
        case 0x90: /* DCS */
                /* this is already handled by the state-machine */
                break;
        case 0x96: /* SPA */
                return TERM_CMD_SPA;
        case 0x97: /* EPA */
                return TERM_CMD_EPA;
        case 0x98: /* SOS */
                /* this is already handled by the state-machine */
                break;
        case 0x9a: /* DECID */
                return TERM_CMD_DECID;
        case 0x9b: /* CSI */
                /* this is already handled by the state-machine */
                break;
        case 0x9c: /* ST */
                return TERM_CMD_ST;
        case 0x9d: /* OSC */
                /* this is already handled by the state-machine */
                break;
        case 0x9e: /* PM */
                /* this is already handled by the state-machine */
                break;
        case 0x9f: /* APC */
                /* this is already handled by the state-machine */
                break;
        }

        return TERM_CMD_NONE;
}

static inline int charset_from_cmd(uint32_t raw, unsigned int flags, bool require_96) {
        static const struct {
                uint32_t raw;
                unsigned int flags;
        } charset_cmds[] = {
                /* 96-compat charsets */
                [TERM_CHARSET_ISO_LATIN1_SUPPLEMENTAL]   = { .raw = 'A', .flags = 0 },
                [TERM_CHARSET_ISO_LATIN2_SUPPLEMENTAL]   = { .raw = 'B', .flags = 0 },
                [TERM_CHARSET_ISO_LATIN5_SUPPLEMENTAL]   = { .raw = 'M', .flags = 0 },
                [TERM_CHARSET_ISO_GREEK_SUPPLEMENTAL]    = { .raw = 'F', .flags = 0 },
                [TERM_CHARSET_ISO_HEBREW_SUPPLEMENTAL]   = { .raw = 'H', .flags = 0 },
                [TERM_CHARSET_ISO_LATIN_CYRILLIC]        = { .raw = 'L', .flags = 0 },

                /* 94-compat charsets */
                [TERM_CHARSET_DEC_SPECIAL_GRAPHIC]       = { .raw = '0', .flags = 0 },
                [TERM_CHARSET_DEC_SUPPLEMENTAL]          = { .raw = '5', .flags = TERM_SEQ_FLAG_PERCENT },
                [TERM_CHARSET_DEC_TECHNICAL]             = { .raw = '>', .flags = 0 },
                [TERM_CHARSET_CYRILLIC_DEC]              = { .raw = '4', .flags = TERM_SEQ_FLAG_AND },
                [TERM_CHARSET_DUTCH_NRCS]                = { .raw = '4', .flags = 0 },
                [TERM_CHARSET_FINNISH_NRCS]              = { .raw = '5', .flags = 0 },
                [TERM_CHARSET_FRENCH_NRCS]               = { .raw = 'R', .flags = 0 },
                [TERM_CHARSET_FRENCH_CANADIAN_NRCS]      = { .raw = '9', .flags = 0 },
                [TERM_CHARSET_GERMAN_NRCS]               = { .raw = 'K', .flags = 0 },
                [TERM_CHARSET_GREEK_DEC]                 = { .raw = '?', .flags = TERM_SEQ_FLAG_DQUOTE },
                [TERM_CHARSET_GREEK_NRCS]                = { .raw = '>', .flags = TERM_SEQ_FLAG_DQUOTE },
                [TERM_CHARSET_HEBREW_DEC]                = { .raw = '4', .flags = TERM_SEQ_FLAG_DQUOTE },
                [TERM_CHARSET_HEBREW_NRCS]               = { .raw = '=', .flags = TERM_SEQ_FLAG_PERCENT },
                [TERM_CHARSET_ITALIAN_NRCS]              = { .raw = 'Y', .flags = 0 },
                [TERM_CHARSET_NORWEGIAN_DANISH_NRCS]     = { .raw = '`', .flags = 0 },
                [TERM_CHARSET_PORTUGUESE_NRCS]           = { .raw = '6', .flags = TERM_SEQ_FLAG_PERCENT },
                [TERM_CHARSET_RUSSIAN_NRCS]              = { .raw = '5', .flags = TERM_SEQ_FLAG_AND },
                [TERM_CHARSET_SCS_NRCS]                  = { .raw = '3', .flags = TERM_SEQ_FLAG_PERCENT },
                [TERM_CHARSET_SPANISH_NRCS]              = { .raw = 'Z', .flags = 0 },
                [TERM_CHARSET_SWEDISH_NRCS]              = { .raw = '7', .flags = 0 },
                [TERM_CHARSET_SWISS_NRCS]                = { .raw = '=', .flags = 0 },
                [TERM_CHARSET_TURKISH_DEC]               = { .raw = '0', .flags = TERM_SEQ_FLAG_PERCENT },
                [TERM_CHARSET_TURKISH_NRCS]              = { .raw = '2', .flags = TERM_SEQ_FLAG_PERCENT },

                /* special charsets */
                [TERM_CHARSET_USERPREF_SUPPLEMENTAL]     = { .raw = '<', .flags = 0 },

                /* secondary choices */
                [TERM_CHARSET_CNT + TERM_CHARSET_FINNISH_NRCS]            = { .raw = 'C', .flags = 0 },
                [TERM_CHARSET_CNT + TERM_CHARSET_FRENCH_NRCS]             = { .raw = 'f', .flags = 0 },
                [TERM_CHARSET_CNT + TERM_CHARSET_FRENCH_CANADIAN_NRCS]    = { .raw = 'Q', .flags = 0 },
                [TERM_CHARSET_CNT + TERM_CHARSET_NORWEGIAN_DANISH_NRCS]   = { .raw = 'E', .flags = 0 },
                [TERM_CHARSET_CNT + TERM_CHARSET_SWEDISH_NRCS]            = { .raw = 'H', .flags = 0 }, /* unused; conflicts with ISO_HEBREW */

                /* tertiary choices */
                [TERM_CHARSET_CNT + TERM_CHARSET_CNT + TERM_CHARSET_NORWEGIAN_DANISH_NRCS] = { .raw = '6', .flags = 0 },
        };
        size_t i, cs;

        /*
         * Secondary choice on SWEDISH_NRCS and primary choice on
         * ISO_HEBREW_SUPPLEMENTAL have a conflict: raw=="H", flags==0.
         * We always choose the ISO 96-compat set, which is what VT510 does.
         */

        for (i = 0; i < ELEMENTSOF(charset_cmds); ++i) {
                if (charset_cmds[i].raw == raw && charset_cmds[i].flags == flags) {
                        cs = i;
                        while (cs >= TERM_CHARSET_CNT)
                                cs -= TERM_CHARSET_CNT;

                        if (!require_96 || cs < TERM_CHARSET_96_CNT || cs >= TERM_CHARSET_94_CNT)
                                return cs;
                }
        }

        return -ENOENT;
}

/* true if exactly one bit in @value is set */
static inline bool exactly_one_bit_set(unsigned int value) {
        return __builtin_popcount(value) == 1;
}

static unsigned int term_parse_host_escape(const term_seq *seq, unsigned int *cs_out) {
        unsigned int t, flags;
        int cs;

        assert_return(seq, TERM_CMD_NONE);

        flags = seq->intermediates;
        t = TERM_SEQ_FLAG_POPEN | TERM_SEQ_FLAG_PCLOSE | TERM_SEQ_FLAG_MULT |
            TERM_SEQ_FLAG_PLUS  | TERM_SEQ_FLAG_MINUS  | TERM_SEQ_FLAG_DOT  |
            TERM_SEQ_FLAG_SLASH;

        if (exactly_one_bit_set(flags & t)) {
                switch (flags & t) {
                case TERM_SEQ_FLAG_POPEN:
                case TERM_SEQ_FLAG_PCLOSE:
                case TERM_SEQ_FLAG_MULT:
                case TERM_SEQ_FLAG_PLUS:
                        cs = charset_from_cmd(seq->terminator, flags & ~t, false);
                        break;
                case TERM_SEQ_FLAG_MINUS:
                case TERM_SEQ_FLAG_DOT:
                case TERM_SEQ_FLAG_SLASH:
                        cs = charset_from_cmd(seq->terminator, flags & ~t, true);
                        break;
                default:
                        cs = -ENOENT;
                        break;
                }

                if (cs >= 0) {
                        if (cs_out)
                                *cs_out = cs;
                        return TERM_CMD_SCS;
                }

                /* looked like a charset-cmd but wasn't; continue */
        }

        switch (seq->terminator) {
        case '3':
                if (flags == TERM_SEQ_FLAG_HASH) /* DECDHL top-half */
                        return TERM_CMD_DECDHL_TH;
                break;
        case '4':
                if (flags == TERM_SEQ_FLAG_HASH) /* DECDHL bottom-half */
                        return TERM_CMD_DECDHL_BH;
                break;
        case '5':
                if (flags == TERM_SEQ_FLAG_HASH) /* DECSWL */
                        return TERM_CMD_DECSWL;
                break;
        case '6':
                if (flags == 0) /* DECBI */
                        return TERM_CMD_DECBI;
                else if (flags == TERM_SEQ_FLAG_HASH) /* DECDWL */
                        return TERM_CMD_DECDWL;
                break;
        case '7':
                if (flags == 0) /* DECSC */
                        return TERM_CMD_DECSC;
                break;
        case '8':
                if (flags == 0) /* DECRC */
                        return TERM_CMD_DECRC;
                else if (flags == TERM_SEQ_FLAG_HASH) /* DECALN */
                        return TERM_CMD_DECALN;
                break;
        case '9':
                if (flags == 0) /* DECFI */
                        return TERM_CMD_DECFI;
                break;
        case '<':
                if (flags == 0) /* DECANM */
                        return TERM_CMD_DECANM;
                break;
        case '=':
                if (flags == 0) /* DECKPAM */
                        return TERM_CMD_DECKPAM;
                break;
        case '>':
                if (flags == 0) /* DECKPNM */
                        return TERM_CMD_DECKPNM;
                break;
        case '@':
                if (flags == TERM_SEQ_FLAG_PERCENT) {
                        /* Select default character set */
                        return TERM_CMD_XTERM_SDCS;
                }
                break;
        case 'D':
                if (flags == 0) /* IND */
                        return TERM_CMD_IND;
                break;
        case 'E':
                if (flags == 0) /* NEL */
                        return TERM_CMD_NEL;
                break;
        case 'F':
                if (flags == 0) /* Cursor to lower-left corner of screen */
                        return TERM_CMD_XTERM_CLLHP;
                else if (flags == TERM_SEQ_FLAG_SPACE) /* S7C1T */
                        return TERM_CMD_S7C1T;
                break;
        case 'G':
                if (flags == TERM_SEQ_FLAG_SPACE) { /* S8C1T */
                        return TERM_CMD_S8C1T;
                } else if (flags == TERM_SEQ_FLAG_PERCENT) {
                        /* Select UTF-8 character set */
                        return TERM_CMD_XTERM_SUCS;
                }
                break;
        case 'H':
                if (flags == 0) /* HTS */
                        return TERM_CMD_HTS;
                break;
        case 'L':
                if (flags == TERM_SEQ_FLAG_SPACE) {
                        /* Set ANSI conformance level 1 */
                        return TERM_CMD_XTERM_SACL1;
                }
                break;
        case 'M':
                if (flags == 0) { /* RI */
                        return TERM_CMD_RI;
                } else if (flags == TERM_SEQ_FLAG_SPACE) {
                        /* Set ANSI conformance level 2 */
                        return TERM_CMD_XTERM_SACL2;
                }
                break;
        case 'N':
                if (flags == 0) { /* SS2 */
                        return TERM_CMD_SS2;
                } else if (flags == TERM_SEQ_FLAG_SPACE) {
                        /* Set ANSI conformance level 3 */
                        return TERM_CMD_XTERM_SACL3;
                }
                break;
        case 'O':
                if (flags == 0) /* SS3 */
                        return TERM_CMD_SS3;
                break;
        case 'P':
                if (flags == 0) /* DCS: this is already handled by the state-machine */
                        return 0;
                break;
        case 'V':
                if (flags == 0) /* SPA */
                        return TERM_CMD_SPA;
                break;
        case 'W':
                if (flags == 0) /* EPA */
                        return TERM_CMD_EPA;
                break;
        case 'X':
                if (flags == 0) { /* SOS */
                        /* this is already handled by the state-machine */
                        break;
                }
                break;
        case 'Z':
                if (flags == 0) /* DECID */
                        return TERM_CMD_DECID;
                break;
        case '[':
                if (flags == 0) { /* CSI */
                        /* this is already handled by the state-machine */
                        break;
                }
                break;
        case '\\':
                if (flags == 0) /* ST */
                        return TERM_CMD_ST;
                break;
        case ']':
                if (flags == 0) { /* OSC */
                        /* this is already handled by the state-machine */
                        break;
                }
                break;
        case '^':
                if (flags == 0) { /* PM */
                        /* this is already handled by the state-machine */
                        break;
                }
                break;
        case '_':
                if (flags == 0) { /* APC */
                        /* this is already handled by the state-machine */
                        break;
                }
                break;
        case 'c':
                if (flags == 0) /* RIS */
                        return TERM_CMD_RIS;
                break;
        case 'l':
                if (flags == 0) /* Memory lock */
                        return TERM_CMD_XTERM_MLHP;
                break;
        case 'm':
                if (flags == 0) /* Memory unlock */
                        return TERM_CMD_XTERM_MUHP;
                break;
        case 'n':
                if (flags == 0) /* LS2 */
                        return TERM_CMD_LS2;
                break;
        case 'o':
                if (flags == 0) /* LS3 */
                        return TERM_CMD_LS3;
                break;
        case '|':
                if (flags == 0) /* LS3R */
                        return TERM_CMD_LS3R;
                break;
        case '}':
                if (flags == 0) /* LS2R */
                        return TERM_CMD_LS2R;
                break;
        case '~':
                if (flags == 0) /* LS1R */
                        return TERM_CMD_LS1R;
                break;
        }

        return TERM_CMD_NONE;
}

static unsigned int term_parse_host_csi(const term_seq *seq) {
        unsigned int flags;

        assert_return(seq, TERM_CMD_NONE);

        flags = seq->intermediates;

        switch (seq->terminator) {
        case 'A':
                if (flags == 0) /* CUU */
                        return TERM_CMD_CUU;
                break;
        case 'a':
                if (flags == 0) /* HPR */
                        return TERM_CMD_HPR;
                break;
        case 'B':
                if (flags == 0) /* CUD */
                        return TERM_CMD_CUD;
                break;
        case 'b':
                if (flags == 0) /* REP */
                        return TERM_CMD_REP;
                break;
        case 'C':
                if (flags == 0) /* CUF */
                        return TERM_CMD_CUF;
                break;
        case 'c':
                if (flags == 0) /* DA1 */
                        return TERM_CMD_DA1;
                else if (flags == TERM_SEQ_FLAG_GT) /* DA2 */
                        return TERM_CMD_DA2;
                else if (flags == TERM_SEQ_FLAG_EQUAL) /* DA3 */
                        return TERM_CMD_DA3;
                break;
        case 'D':
                if (flags == 0) /* CUB */
                        return TERM_CMD_CUB;
                break;
        case 'd':
                if (flags == 0) /* VPA */
                        return TERM_CMD_VPA;
                break;
        case 'E':
                if (flags == 0) /* CNL */
                        return TERM_CMD_CNL;
                break;
        case 'e':
                if (flags == 0) /* VPR */
                        return TERM_CMD_VPR;
                break;
        case 'F':
                if (flags == 0) /* CPL */
                        return TERM_CMD_CPL;
                break;
        case 'f':
                if (flags == 0) /* HVP */
                        return TERM_CMD_HVP;
                break;
        case 'G':
                if (flags == 0) /* CHA */
                        return TERM_CMD_CHA;
                break;
        case 'g':
                if (flags == 0) /* TBC */
                        return TERM_CMD_TBC;
                else if (flags == TERM_SEQ_FLAG_MULT) /* DECLFKC */
                        return TERM_CMD_DECLFKC;
                break;
        case 'H':
                if (flags == 0) /* CUP */
                        return TERM_CMD_CUP;
                break;
        case 'h':
                if (flags == 0) /* SM ANSI */
                        return TERM_CMD_SM_ANSI;
                else if (flags == TERM_SEQ_FLAG_WHAT) /* SM DEC */
                        return TERM_CMD_SM_DEC;
                break;
        case 'I':
                if (flags == 0) /* CHT */
                        return TERM_CMD_CHT;
                break;
        case 'i':
                if (flags == 0) /* MC ANSI */
                        return TERM_CMD_MC_ANSI;
                else if (flags == TERM_SEQ_FLAG_WHAT) /* MC DEC */
                        return TERM_CMD_MC_DEC;
                break;
        case 'J':
                if (flags == 0) /* ED */
                        return TERM_CMD_ED;
                else if (flags == TERM_SEQ_FLAG_WHAT) /* DECSED */
                        return TERM_CMD_DECSED;
                break;
        case 'K':
                if (flags == 0) /* EL */
                        return TERM_CMD_EL;
                else if (flags == TERM_SEQ_FLAG_WHAT) /* DECSEL */
                        return TERM_CMD_DECSEL;
                break;
        case 'L':
                if (flags == 0) /* IL */
                        return TERM_CMD_IL;
                break;
        case 'l':
                if (flags == 0) /* RM ANSI */
                        return TERM_CMD_RM_ANSI;
                else if (flags == TERM_SEQ_FLAG_WHAT) /* RM DEC */
                        return TERM_CMD_RM_DEC;
                break;
        case 'M':
                if (flags == 0) /* DL */
                        return TERM_CMD_DL;
                break;
        case 'm':
                if (flags == 0) /* SGR */
                        return TERM_CMD_SGR;
                else if (flags == TERM_SEQ_FLAG_GT) /* XTERM SMR */
                        return TERM_CMD_XTERM_SRV;
                break;
        case 'n':
                if (flags == 0) /* DSR ANSI */
                        return TERM_CMD_DSR_ANSI;
                else if (flags == TERM_SEQ_FLAG_GT) /* XTERM RMR */
                        return TERM_CMD_XTERM_RRV;
                else if (flags == TERM_SEQ_FLAG_WHAT) /* DSR DEC */
                        return TERM_CMD_DSR_DEC;
                break;
        case 'P':
                if (flags == 0) /* DCH */
                        return TERM_CMD_DCH;
                else if (flags == TERM_SEQ_FLAG_SPACE) /* PPA */
                        return TERM_CMD_PPA;
                break;
        case 'p':
                if (flags == 0) /* DECSSL */
                        return TERM_CMD_DECSSL;
                else if (flags == TERM_SEQ_FLAG_SPACE) /* DECSSCLS */
                        return TERM_CMD_DECSSCLS;
                else if (flags == TERM_SEQ_FLAG_BANG) /* DECSTR */
                        return TERM_CMD_DECSTR;
                else if (flags == TERM_SEQ_FLAG_DQUOTE) /* DECSCL */
                        return TERM_CMD_DECSCL;
                else if (flags == TERM_SEQ_FLAG_CASH) /* DECRQM-ANSI */
                        return TERM_CMD_DECRQM_ANSI;
                else if (flags == (TERM_SEQ_FLAG_CASH | TERM_SEQ_FLAG_WHAT)) /* DECRQM-DEC */
                        return TERM_CMD_DECRQM_DEC;
                else if (flags == TERM_SEQ_FLAG_PCLOSE) /* DECSDPT */
                        return TERM_CMD_DECSDPT;
                else if (flags == TERM_SEQ_FLAG_MULT) /* DECSPPCS */
                        return TERM_CMD_DECSPPCS;
                else if (flags == TERM_SEQ_FLAG_PLUS) /* DECSR */
                        return TERM_CMD_DECSR;
                else if (flags == TERM_SEQ_FLAG_COMMA) /* DECLTOD */
                        return TERM_CMD_DECLTOD;
                else if (flags == TERM_SEQ_FLAG_GT) /* XTERM SPM */
                        return TERM_CMD_XTERM_SPM;
                break;
        case 'Q':
                if (flags == TERM_SEQ_FLAG_SPACE) /* PPR */
                        return TERM_CMD_PPR;
                break;
        case 'q':
                if (flags == 0) /* DECLL */
                        return TERM_CMD_DECLL;
                else if (flags == TERM_SEQ_FLAG_SPACE) /* DECSCUSR */
                        return TERM_CMD_DECSCUSR;
                else if (flags == TERM_SEQ_FLAG_DQUOTE) /* DECSCA */
                        return TERM_CMD_DECSCA;
                else if (flags == TERM_SEQ_FLAG_CASH) /* DECSDDT */
                        return TERM_CMD_DECSDDT;
                else if (flags == TERM_SEQ_FLAG_MULT) /* DECSRC */
                        return TERM_CMD_DECSR;
                else if (flags == TERM_SEQ_FLAG_PLUS) /* DECELF */
                        return TERM_CMD_DECELF;
                else if (flags == TERM_SEQ_FLAG_COMMA) /* DECTID */
                        return TERM_CMD_DECTID;
                break;
        case 'R':
                if (flags == TERM_SEQ_FLAG_SPACE) /* PPB */
                        return TERM_CMD_PPB;
                break;
        case 'r':
                if (flags == 0) {
                        /* DECSTBM */
                        return TERM_CMD_DECSTBM;
                } else if (flags == TERM_SEQ_FLAG_SPACE) {
                        /* DECSKCV */
                        return TERM_CMD_DECSKCV;
                } else if (flags == TERM_SEQ_FLAG_CASH) {
                        /* DECCARA */
                        return TERM_CMD_DECCARA;
                } else if (flags == TERM_SEQ_FLAG_MULT) {
                        /* DECSCS */
                        return TERM_CMD_DECSCS;
                } else if (flags == TERM_SEQ_FLAG_PLUS) {
                        /* DECSMKR */
                        return TERM_CMD_DECSMKR;
                } else if (flags == TERM_SEQ_FLAG_WHAT) {
                        /*
                         * There's a conflict between DECPCTERM and XTERM-RPM.
                         * XTERM-RPM takes a single argument, DECPCTERM takes 2.
                         * Split both up and forward the call to the closer
                         * match.
                         */
                        if (seq->n_args <= 1) /* XTERM RPM */
                                return TERM_CMD_XTERM_RPM;
                        else if (seq->n_args >= 2) /* DECPCTERM */
                                return TERM_CMD_DECPCTERM;
                }
                break;
        case 'S':
                if (flags == 0) /* SU */
                        return TERM_CMD_SU;
                else if (flags == TERM_SEQ_FLAG_WHAT) /* XTERM SGFX */
                        return TERM_CMD_XTERM_SGFX;
                break;
        case 's':
                if (flags == 0) {
                        /*
                         * There's a conflict between DECSLRM and SC-ANSI which
                         * cannot be resolved without knowing the state of
                         * DECLRMM. We leave that decision up to the caller.
                         */
                        return TERM_CMD_DECSLRM_OR_SC;
                } else if (flags == TERM_SEQ_FLAG_CASH) {
                        /* DECSPRTT */
                        return TERM_CMD_DECSPRTT;
                } else if (flags == TERM_SEQ_FLAG_MULT) {
                        /* DECSFC */
                        return TERM_CMD_DECSFC;
                } else if (flags == TERM_SEQ_FLAG_WHAT) {
                        /* XTERM SPM */
                        return TERM_CMD_XTERM_SPM;
                }
                break;
        case 'T':
                if (flags == 0) {
                        /*
                         * Awesome: There's a conflict between SD and XTERM IHMT
                         * that we have to resolve by checking the parameter
                         * count.. XTERM_IHMT needs exactly 5 arguments, SD
                         * takes 0 or 1. We're conservative here and give both
                         * a wider range to allow unused arguments (compat...).
                         */
                        if (seq->n_args >= 5) {
                                /* XTERM IHMT */
                                return TERM_CMD_XTERM_IHMT;
                        } else if (seq->n_args < 5) {
                                /* SD */
                                return TERM_CMD_SD;
                        }
                } else if (flags == TERM_SEQ_FLAG_GT) {
                        /* XTERM RTM */
                        return TERM_CMD_XTERM_RTM;
                }
                break;
        case 't':
                if (flags == 0) {
                        if (seq->n_args > 0 && seq->args[0] < 24) {
                                /* XTERM WM */
                                return TERM_CMD_XTERM_WM;
                        } else {
                                /* DECSLPP */
                                return TERM_CMD_DECSLPP;
                        }
                } else if (flags == TERM_SEQ_FLAG_SPACE) {
                        /* DECSWBV */
                        return TERM_CMD_DECSWBV;
                } else if (flags == TERM_SEQ_FLAG_DQUOTE) {
                        /* DECSRFR */
                        return TERM_CMD_DECSRFR;
                } else if (flags == TERM_SEQ_FLAG_CASH) {
                        /* DECRARA */
                        return TERM_CMD_DECRARA;
                } else if (flags == TERM_SEQ_FLAG_GT) {
                        /* XTERM STM */
                        return TERM_CMD_XTERM_STM;
                }
                break;
        case 'U':
                if (flags == 0) /* NP */
                        return TERM_CMD_NP;
                break;
        case 'u':
                if (flags == 0) {
                        /* RC */
                        return TERM_CMD_RC;
                } else if (flags == TERM_SEQ_FLAG_SPACE) {
                        /* DECSMBV */
                        return TERM_CMD_DECSMBV;
                } else if (flags == TERM_SEQ_FLAG_DQUOTE) {
                        /* DECSTRL */
                        return TERM_CMD_DECSTRL;
                } else if (flags == TERM_SEQ_FLAG_WHAT) {
                        /* DECRQUPSS */
                        return TERM_CMD_DECRQUPSS;
                } else if (seq->args[0] == 1 && flags == TERM_SEQ_FLAG_CASH) {
                        /* DECRQTSR */
                        return TERM_CMD_DECRQTSR;
                } else if (flags == TERM_SEQ_FLAG_MULT) {
                        /* DECSCP */
                        return TERM_CMD_DECSCP;
                } else if (flags == TERM_SEQ_FLAG_COMMA) {
                        /* DECRQKT */
                        return TERM_CMD_DECRQKT;
                }
                break;
        case 'V':
                if (flags == 0) /* PP */
                        return TERM_CMD_PP;
                break;
        case 'v':
                if (flags == TERM_SEQ_FLAG_SPACE) /* DECSLCK */
                        return TERM_CMD_DECSLCK;
                else if (flags == TERM_SEQ_FLAG_DQUOTE) /* DECRQDE */
                        return TERM_CMD_DECRQDE;
                else if (flags == TERM_SEQ_FLAG_CASH) /* DECCRA */
                        return TERM_CMD_DECCRA;
                else if (flags == TERM_SEQ_FLAG_COMMA) /* DECRPKT */
                        return TERM_CMD_DECRPKT;
                break;
        case 'W':
                if (seq->args[0] == 5 && flags == TERM_SEQ_FLAG_WHAT) {
                        /* DECST8C */
                        return TERM_CMD_DECST8C;
                }
                break;
        case 'w':
                if (flags == TERM_SEQ_FLAG_CASH) /* DECRQPSR */
                        return TERM_CMD_DECRQPSR;
                else if (flags == TERM_SEQ_FLAG_SQUOTE) /* DECEFR */
                        return TERM_CMD_DECEFR;
                else if (flags == TERM_SEQ_FLAG_PLUS) /* DECSPP */
                        return TERM_CMD_DECSPP;
                break;
        case 'X':
                if (flags == 0) /* ECH */
                        return TERM_CMD_ECH;
                break;
        case 'x':
                if (flags == 0) /* DECREQTPARM */
                        return TERM_CMD_DECREQTPARM;
                else if (flags == TERM_SEQ_FLAG_CASH) /* DECFRA */
                        return TERM_CMD_DECFRA;
                else if (flags == TERM_SEQ_FLAG_MULT) /* DECSACE */
                        return TERM_CMD_DECSACE;
                else if (flags == TERM_SEQ_FLAG_PLUS) /* DECRQPKFM */
                        return TERM_CMD_DECRQPKFM;
                break;
        case 'y':
                if (flags == 0) /* DECTST */
                        return TERM_CMD_DECTST;
                else if (flags == TERM_SEQ_FLAG_MULT) /* DECRQCRA */
                        return TERM_CMD_DECRQCRA;
                else if (flags == TERM_SEQ_FLAG_PLUS) /* DECPKFMR */
                        return TERM_CMD_DECPKFMR;
                break;
        case 'Z':
                if (flags == 0) /* CBT */
                        return TERM_CMD_CBT;
                break;
        case 'z':
                if (flags == TERM_SEQ_FLAG_CASH) /* DECERA */
                        return TERM_CMD_DECERA;
                else if (flags == TERM_SEQ_FLAG_SQUOTE) /* DECELR */
                        return TERM_CMD_DECELR;
                else if (flags == TERM_SEQ_FLAG_MULT) /* DECINVM */
                        return TERM_CMD_DECINVM;
                else if (flags == TERM_SEQ_FLAG_PLUS) /* DECPKA */
                        return TERM_CMD_DECPKA;
                break;
        case '@':
                if (flags == 0) /* ICH */
                        return TERM_CMD_ICH;
                break;
        case '`':
                if (flags == 0) /* HPA */
                        return TERM_CMD_HPA;
                break;
        case '{':
                if (flags == TERM_SEQ_FLAG_CASH) /* DECSERA */
                        return TERM_CMD_DECSERA;
                else if (flags == TERM_SEQ_FLAG_SQUOTE) /* DECSLE */
                        return TERM_CMD_DECSLE;
                break;
        case '|':
                if (flags == TERM_SEQ_FLAG_CASH) /* DECSCPP */
                        return TERM_CMD_DECSCPP;
                else if (flags == TERM_SEQ_FLAG_SQUOTE) /* DECRQLP */
                        return TERM_CMD_DECRQLP;
                else if (flags == TERM_SEQ_FLAG_MULT) /* DECSNLS */
                        return TERM_CMD_DECSNLS;
                break;
        case '}':
                if (flags == TERM_SEQ_FLAG_SPACE) /* DECKBD */
                        return TERM_CMD_DECKBD;
                else if (flags == TERM_SEQ_FLAG_CASH) /* DECSASD */
                        return TERM_CMD_DECSASD;
                else if (flags == TERM_SEQ_FLAG_SQUOTE) /* DECIC */
                        return TERM_CMD_DECIC;
                break;
        case '~':
                if (flags == TERM_SEQ_FLAG_SPACE) /* DECTME */
                        return TERM_CMD_DECTME;
                else if (flags == TERM_SEQ_FLAG_CASH) /* DECSSDT */
                        return TERM_CMD_DECSSDT;
                else if (flags == TERM_SEQ_FLAG_SQUOTE) /* DECDC */
                        return TERM_CMD_DECDC;
                break;
        }

        return TERM_CMD_NONE;
}

/*
 * State Machine
 * This parser controls the parser-state and returns any detected sequence to
 * the caller. The parser is based on this state-diagram from Paul Williams:
 *   http://vt100.net/emu/
 * It was written from scratch and extended where needed.
 * This parser is fully compatible up to the vt500 series. We expect UCS-4 as
 * input. It's the callers responsibility to do any UTF-8 parsing.
 */

enum parser_state {
        STATE_NONE,             /* placeholder */
        STATE_GROUND,           /* initial state and ground */
        STATE_ESC,              /* ESC sequence was started */
        STATE_ESC_INT,          /* intermediate escape characters */
        STATE_CSI_ENTRY,        /* starting CSI sequence */
        STATE_CSI_PARAM,        /* CSI parameters */
        STATE_CSI_INT,          /* intermediate CSI characters */
        STATE_CSI_IGNORE,       /* CSI error; ignore this CSI sequence */
        STATE_DCS_ENTRY,        /* starting DCS sequence */
        STATE_DCS_PARAM,        /* DCS parameters */
        STATE_DCS_INT,          /* intermediate DCS characters */
        STATE_DCS_PASS,         /* DCS data passthrough */
        STATE_DCS_IGNORE,       /* DCS error; ignore this DCS sequence */
        STATE_OSC_STRING,       /* parsing OSC sequence */
        STATE_ST_IGNORE,        /* unimplemented seq; ignore until ST */
        STATE_NUM
};

enum parser_action {
        ACTION_NONE,            /* placeholder */
        ACTION_CLEAR,           /* clear parameters */
        ACTION_IGNORE,          /* ignore the character entirely */
        ACTION_PRINT,           /* print the character on the console */
        ACTION_EXECUTE,         /* execute single control character (C0/C1) */
        ACTION_COLLECT,         /* collect intermediate character */
        ACTION_PARAM,           /* collect parameter character */
        ACTION_ESC_DISPATCH,    /* dispatch escape sequence */
        ACTION_CSI_DISPATCH,    /* dispatch csi sequence */
        ACTION_DCS_START,       /* start of DCS data */
        ACTION_DCS_COLLECT,     /* collect DCS data */
        ACTION_DCS_CONSUME,     /* consume DCS terminator */
        ACTION_DCS_DISPATCH,    /* dispatch dcs sequence */
        ACTION_OSC_START,       /* start of OSC data */
        ACTION_OSC_COLLECT,     /* collect OSC data */
        ACTION_OSC_CONSUME,     /* consume OSC terminator */
        ACTION_OSC_DISPATCH,    /* dispatch osc sequence */
        ACTION_NUM
};

int term_parser_new(term_parser **out, bool host) {
        _term_parser_free_ term_parser *parser = NULL;

        assert_return(out, -EINVAL);

        parser = new0(term_parser, 1);
        if (!parser)
                return -ENOMEM;

        parser->is_host = host;
        parser->st_alloc = 64;
        parser->seq.st = new0(char, parser->st_alloc + 1);
        if (!parser->seq.st)
                return -ENOMEM;

        *out = parser;
        parser = NULL;
        return 0;
}

term_parser *term_parser_free(term_parser *parser) {
        if (!parser)
                return NULL;

        free(parser->seq.st);
        free(parser);
        return NULL;
}

static inline void parser_clear(term_parser *parser) {
        unsigned int i;

        parser->seq.command = TERM_CMD_NONE;
        parser->seq.terminator = 0;
        parser->seq.intermediates = 0;
        parser->seq.charset = TERM_CHARSET_NONE;
        parser->seq.n_args = 0;
        for (i = 0; i < TERM_PARSER_ARG_MAX; ++i)
                parser->seq.args[i] = -1;

        parser->seq.n_st = 0;
        parser->seq.st[0] = 0;
}

static int parser_ignore(term_parser *parser, uint32_t raw) {
        parser_clear(parser);
        parser->seq.type = TERM_SEQ_IGNORE;
        parser->seq.command = TERM_CMD_NONE;
        parser->seq.terminator = raw;
        parser->seq.charset = TERM_CHARSET_NONE;

        return parser->seq.type;
}

static int parser_print(term_parser *parser, uint32_t raw) {
        parser_clear(parser);
        parser->seq.type = TERM_SEQ_GRAPHIC;
        parser->seq.command = TERM_CMD_GRAPHIC;
        parser->seq.terminator = raw;
        parser->seq.charset = TERM_CHARSET_NONE;

        return parser->seq.type;
}

static int parser_execute(term_parser *parser, uint32_t raw) {
        parser_clear(parser);
        parser->seq.type = TERM_SEQ_CONTROL;
        parser->seq.command = TERM_CMD_GRAPHIC;
        parser->seq.terminator = raw;
        parser->seq.charset = TERM_CHARSET_NONE;
        if (!parser->is_host)
                parser->seq.command = term_parse_host_control(&parser->seq);

        return parser->seq.type;
}

static void parser_collect(term_parser *parser, uint32_t raw) {
        /*
         * Usually, characters from 0x30 to 0x3f are only allowed as leading
         * markers (or as part of the parameters), characters from 0x20 to 0x2f
         * are only allowed as trailing markers. However, our state-machine
         * already verifies those restrictions so we can handle them the same
         * way here. Note that we safely allow markers to be specified multiple
         * times.
         */

        if (raw >= 0x20 && raw <= 0x3f)
                parser->seq.intermediates |= 1 << (raw - 0x20);
}

static void parser_param(term_parser *parser, uint32_t raw) {
        int new;

        if (raw == ';') {
                if (parser->seq.n_args < TERM_PARSER_ARG_MAX)
                        ++parser->seq.n_args;

                return;
        }

        if (parser->seq.n_args >= TERM_PARSER_ARG_MAX)
                return;

        if (raw >= '0' && raw <= '9') {
                new = parser->seq.args[parser->seq.n_args];
                if (new < 0)
                        new = 0;
                new = new * 10 + raw - '0';

                /* VT510 tells us to clamp all values to [0, 9999], however, it
                 * also allows commands with values up to 2^15-1. We simply use
                 * 2^16 as maximum here to be compatible to all commands, but
                 * avoid overflows in any calculations. */
                if (new > 0xffff)
                        new = 0xffff;

                parser->seq.args[parser->seq.n_args] = new;
        }
}

static int parser_esc(term_parser *parser, uint32_t raw) {
        parser->seq.type = TERM_SEQ_ESCAPE;
        parser->seq.command = TERM_CMD_NONE;
        parser->seq.terminator = raw;
        parser->seq.charset = TERM_CHARSET_NONE;
        if (!parser->is_host)
                parser->seq.command = term_parse_host_escape(&parser->seq, &parser->seq.charset);

        return parser->seq.type;
}

static int parser_csi(term_parser *parser, uint32_t raw) {
        /* parser->seq is cleared during CSI-ENTER state, thus there's no need
         * to clear invalid fields here. */

        if (parser->seq.n_args < TERM_PARSER_ARG_MAX) {
                if (parser->seq.n_args > 0 ||
                    parser->seq.args[parser->seq.n_args] >= 0)
                        ++parser->seq.n_args;
        }

        parser->seq.type = TERM_SEQ_CSI;
        parser->seq.command = TERM_CMD_NONE;
        parser->seq.terminator = raw;
        parser->seq.charset = TERM_CHARSET_NONE;
        if (!parser->is_host)
                parser->seq.command = term_parse_host_csi(&parser->seq);

        return parser->seq.type;
}

/* perform state transition and dispatch related actions */
static int parser_transition(term_parser *parser, uint32_t raw, unsigned int state, unsigned int action) {
        if (state != STATE_NONE)
                parser->state = state;

        switch (action) {
        case ACTION_NONE:
                return TERM_SEQ_NONE;
        case ACTION_CLEAR:
                parser_clear(parser);
                return TERM_SEQ_NONE;
        case ACTION_IGNORE:
                return parser_ignore(parser, raw);
        case ACTION_PRINT:
                return parser_print(parser, raw);
        case ACTION_EXECUTE:
                return parser_execute(parser, raw);
        case ACTION_COLLECT:
                parser_collect(parser, raw);
                return TERM_SEQ_NONE;
        case ACTION_PARAM:
                parser_param(parser, raw);
                return TERM_SEQ_NONE;
        case ACTION_ESC_DISPATCH:
                return parser_esc(parser, raw);
        case ACTION_CSI_DISPATCH:
                return parser_csi(parser, raw);
        case ACTION_DCS_START:
                /* not implemented */
                return TERM_SEQ_NONE;
        case ACTION_DCS_COLLECT:
                /* not implemented */
                return TERM_SEQ_NONE;
        case ACTION_DCS_CONSUME:
                /* not implemented */
                return TERM_SEQ_NONE;
        case ACTION_DCS_DISPATCH:
                /* not implemented */
                return TERM_SEQ_NONE;
        case ACTION_OSC_START:
                /* not implemented */
                return TERM_SEQ_NONE;
        case ACTION_OSC_COLLECT:
                /* not implemented */
                return TERM_SEQ_NONE;
        case ACTION_OSC_CONSUME:
                /* not implemented */
                return TERM_SEQ_NONE;
        case ACTION_OSC_DISPATCH:
                /* not implemented */
                return TERM_SEQ_NONE;
        default:
                assert_not_reached("invalid vte-parser action");
                return TERM_SEQ_NONE;
        }
}

static int parser_feed_to_state(term_parser *parser, uint32_t raw) {
        switch (parser->state) {
        case STATE_NONE:
                /*
                 * During initialization, parser->state is cleared. Treat this
                 * as STATE_GROUND. We will then never get to STATE_NONE again.
                 */
        case STATE_GROUND:
                switch (raw) {
                case 0x00 ... 0x1f:     /* C0 */
                case 0x80 ... 0x9b:     /* C1 \ { ST } */
                case 0x9d ... 0x9f:
                        return parser_transition(parser, raw, STATE_NONE, ACTION_EXECUTE);
                case 0x9c:              /* ST */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_IGNORE);
                }

                return parser_transition(parser, raw, STATE_NONE, ACTION_PRINT);
        case STATE_ESC:
                switch (raw) {
                case 0x00 ... 0x1f:     /* C0 */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_EXECUTE);
                case 0x20 ... 0x2f:     /* [' ' - '\'] */
                        return parser_transition(parser, raw, STATE_ESC_INT, ACTION_COLLECT);
                case 0x30 ... 0x4f:     /* ['0' - '~'] \ { 'P', 'X', '[', ']', '^', '_' } */
                case 0x51 ... 0x57:
                case 0x59 ... 0x5a:
                case 0x5c:
                case 0x60 ... 0x7e:
                        return parser_transition(parser, raw, STATE_GROUND, ACTION_ESC_DISPATCH);
                case 0x50:              /* 'P' */
                        return parser_transition(parser, raw, STATE_DCS_ENTRY, ACTION_CLEAR);
                case 0x5b:              /* '[' */
                        return parser_transition(parser, raw, STATE_CSI_ENTRY, ACTION_CLEAR);
                case 0x5d:              /* ']' */
                        return parser_transition(parser, raw, STATE_OSC_STRING, ACTION_CLEAR);
                case 0x58:              /* 'X' */
                case 0x5e:              /* '^' */
                case 0x5f:              /* '_' */
                        return parser_transition(parser, raw, STATE_ST_IGNORE, ACTION_NONE);
                case 0x7f:              /* DEL */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_IGNORE);
                case 0x9c:              /* ST */
                        return parser_transition(parser, raw, STATE_GROUND, ACTION_IGNORE);
                }

                return parser_transition(parser, raw, STATE_ESC_INT, ACTION_COLLECT);
        case STATE_ESC_INT:
                switch (raw) {
                case 0x00 ... 0x1f:     /* C0 */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_EXECUTE);
                case 0x20 ... 0x2f:     /* [' ' - '\'] */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_COLLECT);
                case 0x30 ... 0x7e:     /* ['0' - '~'] */
                        return parser_transition(parser, raw, STATE_GROUND, ACTION_ESC_DISPATCH);
                case 0x7f:              /* DEL */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_IGNORE);
                case 0x9c:              /* ST */
                        return parser_transition(parser, raw, STATE_GROUND, ACTION_IGNORE);
                }

                return parser_transition(parser, raw, STATE_NONE, ACTION_COLLECT);
        case STATE_CSI_ENTRY:
                switch (raw) {
                case 0x00 ... 0x1f:     /* C0 */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_EXECUTE);
                case 0x20 ... 0x2f:     /* [' ' - '\'] */
                        return parser_transition(parser, raw, STATE_CSI_INT, ACTION_COLLECT);
                case 0x3a:              /* ':' */
                        return parser_transition(parser, raw, STATE_CSI_IGNORE, ACTION_NONE);
                case 0x30 ... 0x39:     /* ['0' - '9'] */
                case 0x3b:              /* ';' */
                        return parser_transition(parser, raw, STATE_CSI_PARAM, ACTION_PARAM);
                case 0x3c ... 0x3f:     /* ['<' - '?'] */
                        return parser_transition(parser, raw, STATE_CSI_PARAM, ACTION_COLLECT);
                case 0x40 ... 0x7e:     /* ['@' - '~'] */
                        return parser_transition(parser, raw, STATE_GROUND, ACTION_CSI_DISPATCH);
                case 0x7f:              /* DEL */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_IGNORE);
                case 0x9c:              /* ST */
                        return parser_transition(parser, raw, STATE_GROUND, ACTION_IGNORE);
                }

                return parser_transition(parser, raw, STATE_CSI_IGNORE, ACTION_NONE);
        case STATE_CSI_PARAM:
                switch (raw) {
                case 0x00 ... 0x1f:     /* C0 */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_EXECUTE);
                case 0x20 ... 0x2f:     /* [' ' - '\'] */
                        return parser_transition(parser, raw, STATE_CSI_INT, ACTION_COLLECT);
                case 0x30 ... 0x39:     /* ['0' - '9'] */
                case 0x3b:              /* ';' */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_PARAM);
                case 0x3a:              /* ':' */
                case 0x3c ... 0x3f:     /* ['<' - '?'] */
                        return parser_transition(parser, raw, STATE_CSI_IGNORE, ACTION_NONE);
                case 0x40 ... 0x7e:     /* ['@' - '~'] */
                        return parser_transition(parser, raw, STATE_GROUND, ACTION_CSI_DISPATCH);
                case 0x7f:              /* DEL */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_IGNORE);
                case 0x9c:              /* ST */
                        return parser_transition(parser, raw, STATE_GROUND, ACTION_IGNORE);
                }

                return parser_transition(parser, raw, STATE_CSI_IGNORE, ACTION_NONE);
        case STATE_CSI_INT:
                switch (raw) {
                case 0x00 ... 0x1f:     /* C0 */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_EXECUTE);
                case 0x20 ... 0x2f:     /* [' ' - '\'] */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_COLLECT);
                case 0x30 ... 0x3f:     /* ['0' - '?'] */
                        return parser_transition(parser, raw, STATE_CSI_IGNORE, ACTION_NONE);
                case 0x40 ... 0x7e:     /* ['@' - '~'] */
                        return parser_transition(parser, raw, STATE_GROUND, ACTION_CSI_DISPATCH);
                case 0x7f:              /* DEL */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_IGNORE);
                case 0x9c:              /* ST */
                        return parser_transition(parser, raw, STATE_GROUND, ACTION_IGNORE);
                }

                return parser_transition(parser, raw, STATE_CSI_IGNORE, ACTION_NONE);
        case STATE_CSI_IGNORE:
                switch (raw) {
                case 0x00 ... 0x1f:     /* C0 */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_EXECUTE);
                case 0x20 ... 0x3f:     /* [' ' - '?'] */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_NONE);
                case 0x40 ... 0x7e:     /* ['@' - '~'] */
                        return parser_transition(parser, raw, STATE_GROUND, ACTION_NONE);
                case 0x7f:              /* DEL */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_IGNORE);
                case 0x9c:              /* ST */
                        return parser_transition(parser, raw, STATE_GROUND, ACTION_IGNORE);
                }

                return parser_transition(parser, raw, STATE_NONE, ACTION_NONE);
        case STATE_DCS_ENTRY:
                switch (raw) {
                case 0x00 ... 0x1f:     /* C0 */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_IGNORE);
                case 0x20 ... 0x2f:     /* [' ' - '\'] */
                        return parser_transition(parser, raw, STATE_DCS_INT, ACTION_COLLECT);
                case 0x3a:              /* ':' */
                        return parser_transition(parser, raw, STATE_DCS_IGNORE, ACTION_NONE);
                case 0x30 ... 0x39:     /* ['0' - '9'] */
                case 0x3b:              /* ';' */
                        return parser_transition(parser, raw, STATE_DCS_PARAM, ACTION_PARAM);
                case 0x3c ... 0x3f:     /* ['<' - '?'] */
                        return parser_transition(parser, raw, STATE_DCS_PARAM, ACTION_COLLECT);
                case 0x40 ... 0x7e:     /* ['@' - '~'] */
                        return parser_transition(parser, raw, STATE_DCS_PASS, ACTION_DCS_CONSUME);
                case 0x7f:              /* DEL */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_IGNORE);
                case 0x9c:              /* ST */
                        return parser_transition(parser, raw, STATE_GROUND, ACTION_IGNORE);
                }

                return parser_transition(parser, raw, STATE_DCS_PASS, ACTION_DCS_CONSUME);
        case STATE_DCS_PARAM:
                switch (raw) {
                case 0x00 ... 0x1f:     /* C0 */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_IGNORE);
                case 0x20 ... 0x2f:     /* [' ' - '\'] */
                        return parser_transition(parser, raw, STATE_DCS_INT, ACTION_COLLECT);
                case 0x30 ... 0x39:     /* ['0' - '9'] */
                case 0x3b:              /* ';' */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_PARAM);
                case 0x3a:              /* ':' */
                case 0x3c ... 0x3f:     /* ['<' - '?'] */
                        return parser_transition(parser, raw, STATE_DCS_IGNORE, ACTION_NONE);
                case 0x40 ... 0x7e:     /* ['@' - '~'] */
                        return parser_transition(parser, raw, STATE_DCS_PASS, ACTION_DCS_CONSUME);
                case 0x7f:              /* DEL */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_IGNORE);
                case 0x9c:              /* ST */
                        return parser_transition(parser, raw, STATE_GROUND, ACTION_IGNORE);
                }

                return parser_transition(parser, raw, STATE_DCS_PASS, ACTION_DCS_CONSUME);
        case STATE_DCS_INT:
                switch (raw) {
                case 0x00 ... 0x1f:     /* C0 */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_IGNORE);
                case 0x20 ... 0x2f:     /* [' ' - '\'] */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_COLLECT);
                case 0x30 ... 0x3f:     /* ['0' - '?'] */
                        return parser_transition(parser, raw, STATE_DCS_IGNORE, ACTION_NONE);
                case 0x40 ... 0x7e:     /* ['@' - '~'] */
                        return parser_transition(parser, raw, STATE_DCS_PASS, ACTION_DCS_CONSUME);
                case 0x7f:              /* DEL */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_IGNORE);
                case 0x9c:              /* ST */
                        return parser_transition(parser, raw, STATE_GROUND, ACTION_IGNORE);
                }

                return parser_transition(parser, raw, STATE_DCS_PASS, ACTION_DCS_CONSUME);
        case STATE_DCS_PASS:
                switch (raw) {
                case 0x00 ... 0x7e:     /* ASCII \ { DEL } */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_DCS_COLLECT);
                case 0x7f:              /* DEL */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_IGNORE);
                case 0x9c:              /* ST */
                        return parser_transition(parser, raw, STATE_GROUND, ACTION_DCS_DISPATCH);
                }

                return parser_transition(parser, raw, STATE_NONE, ACTION_DCS_COLLECT);
        case STATE_DCS_IGNORE:
                switch (raw) {
                case 0x00 ... 0x7f:     /* ASCII */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_IGNORE);
                case 0x9c:              /* ST */
                        return parser_transition(parser, raw, STATE_GROUND, ACTION_NONE);
                }

                return parser_transition(parser, raw, STATE_NONE, ACTION_NONE);
        case STATE_OSC_STRING:
                switch (raw) {
                case 0x00 ... 0x06:     /* C0 \ { BEL } */
                case 0x08 ... 0x1f:
                        return parser_transition(parser, raw, STATE_NONE, ACTION_IGNORE);
                case 0x20 ... 0x7f:     /* [' ' - DEL] */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_OSC_COLLECT);
                case 0x07:              /* BEL */
                case 0x9c:              /* ST */
                        return parser_transition(parser, raw, STATE_GROUND, ACTION_OSC_DISPATCH);
                }

                return parser_transition(parser, raw, STATE_NONE, ACTION_OSC_COLLECT);
        case STATE_ST_IGNORE:
                switch (raw) {
                case 0x00 ... 0x7f:     /* ASCII */
                        return parser_transition(parser, raw, STATE_NONE, ACTION_IGNORE);
                case 0x9c:              /* ST */
                        return parser_transition(parser, raw, STATE_GROUND, ACTION_IGNORE);
                }

                return parser_transition(parser, raw, STATE_NONE, ACTION_NONE);
        }

        assert_not_reached("bad vte-parser state");
        return -EINVAL;
}

int term_parser_feed(term_parser *parser, const term_seq **seq_out, uint32_t raw) {
        int r;

        assert_return(parser, -EINVAL);
        assert_return(seq_out, -EINVAL);

        /*
         * Notes:
         *  * DEC treats GR codes as GL. We don't do that as we require UTF-8
         *    as charset and, thus, it doesn't make sense to treat GR special.
         *  * During control sequences, unexpected C1 codes cancel the sequence
         *    and immediately start a new one. C0 codes, however, may or may not
         *    be ignored/executed depending on the sequence.
         */

        switch (raw) {
        case 0x18:              /* CAN */
                r = parser_transition(parser, raw, STATE_GROUND, ACTION_IGNORE);
                break;
        case 0x1a:              /* SUB */
                r = parser_transition(parser, raw, STATE_GROUND, ACTION_EXECUTE);
                break;
        case 0x80 ... 0x8f:     /* C1 \ {DCS, SOS, CSI, ST, OSC, PM, APC} */
        case 0x91 ... 0x97:
        case 0x99 ... 0x9a:
                r = parser_transition(parser, raw, STATE_GROUND, ACTION_EXECUTE);
                break;
        case 0x1b:              /* ESC */
                r = parser_transition(parser, raw, STATE_ESC, ACTION_CLEAR);
                break;
        case 0x98:              /* SOS */
        case 0x9e:              /* PM */
        case 0x9f:              /* APC */
                r = parser_transition(parser, raw, STATE_ST_IGNORE, ACTION_NONE);
                break;
        case 0x90:              /* DCS */
                r = parser_transition(parser, raw, STATE_DCS_ENTRY, ACTION_CLEAR);
                break;
        case 0x9d:              /* OSC */
                r = parser_transition(parser, raw, STATE_OSC_STRING, ACTION_CLEAR);
                break;
        case 0x9b:              /* CSI */
                r = parser_transition(parser, raw, STATE_CSI_ENTRY, ACTION_CLEAR);
                break;
        default:
                r = parser_feed_to_state(parser, raw);
                break;
        }

        if (r <= 0)
                *seq_out = NULL;
        else
                *seq_out = &parser->seq;

        return r;
}
