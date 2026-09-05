/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "ansi-seq.h"
#include "string-util.h"

void ansi_seq_parser_done(AnsiSeqParser *p) {
        if (!p)
                return;

        p->string = mfree(p->string);
        p->string_len = 0;
}

static void ansi_seq_parser_begin_string(AnsiSeqParser *p, char introducer) {
        assert(p);

        p->string_len = 0;
        if (p->string)
                p->string[0] = 0;
        p->bad = false;
        p->introducer = introducer;
}

static int ansi_seq_parser_push_string(AnsiSeqParser *p, char c) {
        assert(p);

        if (p->bad)
                return 0;

        /* Safety check: don't capture unbounded string sequences */
        if (p->string_len >= ANSI_SEQ_STRING_MAX)
                return 0; /* too long */

        if (p->capture) {
                if (!GREEDY_REALLOC(p->string, p->string_len + 2))
                        return -ENOMEM;

                p->string[p->string_len+0] = c;
                p->string[p->string_len+1] = 0;
        }

        p->string_len++;

        return 1; /* added */
}

static int ansi_seq_parser_bad(AnsiSeqParser *p) {
        assert(p);

        /* A bad sequence has been received, reset state to ground, and remember this */

        p->state = ANSI_SEQ_STATE_GROUND;
        p->bad = true;
        return ANSI_SEQ_EVENT_ABORT;
}

int ansi_seq_parser_feed(AnsiSeqParser *p, char c) {
        uint8_t u = (uint8_t) c;
        int r;

        assert(p);

        switch (p->state) {

        case ANSI_SEQ_STATE_GROUND:
                if (c == 0x1B) { /* ESC */
                        p->state = ANSI_SEQ_STATE_ESC;
                        ansi_seq_parser_begin_string(p, /* introducer= */ 0);
                        return ANSI_SEQ_EVENT_SEQUENCE;
                }

                return ANSI_SEQ_EVENT_TEXT;

        case ANSI_SEQ_STATE_ESC:
                switch (c) {

                case '[': /* CSI sequence */
                        p->state = ANSI_SEQ_STATE_CSI;
                        ansi_seq_parser_begin_string(p, c);
                        return ANSI_SEQ_EVENT_SEQUENCE;

                case ']': /* OSC */
                case 'P': /* DCS */
                case 'X': /* SOS */
                case '^': /* PM */
                case '_': /* APC */
                        p->state = ANSI_SEQ_STATE_STRING;
                        ansi_seq_parser_begin_string(p, c);
                        return ANSI_SEQ_EVENT_SEQUENCE;

                case 0x40 ... 0x4f: /* Fe sequence, i.e. the 7-bit form of the C1 controls (e.g. ESC M = RI),
                                     * except for those introducing CSI/string sequences, handled above */
                case 0x51 ... 0x57:
                case 0x59 ... 0x5a:
                case 0x5c:
                case 0x60 ... 0x7e: /* Fs sequence */
                case 0x30 ... 0x3f: /* Fp sequence */
                        p->state = ANSI_SEQ_STATE_GROUND;
                        p->introducer = c;
                        return ANSI_SEQ_EVENT_END;

                case 0x20 ... 0x2f: /* nF sequence */
                        p->state = ANSI_SEQ_STATE_NF;
                        ansi_seq_parser_begin_string(p, c);
                        return ANSI_SEQ_EVENT_SEQUENCE;

                default:
                        /* Anything else is not a valid escape sequence, give up on it */
                        return ansi_seq_parser_bad(p);
                }

        case ANSI_SEQ_STATE_CSI:
                if (u >= 0x40 && u <= 0x7E) { /* final byte, the sequence is complete */
                        r = ansi_seq_parser_push_string(p, c);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return ansi_seq_parser_bad(p);

                        p->state = ANSI_SEQ_STATE_GROUND;
                        return ANSI_SEQ_EVENT_END;
                }

                if (u >= 0x20 && u <= 0x3F) {
                        /* parameter or intermediate byte, the sequence continues */
                        r = ansi_seq_parser_push_string(p, c);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                return ANSI_SEQ_EVENT_SEQUENCE;

                        /* fall through on too long */
                }

                /* Anything else is not a valid escape sequence, give up on it */
                return ansi_seq_parser_bad(p);

        case ANSI_SEQ_STATE_STRING:
                if (c == 0x07) { /* BEL, the single character ST */
                        p->state = ANSI_SEQ_STATE_GROUND;
                        return ANSI_SEQ_EVENT_END;
                }

                if (c == 0x1B) { /* Presumably the beginning of the two character ST. Note that we do not
                                  * support the C1 encoding of ST (0x9C), since that's a valid UTF-8
                                  * codepoint and would hence be ambiguous. */
                        p->state = ANSI_SEQ_STATE_STRING_ESC;
                        return ANSI_SEQ_EVENT_SEQUENCE;
                }

                if (u >= 0x20U) { /* regular payload */
                        r = ansi_seq_parser_push_string(p, c);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                return ANSI_SEQ_EVENT_SEQUENCE;

                        /* fall through on too long */
                }

                /* Any other control character: give up on this sequence */
                return ansi_seq_parser_bad(p);

        case ANSI_SEQ_STATE_STRING_ESC:
                if (c == '\\') { /* ST is complete, and so is the string sequence */
                        p->state = ANSI_SEQ_STATE_GROUND;
                        return ANSI_SEQ_EVENT_END;
                }

                return ansi_seq_parser_bad(p);

        case ANSI_SEQ_STATE_NF:
                if (u >= 0x30 && u <= 0x7E) { /* final byte, the sequence is complete */
                        r = ansi_seq_parser_push_string(p, c);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return ansi_seq_parser_bad(p);

                        p->state = ANSI_SEQ_STATE_GROUND;
                        return ANSI_SEQ_EVENT_END;
                }

                if (u >= 0x20 && u <= 0x2F) {
                        /* parameter or intermediate byte, the sequence continues */
                        r = ansi_seq_parser_push_string(p, c);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                return ANSI_SEQ_EVENT_SEQUENCE;

                        /* fall through on too long */
                }

                /* Anything else is not a valid escape sequence, give up on it */
                return ansi_seq_parser_bad(p);

        default:
                assert_not_reached();
        }
}

int ansi_seq_parser_feed_harder(AnsiSeqParser *p, char c) {
        int r;

        assert(p);

        /* Just like ansi_seq_parser_feed(), but automatically eat up abort events, and resubmit the bad character. */

        do {
                r = ansi_seq_parser_feed(p, c);
        } while (r == ANSI_SEQ_EVENT_ABORT);

        return r;
}

const char* ansi_seq_parser_string(const AnsiSeqParser *p) {
        assert(p);

        if (!p->capture || p->bad || p->introducer == 0)
                return NULL;

        return strempty(p->string);
}
