/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* A minimal, generic state engine that tracks ANSI escape sequence boundaries in a byte stream. It does not
 * interpret sequences, it only determines where they begin and end, so that callers can find "safe"
 * positions in a stream at which generated sequences may be inserted without corrupting a sequence already
 * in progress. Optionally, the payload of "string" sequences (OSC and friends) is captured, so that callers
 * may act on specific sequences of that kind. */

typedef enum AnsiSeqState {
        ANSI_SEQ_STATE_GROUND,     /* regular characters */
        ANSI_SEQ_STATE_ESC,        /* ESC seen, or within an escape sequence that is neither CSI nor a string sequence */
        ANSI_SEQ_STATE_CSI,        /* within a CSI sequence */
        ANSI_SEQ_STATE_STRING,     /* within a string sequence (OSC, DCS, SOS, PM, APC) */
        ANSI_SEQ_STATE_STRING_ESC, /* within a string sequence, ESC seen (presumably the beginning of ST) */
        ANSI_SEQ_STATE_NF,        /* within an NF sequence */
        _ANSI_SEQ_STATE_MAX,
        _ANSI_SEQ_STATE_INVALID = -EINVAL,
} AnsiSeqState;

typedef enum AnsiSeqEvent {
        ANSI_SEQ_EVENT_TEXT,       /* a regular character, not part of any sequence */
        ANSI_SEQ_EVENT_SEQUENCE,   /* a character belonging to a sequence that is not complete yet */
        ANSI_SEQ_EVENT_END,        /* the character completes a sequence, its payload may be queried */
        ANSI_SEQ_EVENT_ABORT,      /* the character aborted a sequence and was not consumed: feed it again! */
        _ANSI_SEQ_EVENT_MAX,
        _ANSI_SEQ_EVENT_INVALID = -EINVAL,
} AnsiSeqEvent;

/* Maximum length of a sequence payload we are willing to process. A sequence that grows beyond this is
 * considered invalid and aborted. */
#define ANSI_SEQ_STRING_MAX 192U

typedef struct AnsiSeqParser {
        AnsiSeqState state;
        char introducer;    /* for string sequences: the character that introduced it, e.g. ']' for OSC */
        char *string;       /* the accumulated payload of the most recent string sequence */
        size_t string_len;
        bool bad;           /* the current string sequence grew beyond ANSI_SEQ_STRING_MAX or is otherwise invalid */
        bool capture;       /* if true we'll capture the sequence */
} AnsiSeqParser;

void ansi_seq_parser_done(AnsiSeqParser *p);

/* Feeds a single character, returns an AnsiSeqEvent, or a negative errno on capture allocation failure */
int ansi_seq_parser_feed(AnsiSeqParser *p, char c);

/* Just like this, but eat up errors, and immediately submit character again */
int ansi_seq_parser_feed_harder(AnsiSeqParser *p, char c);

/* After ANSI_SEQ_EVENT_END: the captured payload as NUL terminated string, or NULL if capturing is
 * off or the payload overflowed */
const char* ansi_seq_parser_string(const AnsiSeqParser *p);
