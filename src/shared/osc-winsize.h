/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* Implements parsing and formatting of OSC 2811 terminal size change notification sequences, as per UAPI
 * spec 17 ("OSC 2811: Terminal Size Change Notification"). */

typedef enum OscWinsizeType {
        OSC_WINSIZE_SUBSCRIBE,   /* the '?' marker was present, along with fields */
        OSC_WINSIZE_CANCEL,      /* the '?' marker was present, without any fields */
        OSC_WINSIZE_REPORT,      /* no '?' marker, i.e. a report of the current dimensions */
        _OSC_WINSIZE_TYPE_MAX,
        _OSC_WINSIZE_TYPE_INVALID = -EINVAL,
} OscWinsizeType;

typedef struct OscWinsize {
        OscWinsizeType type;
        unsigned columns;  /* 0…65535; 0 if absent or unparsable */
        unsigned lines;    /* ditto */
} OscWinsize;

/* Parses the payload of an OSC sequence (i.e. the string between OSC and ST). Returns 0 if this is not an
 * OSC 2811 sequence, and > 0 if it is, in which case *ret is filled in. */
int osc_winsize_parse(const char *seq, OscWinsize *ret);

/* Generates a full sequence of the specified type, including OSC and ST. The dimensions are ignored for
 * OSC_WINSIZE_CANCEL. */
int osc_winsize_format(OscWinsizeType type, unsigned columns, unsigned lines, char **ret);
