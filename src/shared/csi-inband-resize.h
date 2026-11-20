/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* Implements parsing and formatting of the sequences of CSI 2048/48 ("In-Band Window Resize
 * Notifications"), as per https://gist.github.com/rockorager/e695fb2924d36b2bcf1fff4a3704bd83:
 *
 *     CSI ? 2048 h                             → enable reports (DECSET), triggers an immediate report
 *     CSI ? 2048 l                             → disable reports (DECRST)
 *     CSI ? 2048 $ p                           → query mode (DECRQM)
 *     CSI ? 2048 ; Ps $ y                      → mode report (DECRPM), Ps=1 if set, Ps=2 if reset,
 *                                                Ps=4 if permanently reset
 *     CSI 48 ; lines ; columns ; ypix ; xpix t → size report
 *
 * All functions operating on received sequences expect the payload of a CSI sequence as captured by the
 * AnsiSeqParser, i.e. the parameter and intermediate bytes plus the final byte, without the CSI itself. */

#define INBAND_RESIZE_MODE 2048U

#define ANSI_INBAND_RESIZE_ENABLE  "\x1B[?2048h"
#define ANSI_INBAND_RESIZE_DISABLE "\x1B[?2048l"

typedef enum InbandResizeRequest {
        INBAND_RESIZE_ENABLE,   /* DECSET */
        INBAND_RESIZE_DISABLE,  /* DECRST */
        INBAND_RESIZE_QUERY,    /* DECRQM */
        _INBAND_RESIZE_REQUEST_MAX,
        _INBAND_RESIZE_REQUEST_INVALID = -EINVAL,
} InbandResizeRequest;

/* The Ps values of DECRPM */
typedef enum InbandResizeModeState {
        INBAND_RESIZE_MODE_SET               = 1,
        INBAND_RESIZE_MODE_RESET             = 2,
        INBAND_RESIZE_MODE_PERMANENTLY_RESET = 4,
} InbandResizeModeState;

typedef struct InbandResizeReport {
        unsigned lines;          /* 0…65535; 0 if absent or unparsable */
        unsigned columns;        /* ditto */
        unsigned height_pixels;  /* ditto, also 0 if the terminal doesn't know */
        unsigned width_pixels;   /* ditto */
} InbandResizeReport;

/* Checks whether the specified CSI payload is a DECSET, DECRST or DECRQM sequence covering CSI 2048/48.
 * Returns 0 if not, > 0 if it is, in which case *ret is filled in. Since DECSET/DECRST may cover multiple
 * modes at once, *ret_remaining is set to the CSI payload with mode 2048 removed from the parameter list,
 * or NULL if no other modes are covered (and hence the whole sequence can be dropped). */
int inband_resize_parse_request(const char *csi, InbandResizeRequest *ret, char **ret_remaining);

/* Checks whether the specified CSI payload is a size report. Returns 0 if not, > 0 if it is, in which case
 * *ret is filled in. */
int inband_resize_parse_report(const char *csi, InbandResizeReport *ret);

/* Generate full sequences, including the CSI */
int inband_resize_format_report(const InbandResizeReport *report, char **ret);
int inband_resize_format_mode_report(InbandResizeModeState state, char **ret);
