/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "log.h"
#include "output-mode.h"
#include "string-table.h"

void getenv_output_mode(OutputMode *ret) {
        OutputMode mode;
        const char *e;

        assert(ret);

        e = getenv("SYSTEMD_JOURNAL_OUTPUT_MODE");
        if (!e)
                return;

        mode = output_mode_from_string(e);
        if (mode < 0) {
                log_debug_errno(mode,
                                "Unknown output format '%s' specified in '$SYSTEMD_JOURNAL_OUTPUT_MODE', ignoring.",
                                e);
                return;
        }

        *ret = mode;
}

JsonFormatFlags output_mode_to_json_format_flags(OutputMode m) {

        switch (m) {

        case OUTPUT_JSON_SSE:
                return JSON_FORMAT_SSE;

        case OUTPUT_JSON_SEQ:
                return JSON_FORMAT_SEQ;

        case OUTPUT_JSON_PRETTY:
                return JSON_FORMAT_PRETTY;

        default:
                return JSON_FORMAT_NEWLINE;
        }
}

static const char *const output_mode_table[_OUTPUT_MODE_MAX] = {
        [OUTPUT_SHORT] = "short",
        [OUTPUT_SHORT_FULL] = "short-full",
        [OUTPUT_SHORT_ISO] = "short-iso",
        [OUTPUT_SHORT_ISO_PRECISE] = "short-iso-precise",
        [OUTPUT_SHORT_PRECISE] = "short-precise",
        [OUTPUT_SHORT_MONOTONIC] = "short-monotonic",
        [OUTPUT_SHORT_DELTA] = "short-delta",
        [OUTPUT_SHORT_UNIX] = "short-unix",
        [OUTPUT_VERBOSE] = "verbose",
        [OUTPUT_EXPORT] = "export",
        [OUTPUT_JSON] = "json",
        [OUTPUT_JSON_PRETTY] = "json-pretty",
        [OUTPUT_JSON_SSE] = "json-sse",
        [OUTPUT_JSON_SEQ] = "json-seq",
        [OUTPUT_CAT] = "cat",
        [OUTPUT_WITH_UNIT] = "with-unit",
};

DEFINE_STRING_TABLE_LOOKUP(output_mode, OutputMode);
