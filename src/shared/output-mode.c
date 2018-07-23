/* SPDX-License-Identifier: LGPL-2.1+ */

#include "output-mode.h"
#include "string-table.h"

static const char *const output_mode_table[_OUTPUT_MODE_MAX] = {
        [OUTPUT_SHORT] = "short",
        [OUTPUT_SHORT_FULL] = "short-full",
        [OUTPUT_SHORT_ISO] = "short-iso",
        [OUTPUT_SHORT_ISO_PRECISE] = "short-iso-precise",
        [OUTPUT_SHORT_PRECISE] = "short-precise",
        [OUTPUT_SHORT_MONOTONIC] = "short-monotonic",
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
