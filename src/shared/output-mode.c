/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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
        [OUTPUT_CAT] = "cat"
};

DEFINE_STRING_TABLE_LOOKUP(output_mode, OutputMode);
