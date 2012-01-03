/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foologsshowhfoo
#define foologsshowhfoo

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdbool.h>

#include "sd-journal.h"
#include "util.h"

typedef enum output_mode {
        OUTPUT_SHORT,
        OUTPUT_VERBOSE,
        OUTPUT_EXPORT,
        OUTPUT_JSON,
        _OUTPUT_MODE_MAX
} output_mode;

int output_journal(sd_journal *j, output_mode mode, unsigned line, bool show_all);

int show_journal_by_service(
                const char *service,
                output_mode mode,
                const char *prefix,
                unsigned n_columns,
                usec_t not_before,
                unsigned how_many,
                bool show_all);

#endif
