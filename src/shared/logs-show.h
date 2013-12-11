/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>

#include <systemd/sd-journal.h>

#include "util.h"
#include "output-mode.h"

int output_journal(
                FILE *f,
                sd_journal *j,
                OutputMode mode,
                unsigned n_columns,
                OutputFlags flags,
                bool *ellipsized);

int add_match_this_boot(sd_journal *j, const char *machine);

int add_matches_for_unit(
                sd_journal *j,
                const char *unit);

int add_matches_for_user_unit(
                sd_journal *j,
                const char *unit,
                uid_t uid);

int show_journal_by_unit(
                FILE *f,
                const char *unit,
                OutputMode mode,
                unsigned n_columns,
                usec_t not_before,
                unsigned how_many,
                uid_t uid,
                OutputFlags flags,
                bool system,
                bool *ellipsized);

void json_escape(
                FILE *f,
                const char* p,
                size_t l,
                OutputFlags flags);

const char* output_mode_to_string(OutputMode m) _const_;
OutputMode output_mode_from_string(const char *s) _pure_;
