/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2010-2013 Lennart Poettering

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

#include "sd-event.h"

typedef struct PTYForward PTYForward;

int pty_forward_new(sd_event *event, int master, bool ignore_vhangup, bool read_only, PTYForward **f);
PTYForward *pty_forward_free(PTYForward *f);

int pty_forward_get_last_char(PTYForward *f, char *ch);

int pty_forward_set_ignore_vhangup(PTYForward *f, bool ignore_vhangup);
int pty_forward_get_ignore_vhangup(PTYForward *f);

DEFINE_TRIVIAL_CLEANUP_FUNC(PTYForward*, pty_forward_free);
