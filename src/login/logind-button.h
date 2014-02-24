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

typedef struct Button Button;

#include "list.h"
#include "util.h"
#include "logind.h"

struct Button {
        Manager *manager;

        sd_event_source *io_event_source;
        sd_event_source *check_event_source;

        char *name;
        char *seat;
        int fd;

        bool lid_closed;
        bool docked;
};

Button* button_new(Manager *m, const char *name);
void button_free(Button*b);
int button_open(Button *b);
int button_set_seat(Button *b, const char *sn);
int button_check_switches(Button *b);
