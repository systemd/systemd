/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foologindbuttonhfoo
#define foologindbuttonhfoo

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

typedef enum HandleButton {
        HANDLE_IGNORE,
        HANDLE_POWEROFF,
        HANDLE_REBOOT,
        HANDLE_HALT,
        HANDLE_KEXEC,
        HANDLE_SUSPEND,
        HANDLE_HIBERNATE,
        _HANDLE_BUTTON_MAX,
        _HANDLE_BUTTON_INVALID = -1
} HandleButton;

#include "list.h"
#include "util.h"
#include "logind.h"

struct Button {
        Manager *manager;

        char *name;
        char *seat;
        int fd;

        bool lid_close_queued;
};

Button* button_new(Manager *m, const char *name);
void button_free(Button*b);
int button_open(Button *b);
int button_process(Button *b);
int button_recheck(Button *b);
int button_set_seat(Button *b, const char *sn);

const char* handle_button_to_string(HandleButton h);
HandleButton handle_button_from_string(const char *s);

int config_parse_handle_button(const char *filename, unsigned line, const char *section, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);

#endif
