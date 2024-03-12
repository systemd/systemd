/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Button Button;

#include "logind.h"

typedef enum
{
        MOD_NONE = 0,
        MOD_SHIFT = 1,
        MOD_CTRL = 1 << 1,
        MOD_ALT = 1 << 2,
        MOD_META = 1 << 3,

} ButtonMods;

struct Button {
        Manager *manager;

        sd_event_source *io_event_source;
        sd_event_source *check_event_source;

        char *name;
        char *seat;
        int fd;

        int mods_depressed;

        bool lid_closed;
        bool docked;
};

Button* button_new(Manager *m, const char *name);
Button *button_free(Button *b);
int button_open(Button *b);
int button_set_seat(Button *b, const char *sn);
int button_check_switches(Button *b);
