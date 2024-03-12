/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Button Button;

#include "logind.h"

typedef enum {
        Button_Modifier_None  = 0,
        Button_Modifier_Shift = 1 << 0,
        Button_Modifier_Ctrl  = 1 << 1,
        Button_Modifier_Alt   = 1 << 2,
        Button_Modifier_Meta  = 1 << 3,

} ButtonModifierMask;

struct Button {
        Manager *manager;

        sd_event_source *io_event_source;
        sd_event_source *check_event_source;

        char *name;
        char *seat;
        int fd;

        ButtonModifierMask mods_depressed;

        bool lid_closed;
        bool docked;
};

Button* button_new(Manager *m, const char *name);
Button *button_free(Button *b);
int button_open(Button *b);
int button_set_seat(Button *b, const char *sn);
int button_check_switches(Button *b);
