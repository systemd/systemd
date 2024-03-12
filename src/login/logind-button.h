/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Button Button;

#include "logind.h"

typedef enum ButtonModifierMask {
        BUTTON_MODIFIER_NONE        = 0,
        BUTTON_MODIFIER_LEFT_SHIFT  = 1 << 0,
        BUTTON_MODIFIER_RIGHT_SHIFT = 1 << 1,
        BUTTON_MODIFIER_LEFT_CTRL   = 1 << 2,
        BUTTON_MODIFIER_RIGHT_CTRL  = 1 << 3,
        BUTTON_MODIFIER_LEFT_ALT    = 1 << 4,
        BUTTON_MODIFIER_RIGHT_ALT   = 1 << 5,
} ButtonModifierMask;

#define BUTTON_MODIFIER_HAS_SHIFT(modifier) (((modifier) & (BUTTON_MODIFIER_LEFT_SHIFT|BUTTON_MODIFIER_RIGHT_SHIFT)) != 0)
#define BUTTON_MODIFIER_HAS_CTRL(modifier) (((modifier) & (BUTTON_MODIFIER_LEFT_CTRL|BUTTON_MODIFIER_RIGHT_CTRL)) != 0)
#define BUTTON_MODIFIER_HAS_ALT(modifier) (((modifier) & (BUTTON_MODIFIER_LEFT_ALT|BUTTON_MODIFIER_RIGHT_ALT)) != 0)

struct Button {
        Manager *manager;

        sd_event_source *io_event_source;
        sd_event_source *check_event_source;

        char *name;
        char *seat;
        int fd;

        ButtonModifierMask button_modifier_mask;

        bool lid_closed;
        bool docked;
};

Button* button_new(Manager *m, const char *name);
Button *button_free(Button *b);
int button_open(Button *b);
int button_set_seat(Button *b, const char *sn);
int button_check_switches(Button *b);
