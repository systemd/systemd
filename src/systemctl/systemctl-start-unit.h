/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "systemctl.h"

int verb_start(int argc, char *argv[], void *userdata);

struct action_metadata {
        const char *target;
        const char *verb;
        const char *mode;
};

extern const struct action_metadata action_table[_ACTION_MAX];

enum action verb_to_action(const char *verb);
