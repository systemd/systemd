/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stdbool.h>

extern bool arg_daemonize;

typedef struct Manager Manager;

int manager_load(Manager *manager, int argc, char *argv[]);
void manager_set_default_children_max(Manager *manager);
