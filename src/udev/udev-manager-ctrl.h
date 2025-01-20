/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

typedef struct Manager Manager;

int manager_init_ctrl(Manager *manager, int fd);
int manager_start_ctrl(Manager *manager);
