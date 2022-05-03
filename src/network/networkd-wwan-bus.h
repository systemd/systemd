/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Manager Manager;

int manager_enumerate_bearers(Manager *manager);
int manager_match_bearers_signal(Manager *manager);
