/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Manager Manager;

int manager_connect_varlink(Manager *m);
void manager_varlink_done(Manager *m);
