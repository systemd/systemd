/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

int manager_connect_varlink(Manager *m, int fd);
void manager_varlink_done(Manager *m);
