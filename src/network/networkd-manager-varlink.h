/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-manager.h"

int manager_connect_varlink(Manager *m);
void manager_varlink_done(Manager *m);
