/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "manager.h"

int manager_varlink_init(Manager *m);
void manager_varlink_done(Manager *m);
