/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-manager.h"

int manager_varlink_init(Manager *m);
void manager_varlink_done(Manager *m);
