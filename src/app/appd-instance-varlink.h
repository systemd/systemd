/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "appd-forward.h"

int manager_instance_varlink_init(Manager *m);
void manager_instance_varlink_done(Manager *m);
