/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "logind-forward.h"

int manager_metrics_init(Manager *m, int fd);
void manager_metrics_done(Manager *m);
