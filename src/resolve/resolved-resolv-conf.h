/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "resolved-manager.h"

int manager_check_resolv_conf(const Manager *m);
int manager_read_resolv_conf(Manager *m);
int manager_write_resolv_conf(Manager *m);
