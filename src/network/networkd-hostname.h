/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

int manager_watch_hostname(Manager *m);
int manager_set_hostname(Manager *m, const char *hostname);
int manager_request_product_uuid(Manager *m);
