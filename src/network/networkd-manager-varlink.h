/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

int manager_varlink_init(Manager *m, int fd);

void link_varlink_notify_lldp_neighbors(Link *link, bool unfiltered);
void link_varlink_drop_lldp_neighbors_subscriptions(Link *link);
