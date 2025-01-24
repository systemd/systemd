/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-manager.h"

#define LLMNR_PORT 5355

int manager_llmnr_ipv4_udp_fd(Manager *m);
int manager_llmnr_ipv6_udp_fd(Manager *m);
int manager_llmnr_ipv4_tcp_fd(Manager *m);
int manager_llmnr_ipv6_tcp_fd(Manager *m);

void manager_llmnr_stop(Manager *m);
void manager_llmnr_maybe_stop(Manager *m);
int manager_llmnr_start(Manager *m);
