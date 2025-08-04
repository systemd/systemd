/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int dump_lldp_neighbors(sd_varlink *vl, Table *table, int ifindex);
int link_lldp_status(int argc, char *argv[], void *userdata);
