/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

int dump_lldp_neighbors(sd_varlink *vl, Table *table, int ifindex);
int verb_link_lldp_status(int argc, char *argv[], uintptr_t _data, void *userdata);
