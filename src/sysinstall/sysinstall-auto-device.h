/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int sysinstall_auto_pick_block_device(usec_t settle_timeout, char **ret_node);
