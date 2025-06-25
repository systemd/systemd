/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int setup_machine_directory(sd_bus_error *error, bool use_btrfs_subvol, bool use_btrfs_quota);
