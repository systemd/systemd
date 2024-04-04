/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

typedef enum MachineIdSetupFlags {
        MACHINE_ID_SETUP_FORCE_TRANSIENT = 1 << 0,
        MACHINE_ID_SETUP_FORCE_FIRMWARE  = 1 << 1,
} MachineIdSetupFlags;

int machine_id_commit(const char *root);
int machine_id_setup(const char *root, sd_id128_t machine_id, MachineIdSetupFlags flags, sd_id128_t *ret);
