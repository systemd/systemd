/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "forward.h"

typedef enum MachineIdSetupFlags {
        MACHINE_ID_SETUP_FORCE_TRANSIENT = 1 << 0,
        MACHINE_ID_SETUP_FORCE_FIRMWARE  = 1 << 1,
        MACHINE_ID_SETUP_FORCE_NEW       = 1 << 2, /* Discard any ID currently in place, and generate a
                                                    * fresh random one. Must be passed with a null
                                                    * machine_id and without FORCE_TRANSIENT or
                                                    * FORCE_FIRMWARE: it makes up the ID itself, and it is
                                                    * about persisting it. An /etc/machine-id marked
                                                    * "uninitialized" is left alone regardless, as it
                                                    * doubles as the first boot marker. */
} MachineIdSetupFlags;

int machine_id_commit(const char *root);
int machine_id_setup(const char *root, sd_id128_t machine_id, MachineIdSetupFlags flags, sd_id128_t *ret);
