/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdint.h>

/* Define valid section names in repart config files. New sections need to be added here. */
#define REPART_CONF_FILE_VALID_SECTIONS "Partition\0ErofsOptions\0"

uint64_t round_down_size(uint64_t v, uint64_t p);
uint64_t round_up_size(uint64_t v, uint64_t p);
