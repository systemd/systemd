/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cryptenroll.h"
#include "shared-forward.h"

/* Wipes the slots selected by c->wipe_slots / c->n_wipe_slots / c->wipe_slots_scope /
 * c->wipe_slots_mask, except for c->wipe_except_slot (set to -1 for none). If ret_wiped_slots/
 * ret_n_wiped_slots are non-NULL they receive the (ascendingly sorted) list of slots that were actually
 * wiped. */
int wipe_slots(const EnrollContext *c, struct crypt_device *cd, int **ret_wiped_slots, size_t *ret_n_wiped_slots);
