/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cryptenroll.h"

/* Runs the interactive first-boot enrollment wizard, populating *c (c->enroll_type, c->fido2_device,
 * c->wipe_slots_mask). On return c->enroll_type is set to the chosen mechanism, or left
 * _ENROLL_TYPE_INVALID if the user skipped or the wizard was suppressed.
 *
 * prompt_suppress_mask is a bitmask of (1U << EnrollType): if a slot of any such type already exists on the
 * volume, the wizard does nothing (so it can be hooked into first boot but stay quiet on later boots). */
int cryptenroll_run_interactive(EnrollContext *c, unsigned prompt_suppress_mask, bool chrome, sd_varlink **mute_console_link);
