/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Marker file written into the TPM state directory once swtpm_setup has successfully created the TPM state.
 * It is written last, so its presence reliably means a complete TPM was manufactured, rather than a manufacture
 * that was interrupted halfway through. */
#define SWTPM_MANUFACTURED_MARKER ".manufactured"

int manufacture_swtpm(const char *state_dir, const char *secret);
