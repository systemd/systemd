/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Marker file written into the TPM state directory once swtpm_setup has successfully created the TPM state.
 * It is written last, so its presence reliably means a complete TPM was manufactured, rather than a manufacture
 * that was interrupted halfway through. */
#define SWTPM_MANUFACTURED_MARKER ".manufactured"

/* Written by systemd-tpm2-swtpm into its runtime directory once it allocated the vTPM proxy device (which is
 * always tpm0) and placed it in its fdstore. Contains the device's "major:minor", so that
 * systemd-tpm2-generator can recognize the TPM as the software TPM's own one after the initrd→host
 * transition. The service's RuntimeDirectory= is preserved when the service is stopped. */
#define SWTPM_DEVNO_FILENAME "devno"
#define SWTPM_DEVNO_PATH "/run/systemd/swtpm/" SWTPM_DEVNO_FILENAME

int manufacture_swtpm(const char *state_dir, const char *secret);
