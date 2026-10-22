/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"
#include "sha256.h"

/* Trust-on-first-use for add-ons the firmware refuses to load under Secure Boot. See the "Trusting Addons
 * On First Use" section of systemd-stub(7). */

typedef struct TofuContext {
        bool enabled;          /* The booted UKI profile opted in via TOFU= in its .profile section, and Secure Boot is on */
        char *os_id;           /* IMAGE_ID= or ID= of the UKI's .osrel, the record is pinned to it */
        char *id;              /* ID= of the UKI's .osrel, for matching a factory reset request */
        char *image_id;        /* IMAGE_ID= of the UKI's .osrel, if any, ditto */
        char16_t *variable;    /* Name of the EFI variable holding the record */
        uint32_t record_attributes; /* Attributes of the record variable as found, needed to delete a damaged one */

        bool enrolling;        /* No record exists yet: hashes of unsigned add-ons are recorded this boot */
        bool forgotten;        /* The record was deleted on this boot, nothing is trusted until the next boot enrols again */
        bool scan_incomplete;  /* An add-on directory could not be enumerated, hence no record may be written */
        bool damaged;          /* The record could not be read or deleted, nothing is trusted until a factory reset */
        uint8_t *hashes;       /* The recorded hashes, SHA256_DIGEST_SIZE bytes each */
        size_t n_hashes;

        char16_t *accepted;    /* Space separated names of add-ons accepted via TOFU this boot */
} TofuContext;

void tofu_context_done(TofuContext *c);

/* Parses the .profile section of the booted profile and the .osrel section, reads the record, and processes
 * a pending factory reset request. */
void tofu_setup(
                TofuContext *c,
                const char *profile,
                size_t profile_size,
                const char *osrel,
                size_t osrel_size);

/* Returns true if the add-on with the specified contents may be used, i.e. its hash is recorded, or we are
 * enrolling and have room for it. Does not modify the context, the hash is returned so that the caller can
 * pass it to tofu_accept() once the add-on passed all other checks. */
bool tofu_check(
                TofuContext *c,
                const void *buffer,
                size_t size,
                const char16_t *filename,
                uint8_t ret_hash[static SHA256_DIGEST_SIZE]);

/* Records the hash if we are enrolling and it is not recorded yet, and lists the add-on as accepted. Only to
 * be called after tofu_check() returned true for the same hash. */
void tofu_accept(
                TofuContext *c,
                const uint8_t hash[static SHA256_DIGEST_SIZE],
                const char16_t *filename);

/* Writes the record if we were enrolling, and exports the state to userspace via EFI variables. */
void tofu_finish(TofuContext *c);
