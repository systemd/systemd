/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"
#include "pe.h"
#include "proto/loaded-image.h"

/* Trust-on-first-use for addons the firmware refuses to load under Secure Boot. See the "Trusting Addons On
 * First Use" section of systemd-stub(7).
 *
 * On a boot that enrols, the addons are scanned twice: first all usable unsigned addons are collected via
 * tofu_enrol() and the record is written via tofu_commit(), then the addons are loaded as usual, and only
 * those whose hash made it into the written record are trusted via tofu_check(). That way nothing is used
 * that isn't recorded, even if the record cannot be written. */

typedef enum TofuState {
        TOFU_DISABLED,       /* The booted profile doesn't opt in, Secure Boot is off, or .osrel lacks ID= */
        TOFU_ENROLLING,      /* No record exists yet, unsigned addons are collected on this boot */
        TOFU_ENROLLED,       /* The record was written on this boot */
        TOFU_VERIFIED,       /* An existing record is used */
        TOFU_INCOMPLETE,     /* Enrolment could not finish, nothing is trusted, it is retried on the next boot */
        TOFU_FORGOTTEN,      /* The record was deleted on this boot, nothing is trusted until the next boot */
        TOFU_RESET_PENDING,  /* No record, but a factory reset is pending, nothing is enrolled until it's done */
        TOFU_DAMAGED,        /* The record could not be read or deleted, nothing is trusted until a reset */
        _TOFU_STATE_MAX,
} TofuState;

typedef struct TofuContext {
        TofuState state;
        char *id;                   /* ID= of the UKI's .osrel, for matching a factory reset request */
        char *image_id;             /* IMAGE_ID= of the UKI's .osrel, if any, ditto */
        const char *os_id;          /* IMAGE_ID= if set, ID= otherwise, the record is pinned to it */
        char16_t *variable;         /* Name of the EFI variable holding the record */
        uint32_t record_attributes; /* Attributes of the record variable as found, to delete a damaged one */

        bool scan_incomplete;       /* An addon couldn't be looked at while enrolling, no record may be written */
        bool scan_unsupported;      /* The boot loader doesn't let us look at all addon directories, ditto */
        uint8_t *hashes;            /* The recorded hashes, SHA256_DIGEST_SIZE bytes each */
        size_t n_hashes;

        void *dbx;                  /* The firmware's forbidden signature database, if any */
        size_t dbx_size;
        void *mokx;                 /* shim's MokListX, if any */
        size_t mokx_size;

        char16_t *accepted;         /* NUL separated paths of the addons trusted on first use on this boot */
        size_t accepted_size;       /* Size of the above in bytes */
} TofuContext;

void tofu_context_done(TofuContext *c);

/* Parses the .profile section of the booted profile and the .osrel section, reads the record, and processes
 * a pending factory reset request. */
void tofu_setup(
                TofuContext *c,
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector *profile_section,
                const PeSectionVector *osrel_section);

static inline bool tofu_enrolling(const TofuContext *c) {
        return c && c->state == TOFU_ENROLLING;
}

/* While enrolling: records the hash of a usable unsigned addon. */
void tofu_enrol(TofuContext *c, const void *buffer, size_t size, const char16_t *path);

/* While enrolling: writes the record, unless the scan was incomplete. If no record is written, nothing is
 * trusted on this boot. */
void tofu_commit(TofuContext *c);

/* Returns true if the unsigned addon with the specified contents is trusted, i.e. its hash is in the record
 * that is in effect on this boot. */
bool tofu_check(const TofuContext *c, const void *buffer, size_t size, const char16_t *path);

/* Lists an addon that tofu_check() returned true for, and that passed all other checks, as used. */
void tofu_accept(TofuContext *c, const char16_t *path);

/* Exports the state to userspace via EFI variables. */
void tofu_finish(TofuContext *c);
