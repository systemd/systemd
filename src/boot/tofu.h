/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"
#include "iovec-util.h"
#include "pe.h"
#include "proto/loaded-image.h"

/* Trust-on-first-use for addons the firmware refuses to load under Secure Boot. See the "Trusting Addons On
 * First Use" section of systemd-stub(7).
 *
 * On a boot that enrolls, the addons are scanned twice: first all usable unsigned addons are collected via
 * tofu_enroll() and the record is written via tofu_commit(), then the addons are loaded as usual, and only
 * those whose hash made it into the written record are trusted via tofu_check(). That way nothing is used
 * that isn't recorded, even if the record cannot be written. */

typedef enum TofuState {
        TOFU_DISABLED,       /* The booted profile doesn't opt in, or Secure Boot is off */
        TOFU_ENROLLING,      /* No record exists yet, unsigned addons are collected on this boot */
        TOFU_ENROLLED,       /* The record was written on this boot */
        TOFU_VERIFIED,       /* An existing record is used */
        TOFU_INCOMPLETE,     /* The record could not be written, nothing is trusted, enrollment is retried on the next boot */
        TOFU_DAMAGED,        /* The record could not be read, nothing is trusted until a factory reset */
        _TOFU_STATE_MAX,
} TofuState;

typedef struct TofuContext {
        TofuState state;
        char *token;                /* The value of the profile's TOFU= field, the record is pinned to it */
        char16_t *variable;         /* Name of the EFI variable holding the record */

        bool scan_incomplete;       /* An addon couldn't be looked at while enrolling, it stays out of the record */
        bool scan_unsupported;      /* The boot loader doesn't let us look at all addon directories, ditto */
        uint8_t *hashes;            /* The recorded hashes, SHA256_DIGEST_SIZE bytes each */
        size_t n_hashes;

        struct iovec dbx;           /* The firmware's forbidden signature database, if any */
        struct iovec mokx;          /* shim's MokListX, if any */

        struct iovec accepted;      /* NUL separated char16_t paths of the addons trusted on first use on this boot */
} TofuContext;

void tofu_context_done(TofuContext *c);

/* Parses the .profile section of the booted profile and reads the record */
void tofu_setup(
                TofuContext *c,
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector *profile_section);

static inline bool tofu_enrolling(const TofuContext *c) {
        return c && c->state == TOFU_ENROLLING;
}

/* While enrolling: records the hash of a usable unsigned addon. */
void tofu_enroll(TofuContext *c, const void *buffer, size_t size, const char16_t *path);

/* While enrolling: writes the record. Addons the scan could not look at stay out of it and are never
 * trusted. If the record cannot be written, nothing is trusted on this boot. */
void tofu_commit(TofuContext *c);

/* Returns true if the unsigned addon with the specified contents is trusted, i.e. its hash is in the record
 * that is in effect on this boot. */
bool tofu_check(const TofuContext *c, const void *buffer, size_t size, const char16_t *path);

/* Lists an addon that tofu_check() returned true for, and that passed all other checks, as used. */
void tofu_accept(TofuContext *c, const char16_t *path);

/* Exports the state to userspace via EFI variables. */
void tofu_finish(TofuContext *c);
