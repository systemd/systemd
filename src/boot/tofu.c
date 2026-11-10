/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "console.h"
#include "efi-efivars.h"
#include "efi-log.h"
#include "efi-string.h"
#include "graphics.h"
#include "iovec-util.h"
#include "pe.h"
#include "secure-boot.h"
#include "sha256.h"
#include "tofu.h"
#include "util.h"

#define TOFU_RECORD_MAGIC "TOFU"
#define TOFU_RECORD_VERSION UINT8_C(1)
#define TOFU_TOKEN_LENGTH_MAX 64U
#define TOFU_RECORD_ATTRIBUTES (EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_BOOTSERVICE_ACCESS)
#define TOFU_HASHES_MAX 64U
#define TOFU_MESSAGE_PAUSE_USEC (2U * 1000U * 1000U)

/* The on-disk (well, in-NVRAM) format of the record: a header, followed by the hashes of the addons that
 * were trusted on first use. The record is bound to the TOFU= token of the profile it was created for via
 * the name of the variable, so that two OSes on the same system never consult each other's record. NVRAM is
 * small, hence no field counts the hashes, the size of the variable does. */
typedef struct TofuRecord {
        char magic[4];
        uint8_t version;
        uint8_t reserved[3]; /* must be zero */
        uint8_t hashes[];
} _packed_ TofuRecord;

static const char16_t * const tofu_state_table[_TOFU_STATE_MAX] = {
        [TOFU_ENROLLING]     = u"enrolling", /* Never exported, tofu_commit() moves on from it */
        [TOFU_ENROLLED]      = u"enrolled",
        [TOFU_VERIFIED]      = u"verified",
        [TOFU_INCOMPLETE]    = u"incomplete",
        [TOFU_DAMAGED]       = u"damaged",
};

void tofu_context_done(TofuContext *c) {
        assert(c);

        free(c->token);
        free(c->variable);
        free(c->hashes);
        iovec_done(&c->dbx);
        iovec_done(&c->mokx);
        iovec_done(&c->accepted);
}

static bool tofu_token_is_valid(const char *token) {
        size_t n = 0;

        assert(token);

        /* The token becomes part of the name of the record variable, hence keep it to a safe charset */

        for (const char *c = token; *c != 0; c++, n++)
                if (!((*c >= 'a' && *c <= 'z') ||
                      (*c >= 'A' && *c <= 'Z') ||
                      (*c >= '0' && *c <= '9') ||
                      IN_SET(*c, '.', '_', '-')))
                        return false;

        return n > 0 && n <= TOFU_TOKEN_LENGTH_MAX;
}

static char* profile_tofu_token(const char *profile, size_t profile_size) {
        if (!profile || profile_size == 0)
                return NULL;

        _cleanup_free_ char *copy = xstrndup8(profile, profile_size);

        char *line, *key, *value;
        size_t pos = 0;
        _cleanup_free_ char *token = NULL;
        while ((line = line_get_key_value(copy, "=", &pos, &key, &value)))
                if (streq8(key, "TOFU")) {
                        free(token);
                        token = value && *value != 0 ? xstrdup8(value) : NULL;
                }

        if (token && !tofu_token_is_valid(token)) {
                log_error("TOFU= token of the UKI profile must consist of 1..%u letters, digits, '.', '_' and '-', ignoring: %s",
                          TOFU_TOKEN_LENGTH_MAX, token);
                return NULL;
        }

        return TAKE_PTR(token);
}

static bool hash_is_recorded(const TofuContext *c, const uint8_t hash[static SHA256_DIGEST_SIZE]) {
        assert(c);
        assert(hash);

        for (size_t i = 0; i < c->n_hashes; i++)
                if (memcmp(c->hashes + i * SHA256_DIGEST_SIZE, hash, SHA256_DIGEST_SIZE) == 0)
                        return true;

        return false;
}

static bool signature_list_has_sha256(const void *data, size_t size, const uint8_t hash[static SHA256_DIGEST_SIZE]) {
        const uint8_t *p = data;

        assert(data || size == 0);
        assert(hash);

        /* Looks for the hash among the EFI_CERT_SHA256 entries of a series of EFI_SIGNATURE_LISTs, as found
         * in dbx and MokListX */

        while (size >= sizeof(EFI_SIGNATURE_LIST)) {
                EFI_SIGNATURE_LIST l;
                memcpy(&l, p, sizeof(l));

                if (l.SignatureListSize < sizeof(EFI_SIGNATURE_LIST) || l.SignatureListSize > size)
                        break; /* Malformed */

                if (efi_guid_equal(&l.SignatureType, MAKE_GUID_PTR(EFI_CERT_SHA256)) &&
                    l.SignatureSize == sizeof(EFI_GUID) + SHA256_DIGEST_SIZE &&
                    l.SignatureHeaderSize <= l.SignatureListSize - sizeof(EFI_SIGNATURE_LIST))
                        for (size_t o = sizeof(EFI_SIGNATURE_LIST) + l.SignatureHeaderSize;
                             l.SignatureListSize - o >= l.SignatureSize;
                             o += l.SignatureSize)
                                if (memcmp(p + o + sizeof(EFI_GUID), hash, SHA256_DIGEST_SIZE) == 0)
                                        return true;

                p += l.SignatureListSize;
                size -= l.SignatureListSize;
        }

        return false;
}

static bool addon_revoked(const TofuContext *c, const void *buffer, size_t size, const char16_t *path) {
        EFI_STATUS err;

        assert(c);
        assert(buffer || size == 0);
        assert(path);

        /* The firmware refuses images whose Authenticode hash is in dbx, signed or not, and shim does the
         * same for MokListX. Addons trusted on first use don't pass through either, hence check ourselves,
         * so that a revocation by hash applies to them too. */

        uint8_t hash[SHA256_DIGEST_SIZE];
        err = pe_buffer_authenticode_sha256(buffer, size, hash);
        if (err != EFI_SUCCESS) {
                log_error_status(err, "Unable to calculate Authenticode hash of addon '%ls', not trusting it: %m", path);
                return true;
        }

        if (signature_list_has_sha256(c->dbx.iov_base, c->dbx.iov_len, hash) ||
            signature_list_has_sha256(c->mokx.iov_base, c->mokx.iov_len, hash)) {
                log_error("Addon '%ls' is revoked by its hash in dbx or MokListX, not trusting it.", path);
                return true;
        }

        return false;
}

static void forget_hashes(TofuContext *c) {
        assert(c);

        c->hashes = mfree(c->hashes);
        c->n_hashes = 0;
}

static EFI_STATUS read_record(TofuContext *c) {
        EFI_STATUS err;

        assert(c);
        assert(c->variable);
        assert(c->token);

        /* Returns EFI_NOT_FOUND quietly if there is no record. All other failures are logged here. */

        _cleanup_free_ void *data = NULL;
        uint32_t attributes;
        size_t size = 0;
        err = efivar_get_raw_full(MAKE_GUID_PTR(LOADER), c->variable, &attributes, &data, &size);
        if (err == EFI_NOT_FOUND)
                return err;
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to read TOFU record EFI variable, not trusting any unsigned addon: %m");

        /* Remember how the variable is stored, so that a damaged one can be deleted with matching
         * attributes, as the UEFI spec requires. */

        /* The record must be inaccessible after ExitBootServices(), otherwise userspace could have created
         * it. If it is accessible, something else than us wrote it, hence ignore it. */
        if ((attributes & (EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_BOOTSERVICE_ACCESS|EFI_VARIABLE_RUNTIME_ACCESS)) !=
            TOFU_RECORD_ATTRIBUTES)
                return log_error_status(EFI_PROTOCOL_ERROR, "TOFU record EFI variable has unexpected attributes, not trusting any unsigned addon.");

        if (size < sizeof(TofuRecord))
                return log_error_status(EFI_PROTOCOL_ERROR, "TOFU record EFI variable is too short, not trusting any unsigned addon.");

        const TofuRecord *record = data;
        if (memcmp(record->magic, TOFU_RECORD_MAGIC, sizeof(record->magic)) != 0 ||
            record->version != TOFU_RECORD_VERSION)
                return log_error_status(EFI_PROTOCOL_ERROR, "TOFU record EFI variable has unexpected magic or version, not trusting any unsigned addon.");

        if (!memeqzero(record->reserved, sizeof(record->reserved)))
                return log_error_status(EFI_PROTOCOL_ERROR, "TOFU record EFI variable has unexpected flags, not trusting any unsigned addon.");

        size_t n_hashes = (size - sizeof(TofuRecord)) / SHA256_DIGEST_SIZE;
        if (n_hashes > TOFU_HASHES_MAX ||
            size != sizeof(TofuRecord) + n_hashes * SHA256_DIGEST_SIZE)
                return log_error_status(EFI_PROTOCOL_ERROR, "TOFU record EFI variable has unexpected size, not trusting any unsigned addon.");

        c->n_hashes = n_hashes;
        c->hashes = c->n_hashes > 0 ? xmemdup(record->hashes, c->n_hashes * SHA256_DIGEST_SIZE) : NULL;
        return EFI_SUCCESS;
}

static EFI_STATUS write_record(const TofuContext *c) {
        assert(c);
        assert(c->variable);
        assert(c->token);
        assert(c->hashes || c->n_hashes == 0);

        size_t size = sizeof(TofuRecord) + c->n_hashes * SHA256_DIGEST_SIZE;
        _cleanup_free_ TofuRecord *record = xmalloc(size);
        *record = (TofuRecord) {
                .version = TOFU_RECORD_VERSION,
        };
        memcpy(record->magic, TOFU_RECORD_MAGIC, sizeof(record->magic));
        if (c->n_hashes > 0)
                memcpy(record->hashes, c->hashes, c->n_hashes * SHA256_DIGEST_SIZE);

        /* Set the variable without EFI_VARIABLE_RUNTIME_ACCESS, so that it is invisible and immutable once
         * the OS runs. efivar_set_raw() unconditionally adds that flag, hence call SetVariable() directly. */
        return RT->SetVariable(c->variable, MAKE_GUID_PTR(LOADER), TOFU_RECORD_ATTRIBUTES, size, record);
}

void tofu_setup(
                TofuContext *c,
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector *profile_section) {

        EFI_STATUS err;

        assert(c);
        assert(loaded_image);

        *c = (TofuContext) {};

        const char *profile = NULL;
        size_t profile_size = 0;
        if (PE_SECTION_VECTOR_IS_SET(profile_section)) {
                profile = (const char*) loaded_image->ImageBase + profile_section->memory_offset;
                profile_size = profile_section->memory_size;
        }

        c->token = profile_tofu_token(profile, profile_size);
        if (!c->token)
                return;

        /* Without Secure Boot the firmware loads unsigned addons just fine, and we'd never see them. Don't
         * enroll in that case, as the record would be empty and close the enrollment window for good once
         * Secure Boot is turned on. */
        if (!secure_boot_enabled()) {
                log_debug("Secure Boot is disabled, not trusting addons on first use.");
                return;
        }

        c->variable = xasprintf("StubTofuRecord-%s", c->token);

        /* Both are optional, if they are missing nothing is revoked */
        (void) efivar_get_raw(MAKE_GUID_PTR(EFI_IMAGE_SECURITY_DATABASE), u"dbx", &c->dbx.iov_base, &c->dbx.iov_len);
        (void) efivar_get_raw(MAKE_GUID_PTR(SHIM_LOCK), u"MokListX", &c->mokx.iov_base, &c->mokx.iov_len);

        err = read_record(c);
        if (err == EFI_NOT_FOUND) {
                log_debug("No TOFU record for token '%s' yet, enrolling unsigned addons on this boot.", c->token);
                c->state = TOFU_ENROLLING;
                return;
        }
        if (err != EFI_SUCCESS) {
                /* read_record() logged already. Don't trust anything. A factory reset erases the record,
                 * which makes enrollment possible again. */
                forget_hashes(c);
                c->state = TOFU_DAMAGED;
                return;
        }

        log_debug("TOFU record for token '%s' lists %zu addons.", c->token, c->n_hashes);
        c->state = TOFU_VERIFIED;
}

void tofu_enroll(TofuContext *c, const void *buffer, size_t size, const char16_t *path) {
        assert(c);
        assert(buffer || size == 0);
        assert(path);

        if (c->state != TOFU_ENROLLING)
                return;

        if (addon_revoked(c, buffer, size, path))
                return;

        uint8_t hash[SHA256_DIGEST_SIZE];
        sha256_direct(buffer, size, hash);

        if (hash_is_recorded(c, hash)) /* The same addon in both directories */
                return;

        if (c->n_hashes >= TOFU_HASHES_MAX) {
                log_error("Too many unsigned addons to trust on first use, not trusting '%ls'.", path);
                return;
        }

        c->hashes = xrealloc(c->hashes, c->n_hashes * SHA256_DIGEST_SIZE, (c->n_hashes + 1) * SHA256_DIGEST_SIZE);
        memcpy(c->hashes + c->n_hashes * SHA256_DIGEST_SIZE, hash, SHA256_DIGEST_SIZE);
        c->n_hashes++;

        /* This is security relevant, hence make sure it is visible, even if the splash is shown already */
        _cleanup_free_ char16_t *h = hexdump16(hash, 8);
        (void) graphics_mode(/* on= */ false);
        printf("Found unsigned addon '%ls' to trust on first use (SHA256 %ls...).\n", path, h);
}

void tofu_commit(TofuContext *c) {
        EFI_STATUS err;

        assert(c);

        if (c->state != TOFU_ENROLLING)
                return;

        /* scan_incomplete and scan_unsupported do not stop the record from being written: if a directory we
         * could not look at kept the enrollment window open, the OS could plant addons later and reboot via
         * a firmware boot entry for the UKI, which exposes every directory, to get them enrolled. The record
         * is hence written on the first boot in any case, and an addon that was not seen on that boot is
         * never trusted. */
        if (c->scan_incomplete)
                log_error("Could not look at every addon, addons not seen on this boot are never trusted on first use.");
        else if (c->scan_unsupported)
                log_info("Boot loader provides no access to all addon directories, addons not seen on this boot are never trusted on first use.");

        /* Write the record even if we found nothing to trust, so that the enrollment window is closed after
         * the first boot with TOFU enabled, and nothing can be added later without a factory reset. */
        err = write_record(c);
        if (err != EFI_SUCCESS) {
                log_error_status(err, "Failed to write TOFU record, not trusting any unsigned addon on this boot: %m");
                forget_hashes(c);
                c->state = TOFU_INCOMPLETE;
                return;
        }

        log_debug("Wrote TOFU record for token '%s' with %zu addons.", c->token, c->n_hashes);
        c->state = TOFU_ENROLLED;

        if (c->n_hashes > 0) {
                printf("Trusting %zu unsigned addon(s) on first use from now on.\n", c->n_hashes);
                (void) console_key_read(/* ret_key= */ NULL, TOFU_MESSAGE_PAUSE_USEC);
        }
}

bool tofu_check(const TofuContext *c, const void *buffer, size_t size, const char16_t *path) {
        assert(c);
        assert(buffer || size == 0);
        assert(path);

        if (!IN_SET(c->state, TOFU_ENROLLED, TOFU_VERIFIED)) {
                log_error("Addon '%ls' is not signed, and no addons are trusted on first use on this boot, ignoring.", path);
                return false;
        }

        uint8_t hash[SHA256_DIGEST_SIZE];
        sha256_direct(buffer, size, hash);

        if (!hash_is_recorded(c, hash)) {
                log_error("Addon '%ls' is not signed and not trusted on first use, ignoring.", path);
                return false;
        }

        /* It might have been revoked after it was recorded */
        if (addon_revoked(c, buffer, size, path))
                return false;

        return true;
}

void tofu_accept(TofuContext *c, const char16_t *path) {
        assert(c);
        assert(path);

        log_debug("Addon '%ls' is not signed, but trusted on first use.", path);

        size_t l = strsize16(path);
        c->accepted.iov_base = xrealloc(c->accepted.iov_base, c->accepted.iov_len, c->accepted.iov_len + l);
        memcpy((uint8_t*) c->accepted.iov_base + c->accepted.iov_len, path, l);
        c->accepted.iov_len += l;
}

void tofu_finish(TofuContext *c) {
        assert(c);

        if (c->state == TOFU_DISABLED)
                return;

        /* tofu_commit() is always called while enrolling, but if it weren't, nothing was written */
        if (c->state == TOFU_ENROLLING)
                c->state = TOFU_INCOMPLETE;

        (void) efivar_set_str16(MAKE_GUID_PTR(LOADER), u"StubTofuState", tofu_state_table[c->state], /* flags= */ 0);

        /* Like LoaderEntries, a list of NUL terminated strings. Not set if no addon was trusted. */
        if (c->accepted.iov_len > 0)
                (void) efivar_set_raw(MAKE_GUID_PTR(LOADER), u"StubTofuAddons", c->accepted.iov_base, c->accepted.iov_len, /* flags= */ 0);
}
