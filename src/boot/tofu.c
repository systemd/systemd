/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "console.h"
#include "efi-efivars.h"
#include "efi-log.h"
#include "efi-string.h"
#include "graphics.h"
#include "pe.h"
#include "secure-boot.h"
#include "sha256.h"
#include "tofu.h"
#include "util.h"

#define TOFU_RECORD_MAGIC "TOFU"
#define TOFU_RECORD_VERSION UINT32_C(1)
#define TOFU_RECORD_ATTRIBUTES (EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_BOOTSERVICE_ACCESS)
#define TOFU_HASHES_MAX 64U
#define TOFU_PROMPT_TIMEOUT_SEC 30U
#define TOFU_MESSAGE_PAUSE_USEC (2U * 1000U * 1000U)

/* The on-disk (well, in-NVRAM) format of the record: a header, followed by the hashes of the addons that
 * were trusted on first use. The record is bound to the OS it was created for via a hash of the OS ID, so
 * that two OSes on the same system never consult each other's record. */
typedef struct TofuRecord {
        char magic[4];
        uint32_t version;
        uint8_t os_id_hash[SHA256_DIGEST_SIZE];
        uint32_t n_hashes;
        uint8_t hashes[];
} _packed_ TofuRecord;

static const char16_t * const tofu_state_table[_TOFU_STATE_MAX] = {
        [TOFU_ENROLLING]     = u"enrolling", /* Never exported, tofu_commit() moves on from it */
        [TOFU_ENROLLED]      = u"enrolled",
        [TOFU_VERIFIED]      = u"verified",
        [TOFU_INCOMPLETE]    = u"incomplete",
        [TOFU_FORGOTTEN]     = u"forgotten",
        [TOFU_RESET_PENDING] = u"reset-pending",
        [TOFU_DAMAGED]       = u"damaged",
};

void tofu_context_done(TofuContext *c) {
        assert(c);

        free(c->id);
        free(c->image_id);
        free(c->variable);
        free(c->hashes);
        free(c->dbx);
        free(c->mokx);
        free(c->accepted);
}

static bool profile_enables_tofu(const char *profile, size_t profile_size) {
        if (!profile || profile_size == 0)
                return false;

        _cleanup_free_ char *copy = xstrndup8(profile, profile_size);

        char *line, *key, *value;
        size_t pos = 0;
        bool b = false;
        while ((line = line_get_key_value(copy, "=", &pos, &key, &value)))
                if (streq8(key, "TOFU")) {
                        if (!parse_boolean(value, &b)) {
                                log_error("Cannot parse TOFU= setting of UKI profile, ignoring: %s", value);
                                b = false;
                        }
                }

        return b;
}

static char* osrel_get(const char *osrel, size_t osrel_size, const char *field) {
        assert(osrel || osrel_size == 0);
        assert(field);

        /* Returns the value of the specified .osrel field, or NULL if it isn't set */

        if (!osrel || osrel_size == 0)
                return NULL;

        _cleanup_free_ char *copy = xstrndup8(osrel, osrel_size);

        char *line, *key, *value;
        size_t pos = 0;
        while ((line = line_get_key_value(copy, "=", &pos, &key, &value)))
                if (streq8(key, field))
                        return xstrdup8(value);

        return NULL;
}

static void hash_os_id(const char *os_id, uint8_t ret[static SHA256_DIGEST_SIZE]) {
        static const char label[] = "systemd-stub tofu os id label v1";

        assert(os_id);
        assert(ret);

        struct sha256_ctx hash;
        sha256_init_ctx(&hash);
        sha256_process_bytes(label, sizeof(label) - 1, &hash);
        sha256_process_bytes_and_size(os_id, strlen8(os_id), &hash);
        sha256_finish_ctx(&hash, ret);
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

        if (signature_list_has_sha256(c->dbx, c->dbx_size, hash) ||
            signature_list_has_sha256(c->mokx, c->mokx_size, hash)) {
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
        assert(c->os_id);

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
        c->record_attributes = attributes;

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

        if (record->n_hashes > TOFU_HASHES_MAX ||
            size != sizeof(TofuRecord) + (size_t) record->n_hashes * SHA256_DIGEST_SIZE)
                return log_error_status(EFI_PROTOCOL_ERROR, "TOFU record EFI variable has unexpected size, not trusting any unsigned addon.");

        uint8_t os_id_hash[SHA256_DIGEST_SIZE];
        hash_os_id(c->os_id, os_id_hash);
        if (memcmp(record->os_id_hash, os_id_hash, sizeof(os_id_hash)) != 0)
                return log_error_status(EFI_PROTOCOL_ERROR, "TOFU record EFI variable belongs to a different OS, not trusting any unsigned addon.");

        c->n_hashes = record->n_hashes;
        c->hashes = c->n_hashes > 0 ? xmemdup(record->hashes, c->n_hashes * SHA256_DIGEST_SIZE) : NULL;
        return EFI_SUCCESS;
}

static EFI_STATUS write_record(const TofuContext *c) {
        assert(c);
        assert(c->variable);
        assert(c->os_id);
        assert(c->hashes || c->n_hashes == 0);

        size_t size = sizeof(TofuRecord) + c->n_hashes * SHA256_DIGEST_SIZE;
        _cleanup_free_ TofuRecord *record = xmalloc(size);
        *record = (TofuRecord) {
                .version = TOFU_RECORD_VERSION,
                .n_hashes = c->n_hashes,
        };
        memcpy(record->magic, TOFU_RECORD_MAGIC, sizeof(record->magic));
        hash_os_id(c->os_id, record->os_id_hash);
        if (c->n_hashes > 0)
                memcpy(record->hashes, c->hashes, c->n_hashes * SHA256_DIGEST_SIZE);

        /* Set the variable without EFI_VARIABLE_RUNTIME_ACCESS, so that it is invisible and immutable once
         * the OS runs. efivar_set_raw() unconditionally adds that flag, hence call SetVariable() directly. */
        return RT->SetVariable(c->variable, MAKE_GUID_PTR(LOADER), TOFU_RECORD_ATTRIBUTES, size, record);
}

static EFI_STATUS delete_record(const TofuContext *c) {
        assert(c);
        assert(c->variable);

        /* Deleting requires passing the attributes the variable was created with, use the ones we found it
         * with, so that a damaged record (e.g. one created with the wrong attributes) can be removed too. */
        return RT->SetVariable(
                        c->variable,
                        MAKE_GUID_PTR(LOADER),
                        c->record_attributes != 0 ? c->record_attributes : TOFU_RECORD_ATTRIBUTES,
                        0,
                        NULL);
}

static bool factory_reset_requested(const char *id, const char *image_id) {
        EFI_STATUS err;

        assert(id);

        /* userspace sets FactoryResetRequest to a JSON object carrying the ID= of the requesting OS in
         * osReleaseId and its IMAGE_ID= in osReleaseImageId, the latter only if the OS has one. We don't have
         * a JSON parser here, so check for the fields in a non-fancy way, it's our own format after
         * all. Mirror what userspace does with the request (see factory_reset_mode_efi_variable()): both
         * fields have to match what our .osrel says, a missing IMAGE_ID= included. */

        _cleanup_free_ char16_t *request = NULL;
        err = efivar_get_str16(MAKE_GUID_PTR(SYSTEMD), u"FactoryResetRequest", &request);
        if (err != EFI_SUCCESS)
                return false;

        _cleanup_free_ char16_t *id_needle = xasprintf("\"osReleaseId\":\"%s\"", id);
        _cleanup_free_ char16_t *image_id_needle = image_id ?
                xasprintf("\"osReleaseImageId\":\"%s\"", image_id) :
                xstrdup16(u"\"osReleaseImageId\":");

        bool id_matches = !!strstr16(request, id_needle),
                image_id_matches = image_id ?
                        !!strstr16(request, image_id_needle) :   /* ours must be in the request */
                        !strstr16(request, image_id_needle);     /* the request must not carry any */
        if (!id_matches || !image_id_matches) {
                log_debug("Factory reset requested by a different OS, ignoring.");
                return false;
        }

        return true;
}

static bool prompt_forget(void) {
        EFI_STATUS err;

        /* The splash may have switched to graphics mode, and a key pressed earlier must not answer the
         * question, hence prepare the console like systemd-boot does before showing its menu. */
        (void) graphics_mode(false);
        (void) ST->ConIn->Reset(ST->ConIn, /* ExtendedVerification= */ false);

        printf("Factory reset requested: forget the addons trusted on first use?\n");

        for (unsigned left = TOFU_PROMPT_TIMEOUT_SEC; left > 0;) {
                printf("\rPress 'y' to forget them, any other key to keep them (keeping them in %us).", left);

                uint64_t key = 0;
                err = console_key_read(&key, /* timeout_usec= */ 1000 * 1000);
                if (err == EFI_NOT_READY) /* Spurious wakeup */
                        continue;
                if (err == EFI_TIMEOUT) {
                        left--;
                        continue;
                }

                printf("\n");

                if (err != EFI_SUCCESS) {
                        log_error_status(err, "Error waiting for user input, keeping the addons trusted on first use: %m");
                        return false;
                }

                return IN_SET(key, KEYPRESS(0, 0, 'y'), KEYPRESS(0, 0, 'Y'));
        }

        printf("\n");
        return false;
}

void tofu_setup(
                TofuContext *c,
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector *profile_section,
                const PeSectionVector *osrel_section) {

        EFI_STATUS err;

        assert(c);
        assert(loaded_image);

        *c = (TofuContext) {};

        const char *profile = NULL, *osrel = NULL;
        size_t profile_size = 0, osrel_size = 0;
        if (PE_SECTION_VECTOR_IS_SET(profile_section)) {
                profile = (const char*) loaded_image->ImageBase + profile_section->memory_offset;
                profile_size = profile_section->memory_size;
        }
        if (PE_SECTION_VECTOR_IS_SET(osrel_section)) {
                osrel = (const char*) loaded_image->ImageBase + osrel_section->memory_offset;
                osrel_size = osrel_section->memory_size;
        }

        if (!profile_enables_tofu(profile, profile_size))
                return;

        /* Without Secure Boot the firmware loads unsigned addons just fine, and we'd never see them. Don't
         * enrol in that case, as the record would be empty and close the enrolment window for good once
         * Secure Boot is turned on. */
        if (!secure_boot_enabled()) {
                log_debug("Secure Boot is disabled, not trusting addons on first use.");
                return;
        }

        /* The record is pinned to the OS, and a factory reset request is matched against it. Without an ID=
         * we can do neither, and a fallback would be shared by every such OS. */
        c->id = osrel_get(osrel, osrel_size, "ID");
        if (!c->id) {
                log_error("UKI profile enables trusting addons on first use, but the UKI's .osrel section lacks ID=, not trusting any unsigned addon.");
                return;
        }
        c->image_id = osrel_get(osrel, osrel_size, "IMAGE_ID");
        c->os_id = c->image_id ?: c->id;
        c->variable = xasprintf("StubTofuRecord-%s", c->os_id);

        /* Both are optional, if they are missing nothing is revoked */
        (void) efivar_get_raw(MAKE_GUID_PTR(EFI_IMAGE_SECURITY_DATABASE), u"dbx", &c->dbx, &c->dbx_size);
        (void) efivar_get_raw(MAKE_GUID_PTR(SHIM_LOCK), u"MokListX", &c->mokx, &c->mokx_size);

        bool reset_requested = factory_reset_requested(c->id, c->image_id);

        err = read_record(c);
        if (err == EFI_NOT_FOUND) {
                if (reset_requested) {
                        /* Once we forgot the record, the OS performs the factory reset, which removes the
                         * request when done. Until then the ESP still has whatever the old installation
                         * left there, hence don't enrol anything yet. */
                        log_info("Factory reset pending, not trusting addons on first use until it completed.");
                        c->state = TOFU_RESET_PENDING;
                        return;
                }

                log_debug("No TOFU record for OS '%s' yet, enrolling unsigned addons on this boot.", c->os_id);
                c->state = TOFU_ENROLLING;
                return;
        }
        if (err != EFI_SUCCESS) {
                /* read_record() logged already. Don't trust anything, but allow forgetting the record via a
                 * factory reset below, so that enrolment is possible again. */
                forget_hashes(c);
                c->state = TOFU_DAMAGED;
        } else {
                log_debug("TOFU record for OS '%s' lists %zu addons.", c->os_id, c->n_hashes);
                c->state = TOFU_VERIFIED;
        }

        if (!reset_requested || !prompt_forget())
                return;

        err = delete_record(c);
        if (err != EFI_SUCCESS) {
                log_error_status(err, "Failed to delete TOFU record, not trusting any unsigned addon: %m");
                forget_hashes(c);
                c->state = TOFU_DAMAGED;
                return;
        }

        /* Don't enrol again right away: the factory reset requested from userspace has not run yet, and the
         * contents of the ESP are whatever the OS (or whoever controlled it) left behind. Trust nothing
         * unsigned on this boot, and enrol afresh once the reset completed. */
        printf("Forgot %zu trusted addon(s). Unsigned addons are ignored until the factory reset completed.\n", c->n_hashes);
        (void) console_key_read(/* ret_key= */ NULL, TOFU_MESSAGE_PAUSE_USEC);

        forget_hashes(c);
        c->state = TOFU_FORGOTTEN;
}

void tofu_enrol(TofuContext *c, const void *buffer, size_t size, const char16_t *path) {
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
        _cleanup_free_ char16_t *h = hexdump(hash, 8);
        (void) graphics_mode(false);
        printf("Found unsigned addon '%ls' to trust on first use (SHA256 %ls...).\n", path, h);
}

void tofu_commit(TofuContext *c) {
        EFI_STATUS err;

        assert(c);

        if (c->state != TOFU_ENROLLING)
                return;

        if (c->scan_incomplete || c->scan_unsupported) {
                /* A boot loader that doesn't give us access to all addon directories is not an error, it just
                 * can't be used for enrolment, hence don't complain loudly about it on every boot */
                if (c->scan_incomplete)
                        log_error("Could not look at all addons, not trusting any unsigned addon on this boot, enrolling again on the next boot.");
                else
                        log_info("Boot loader provides no access to all addon directories, cannot trust addons on first use when booted this way.");
                forget_hashes(c);
                c->state = TOFU_INCOMPLETE;
                return;
        }

        /* Write the record even if we found nothing to trust, so that the enrolment window is closed after
         * the first boot with TOFU enabled, and nothing can be added later without a factory reset. */
        err = write_record(c);
        if (err != EFI_SUCCESS) {
                log_error_status(err, "Failed to write TOFU record, not trusting any unsigned addon on this boot: %m");
                forget_hashes(c);
                c->state = TOFU_INCOMPLETE;
                return;
        }

        log_debug("Wrote TOFU record for OS '%s' with %zu addons.", c->os_id, c->n_hashes);
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
        c->accepted = xrealloc(c->accepted, c->accepted_size, c->accepted_size + l);
        memcpy((uint8_t*) c->accepted + c->accepted_size, path, l);
        c->accepted_size += l;
}

void tofu_finish(TofuContext *c) {
        assert(c);

        if (c->state == TOFU_DISABLED)
                return;

        /* tofu_commit() is always called while enrolling, but if it weren't, nothing was written */
        if (c->state == TOFU_ENROLLING)
                c->state = TOFU_INCOMPLETE;

        (void) efivar_set_str16(MAKE_GUID_PTR(LOADER), u"StubTofuState", tofu_state_table[c->state], 0);

        /* Like LoaderEntries, a list of NUL terminated strings. Not set if no addon was trusted. */
        if (c->accepted_size > 0)
                (void) efivar_set_raw(MAKE_GUID_PTR(LOADER), u"StubTofuAddons", c->accepted, c->accepted_size, 0);
}
