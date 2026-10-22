/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "boot-secret.h"
#include "console.h"
#include "efi-efivars.h"
#include "efi-log.h"
#include "efi-string.h"
#include "secure-boot.h"
#include "tofu.h"
#include "util.h"

/* The vendor GUID of systemd's own EFI variables, i.e. FactoryResetRequest, see efivars.h in userspace */
#define SYSTEMD_GUID \
        GUID_DEF(0x8cf2644b, 0x4b0b, 0x428f, 0x93, 0x87, 0x6d, 0x87, 0x60, 0x50, 0xdc, 0x67)

#define TOFU_RECORD_MAGIC "TOFU"
#define TOFU_RECORD_VERSION UINT32_C(1)
#define TOFU_RECORD_ATTRIBUTES (EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_BOOTSERVICE_ACCESS)
#define TOFU_HASHES_MAX 64U
#define TOFU_PROMPT_TIMEOUT_SEC 30U

/* The on-disk (well, in-NVRAM) format of the record: a header, followed by the hashes of the add-ons that
 * were trusted on first use. The record is bound to the OS it was created for via a hash of the OS ID, so
 * that two OSes on the same system never consult each other's record. */
typedef struct TofuRecord {
        char magic[4];
        uint32_t version;
        uint8_t os_id_hash[SHA256_DIGEST_SIZE];
        uint32_t n_hashes;
        uint8_t hashes[];
} _packed_ TofuRecord;

void tofu_context_done(TofuContext *c) {
        assert(c);

        free(c->os_id);
        free(c->id);
        free(c->image_id);
        free(c->variable);
        free(c->hashes);
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

static EFI_STATUS read_record(TofuContext *c) {
        EFI_STATUS err;

        assert(c);
        assert(c->variable);

        _cleanup_free_ void *data = NULL;
        uint32_t attributes;
        size_t size = 0;
        err = efivar_get_raw_full(MAKE_GUID_PTR(LOADER), c->variable, &attributes, &data, &size);
        if (err != EFI_SUCCESS)
                return err;

        /* Remember how the variable is stored, so that a damaged one can be deleted with matching
         * attributes, as the UEFI spec requires. */
        c->record_attributes = attributes;

        /* The record must be inaccessible after ExitBootServices(), otherwise userspace could have created
         * it. If it is accessible, something else than us wrote it, hence ignore it. */
        if ((attributes & (EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_BOOTSERVICE_ACCESS|EFI_VARIABLE_RUNTIME_ACCESS)) !=
            TOFU_RECORD_ATTRIBUTES)
                return log_error_status(EFI_PROTOCOL_ERROR, "TOFU record EFI variable has unexpected attributes, ignoring.");

        if (size < sizeof(TofuRecord))
                return log_error_status(EFI_PROTOCOL_ERROR, "TOFU record EFI variable is too short, ignoring.");

        const TofuRecord *record = data;
        if (memcmp(record->magic, TOFU_RECORD_MAGIC, sizeof(record->magic)) != 0 ||
            record->version != TOFU_RECORD_VERSION)
                return log_error_status(EFI_PROTOCOL_ERROR, "TOFU record EFI variable has unexpected magic or version, ignoring.");

        if (record->n_hashes > TOFU_HASHES_MAX ||
            size != sizeof(TofuRecord) + (size_t) record->n_hashes * SHA256_DIGEST_SIZE)
                return log_error_status(EFI_PROTOCOL_ERROR, "TOFU record EFI variable has unexpected size, ignoring.");

        uint8_t os_id_hash[SHA256_DIGEST_SIZE];
        hash_os_id(c->os_id, os_id_hash);
        if (memcmp(record->os_id_hash, os_id_hash, sizeof(os_id_hash)) != 0)
                return log_error_status(EFI_PROTOCOL_ERROR, "TOFU record EFI variable belongs to a different OS, ignoring.");

        c->n_hashes = record->n_hashes;
        c->hashes = c->n_hashes > 0 ? xmemdup(record->hashes, c->n_hashes * SHA256_DIGEST_SIZE) : NULL;
        return EFI_SUCCESS;
}

static EFI_STATUS write_record(const TofuContext *c) {
        assert(c);
        assert(c->variable);
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

        /* userspace sets FactoryResetRequest to a JSON object carrying the ID= of the requesting OS in
         * osReleaseId and its IMAGE_ID= in osReleaseImageId, the latter only if the OS has one. We don't have
         * a JSON parser here, so check for the fields in a non-fancy way, it's our own format after
         * all. Mirror what userspace does with the request (see factory_reset_mode_efi_variable()): both
         * fields have to match what our .osrel says, a missing IMAGE_ID= included. */

        _cleanup_free_ char16_t *request = NULL;
        err = efivar_get_str16(MAKE_GUID_PTR(SYSTEMD), u"FactoryResetRequest", &request);
        if (err != EFI_SUCCESS)
                return false;

        if (!id) {
                log_error("Factory reset requested, but UKI lacks an ID= field in its .osrel section, not forgetting trusted add-ons.");
                return false;
        }

        _cleanup_free_ char16_t *id_needle = xasprintf("\"osReleaseId\":\"%s\"", id);
        _cleanup_free_ char16_t *image_id_needle = image_id ?
                xasprintf("\"osReleaseImageId\":\"%s\"", image_id) :
                xstrdup16(u"\"osReleaseImageId\":");

        bool id_matches = !!strstr16(request, id_needle),
                image_id_matches = image_id ?
                        !!strstr16(request, image_id_needle) :   /* ours must be in the request */
                        !strstr16(request, image_id_needle);     /* the request must not carry any */
        if (!id_matches || !image_id_matches) {
                log_error("Factory reset requested by a different OS, not forgetting trusted add-ons.");
                return false;
        }

        return true;
}

static bool prompt_forget(void) {
        EFI_STATUS err;

        printf("Factory reset requested: forget the add-ons trusted on first use?\n");

        for (unsigned left = TOFU_PROMPT_TIMEOUT_SEC; left > 0; left--) {
                printf("\rPress 'y' to forget them, any other key to keep them (keeping them in %us).", left);

                uint64_t key = 0;
                err = console_key_read(&key, /* timeout_usec= */ 1000 * 1000);
                if (err == EFI_TIMEOUT)
                        continue;
                if (err != EFI_SUCCESS) {
                        printf("\n");
                        return false;
                }

                printf("\n");
                return IN_SET(key, KEYPRESS(0, 0, 'y'), KEYPRESS(0, 0, 'Y'));
        }

        printf("\n");
        return false;
}

void tofu_setup(
                TofuContext *c,
                const char *profile,
                size_t profile_size,
                const char *osrel,
                size_t osrel_size) {

        EFI_STATUS err;

        assert(c);

        *c = (TofuContext) {};

        if (!profile_enables_tofu(profile, profile_size))
                return;

        /* Without Secure Boot the firmware loads unsigned add-ons just fine, and we'd never see them. Don't
         * enrol in that case, as the record would be empty and close the enrolment window for good once
         * Secure Boot is turned on. */
        if (!secure_boot_enabled()) {
                log_debug("Secure Boot is disabled, not trusting add-ons on first use.");
                return;
        }

        c->enabled = true;
        c->os_id = osrel_pick_id(osrel, osrel_size);
        c->id = osrel_get(osrel, osrel_size, "ID");
        c->image_id = osrel_get(osrel, osrel_size, "IMAGE_ID");
        c->variable = xasprintf("StubTofuAddons-%s", c->os_id);

        err = read_record(c);
        if (err == EFI_NOT_FOUND) {
                log_debug("No TOFU record for OS '%s' yet, enrolling unsigned add-ons on this boot.", c->os_id);
                c->enrolling = true;
                return;
        }
        if (err != EFI_SUCCESS) {
                /* A damaged record is not a reason to trust anything, keep TOFU armed but don't enrol. It
                 * can still be forgotten via a factory reset below, so that enrolment is possible again. */
                log_error_status(err, "Failed to read TOFU record, not trusting any unsigned add-on: %m");
                c->damaged = true;
        } else
                log_debug("TOFU record for OS '%s' lists %zu add-ons.", c->os_id, c->n_hashes);

        if (factory_reset_requested(c->id, c->image_id) && prompt_forget()) {
                err = delete_record(c);
                if (err != EFI_SUCCESS) {
                        log_error_status(err, "Failed to delete TOFU record: %m");
                        c->damaged = true;
                        return;
                }

                /* Don't enrol again right away: the factory reset requested from userspace has not run yet,
                 * and the contents of the ESP are whatever the OS (or whoever controlled it) left behind.
                 * Trust nothing unsigned on this boot, the next boot finds no record and enrols afresh. */
                printf("Forgot %zu trusted add-on(s). Unsigned add-ons are ignored on this boot, and trusted on first use again on the next boot.\n", c->n_hashes);
                (void) console_key_read(/* ret_key= */ NULL, /* timeout_usec= */ 2 * 1000 * 1000);

                c->hashes = mfree(c->hashes);
                c->n_hashes = 0;
                c->forgotten = true;
                c->damaged = false;
        }
}

bool tofu_check(
                TofuContext *c,
                const void *buffer,
                size_t size,
                const char16_t *filename,
                uint8_t ret_hash[static SHA256_DIGEST_SIZE]) {

        assert(c);
        assert(buffer || size == 0);
        assert(filename);
        assert(ret_hash);

        if (!c->enabled)
                return false;

        sha256_direct(buffer, size, ret_hash);

        if (hash_is_recorded(c, ret_hash))
                return true;

        if (!c->enrolling) {
                log_error("Add-on '%ls' is not signed and not trusted on first use, ignoring.", filename);
                return false;
        }

        if (c->n_hashes >= TOFU_HASHES_MAX) {
                log_error("Too many unsigned add-ons to trust on first use, ignoring '%ls'.", filename);
                return false;
        }

        return true;
}

void tofu_accept(
                TofuContext *c,
                const uint8_t hash[static SHA256_DIGEST_SIZE],
                const char16_t *filename) {

        assert(c);
        assert(c->enabled);
        assert(hash);
        assert(filename);

        if (hash_is_recorded(c, hash))
                log_debug("Add-on '%ls' is not signed, but trusted on first use.", filename);
        else {
                assert(c->enrolling);
                assert(c->n_hashes < TOFU_HASHES_MAX);

                c->hashes = xrealloc(c->hashes, c->n_hashes * SHA256_DIGEST_SIZE, (c->n_hashes + 1) * SHA256_DIGEST_SIZE);
                memcpy(c->hashes + c->n_hashes * SHA256_DIGEST_SIZE, hash, SHA256_DIGEST_SIZE);
                c->n_hashes++;

                _cleanup_free_ char16_t *h = hexdump(hash, 8);
                printf("Trusting unsigned add-on '%ls' on first use (SHA256 %ls...).\n", filename, h);
        }

        _cleanup_free_ char16_t *tmp = TAKE_PTR(c->accepted);
        c->accepted = xasprintf("%ls%ls%ls", strempty(tmp), isempty(tmp) ? u"" : u" ", filename);
}

void tofu_finish(TofuContext *c) {
        EFI_STATUS err;

        assert(c);

        if (!c->enabled)
                return;

        const char16_t *state;
        if (c->forgotten)
                state = u"forgotten";
        else if (c->damaged)
                state = u"damaged";
        else if (!c->enrolling)
                state = u"verified";
        else if (c->scan_incomplete) {
                /* We could not look at all add-ons, hence we don't know what to trust yet. Leave the
                 * enrolment window open for a boot that can. */
                log_error("Could not enumerate all add-on directories, not writing TOFU record, enrolling again on next boot.");
                state = u"incomplete";
        } else {
                /* Write the record even if we found nothing to trust, so that the enrolment window is closed
                 * after the first boot with TOFU enabled, and nothing can be added later without a factory
                 * reset. */
                err = write_record(c);
                if (err != EFI_SUCCESS) {
                        log_error_status(err, "Failed to write TOFU record: %m");
                        state = u"incomplete";
                } else {
                        log_debug("Wrote TOFU record for OS '%s' with %zu add-ons.", c->os_id, c->n_hashes);
                        if (c->n_hashes > 0) /* give the user a chance to see what we trusted */
                                (void) console_key_read(/* ret_key= */ NULL, /* timeout_usec= */ 2 * 1000 * 1000);
                        state = u"enrolled";
                }
        }

        (void) efivar_set_str16(MAKE_GUID_PTR(LOADER), u"StubTofuState", state, 0);
        (void) efivar_set_str16(MAKE_GUID_PTR(LOADER), u"StubTofuAddons", strempty(c->accepted), 0);
}
