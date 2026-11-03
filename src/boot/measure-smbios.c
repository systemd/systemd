/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi-efivars.h"
#include "efi-log.h"
#include "measure.h"
#include "measure-smbios.h"
#include "smbios.h"
#include "tpm2-pcr.h"
#include "util.h"

typedef struct MeasureSmbiosContext {
        bool measured; /* At least one structure was measured */
        bool failed;   /* At least one measurement failed */
} MeasureSmbiosContext;

static void measure_smbios_raw(
                const void *p,
                size_t size,
                uint32_t event_id,
                const char16_t *description,
                MeasureSmbiosContext *ctx) {

        EFI_STATUS err;
        bool m = false;

        assert(p);
        assert(description);
        assert(ctx);

        err = tpm_log_tagged_event(
                        TPM2_PCR_PLATFORM_CONFIG,
                        POINTER_TO_PHYSICAL_ADDRESS(p),
                        size,
                        event_id,
                        description,
                        &m);
        if (err != EFI_SUCCESS) {
                log_error_status(err, "Unable to measure SMBIOS structure (%ls): %m", description);
                ctx->failed = true;
                return;
        }

        ctx->measured = ctx->measured || m;
}

static void measure_smbios_type1(const SmbiosHeader *header, size_t size, MeasureSmbiosContext *ctx) {
        assert(header);
        assert(ctx);

        /* The wake-up type field varies depending on how the machine was powered on (cold boot, resume
         * from sleep, AC restore, …), which would make the measurement non-reproducible. Hence measure a
         * copy with that field zeroed out.
         *
         * Whether the field is present is governed by the formatted-area length header->length (as in
         * get_smbios_table()), not the total size which also covers the trailing string set. If the
         * formatted area is too short to reach it (e.g. a legacy SMBIOS 2.0 record), there's nothing to
         * normalize, so measure the structure as-is. This length comes from the (untrusted) firmware
         * SMBIOS table and assert() is a no-op in release sd-boot builds, so it must be checked here
         * before the copy is written to at a fixed offset. */

        _cleanup_free_ SmbiosTableType1 *copy = NULL;
        const void *p = header;

        if (header->length > offsetof(SmbiosTableType1, wake_up_type)) {
                copy = xmemdup(header, size);
                memzero((uint8_t*) copy + offsetof(SmbiosTableType1, wake_up_type),
                        MIN(sizeof_field(SmbiosTableType1, wake_up_type),
                            header->length - offsetof(SmbiosTableType1, wake_up_type)));
                p = copy;
        }

        measure_smbios_raw(p, size, SMBIOS_TYPE1_EVENT_TAG_ID, u"smbios:type1", ctx);
}

static bool measure_smbios_object(const SmbiosHeader *header, size_t size, void *userdata) {
        MeasureSmbiosContext *ctx = ASSERT_PTR(userdata);

        switch (header->type) {

        case 1: /* System Information */
                measure_smbios_type1(header, size, ctx);
                break;

        case 2: /* Baseboard Information */
                measure_smbios_raw(header, size, SMBIOS_TYPE2_EVENT_TAG_ID, u"smbios:type2", ctx);
                break;

        case 11: /* OEM Strings */
                measure_smbios_raw(header, size, SMBIOS_TYPE11_EVENT_TAG_ID, u"smbios:type11", ctx);
                break;

        default:
                break;
        }

        return true; /* Keep iterating: there may be more than one matching structure (e.g. type 11). */
}

void measure_smbios(void) {
        MeasureSmbiosContext ctx = {};

        if (!runtime_measurement_available())
                return;

        /* If the measurement was already done this boot (e.g. by sd-boot before it chainloaded us), don't
         * do it again — re-extending PCR 1 would invalidate the value. */
        if (efivar_get_raw(MAKE_GUID_PTR(LOADER), u"LoaderPcrSMBIOS", /* ret_data= */ NULL, /* ret_size= */ NULL) == EFI_SUCCESS)
                return;

        /* Measure SMBIOS type 1 (system information), type 2 (baseboard information) and type 11 (OEM
         * strings) into PCR 1, in a single pass over the SMBIOS table. */
        smbios_foreach(measure_smbios_object, &ctx);

        /* Tell the OS which PCR we used (and suppress a second pass), but only if every structure was measured. */
        if (ctx.measured && !ctx.failed)
                (void) efivar_set_uint64_str16(MAKE_GUID_PTR(LOADER), u"LoaderPcrSMBIOS", TPM2_PCR_PLATFORM_CONFIG, /* flags= */ 0);
}
