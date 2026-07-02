/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi-efivars.h"
#include "efi-log.h"
#include "measure.h"
#include "measure-smbios.h"
#include "smbios.h"
#include "tpm2-pcr.h"
#include "util.h"

static void measure_smbios_raw(
                const void *p,
                size_t size,
                uint32_t event_id,
                const char16_t *description,
                bool *measured) {

        EFI_STATUS err;
        bool m = false;

        assert(p);
        assert(description);
        assert(measured);

        err = tpm_log_tagged_event(
                        TPM2_PCR_PLATFORM_CONFIG,
                        POINTER_TO_PHYSICAL_ADDRESS(p),
                        size,
                        event_id,
                        description,
                        &m);
        if (err != EFI_SUCCESS)
                log_error_status(err, "Unable to measure SMBIOS structure (%ls), ignoring: %m", description);

        *measured = *measured || m;
}

static void measure_smbios_type1(const SmbiosHeader *header, size_t size, bool *measured) {
        assert(header);
        assert(measured);

        /* The wake-up type field varies depending on how the machine was powered on (cold boot, resume
         * from sleep, AC restore, …), which would make the measurement non-reproducible. Hence measure a
         * copy with that field zeroed out. */

        assert(size >= sizeof(SmbiosTableType1));

        _cleanup_free_ SmbiosTableType1 *copy = xmemdup(header, size);
        copy->wake_up_type = 0;

        measure_smbios_raw(copy, size, SMBIOS_TYPE1_EVENT_TAG_ID, u"smbios:type1", measured);
}

static bool measure_smbios_object(const SmbiosHeader *header, size_t size, void *userdata) {
        bool *measured = ASSERT_PTR(userdata);

        switch (header->type) {

        case 1: /* System Information */
                measure_smbios_type1(header, size, measured);
                break;

        case 2: /* Baseboard Information */
                measure_smbios_raw(header, size, SMBIOS_TYPE2_EVENT_TAG_ID, u"smbios:type2", measured);
                break;

        case 11: /* OEM Strings */
                measure_smbios_raw(header, size, SMBIOS_TYPE11_EVENT_TAG_ID, u"smbios:type11", measured);
                break;

        default:
                break;
        }

        return true; /* Keep iterating: there may be more than one matching structure (e.g. type 11). */
}

void measure_smbios(void) {
        bool measured = false;

        if (!runtime_measurement_available())
                return;

        /* If the measurement was already done this boot (e.g. by sd-boot before it chainloaded us), don't
         * do it again — re-extending PCR 1 would invalidate the value. */
        if (efivar_get_raw(MAKE_GUID_PTR(LOADER), u"LoaderPcrSMBIOS", /* ret_data= */ NULL, /* ret_size= */ NULL) == EFI_SUCCESS)
                return;

        /* Measure SMBIOS type 1 (system information), type 2 (baseboard information) and type 11 (OEM
         * strings) into PCR 1, in a single pass over the SMBIOS table. */
        smbios_foreach(measure_smbios_object, &measured);

        /* If we measured something, tell the OS which PCR we used (and suppress a second pass). */
        if (measured)
                (void) efivar_set_uint64_str16(MAKE_GUID_PTR(LOADER), u"LoaderPcrSMBIOS", TPM2_PCR_PLATFORM_CONFIG, /* flags= */ 0);
}
