/* SPDX-License-Identifier: BSD-3-Clause */

/*
 * Based on Nikita Travkin's dtbloader implementation.
 * Copyright (c) 2024 Nikita Travkin <nikita@trvn.ru>
 *
 * https://github.com/TravMurav/dtbloader/blob/main/src/chid.c
 */

/*
 * Based on Linaro dtbloader implementation.
 * Copyright (c) 2019, Linaro. All rights reserved.
 *
 * https://github.com/aarch64-laptops/edk2/blob/dtbloader-app/EmbeddedPkg/Application/ConfigTableLoader/CHID.c
 */

#include "chid.h"
#include "chid-fundamental.h"
#include "efi.h"
#include "sha1-fundamental.h"
#include "smbios.h"
#include "util.h"

/**
 * smbios_to_hashable_string() - Convert ascii smbios string to stripped char16_t.
 */
static char16_t *smbios_to_hashable_string(const char *str) {
        char16_t *ret;

        if (!str) {
                /* User of this function is expected to free the result. */
                ret = xcalloc(sizeof(*ret));
                return ret;
        }

        /*
         * We need to strip leading and trailing spaces, leading zeroes.
         * See fwupd/libfwupdplugin/fu-hwids-smbios.c
         */
        while (*str == ' ')
                str++;

        while (*str == '0')
                str++;

        size_t len = strlen8(str);

        while (len && str[len - 1] == ' ')
                len--;

        ret = xcalloc_multiply(len + 1, sizeof(*ret));
        if (!ret)
                return NULL;

        for (size_t i = 0; i < len; i++)
                ret[i] = str[i];

        return ret;
}

static void smbios_info_populate(SmbiosInfo *ret_info) {
        RawSmbiosInfo raw;
        smbios_raw_info_populate(&raw);

        ret_info->str[CHID_SMBIOS_MANUFACTURER] = smbios_to_hashable_string(raw.manufacturer);
        ret_info->str[CHID_SMBIOS_PRODUCT_NAME] = smbios_to_hashable_string(raw.product_name);
        ret_info->str[CHID_SMBIOS_PRODUCT_SKU] = smbios_to_hashable_string(raw.product_sku);
        ret_info->str[CHID_SMBIOS_FAMILY] = smbios_to_hashable_string(raw.family);
        ret_info->str[CHID_SMBIOS_BASEBOARD_PRODUCT] = smbios_to_hashable_string(raw.baseboard_product);
        ret_info->str[CHID_SMBIOS_BASEBOARD_MANUFACTURER] = smbios_to_hashable_string(raw.baseboard_manufacturer);
}

static void smbios_info_done(SmbiosInfo *info) {
        FOREACH_ELEMENT(i, info->str)
                *i = mfree(*i);
}

static EFI_STATUS populate_board_hwids(Uuid ret_hwids[static 15]) {
        _cleanup_(smbios_info_done) SmbiosInfo info = {};

        if (!ret_hwids)
                return EFI_INVALID_PARAMETER;

        smbios_info_populate(&info);
        hwid_calculate(&info, ret_hwids);

        return EFI_SUCCESS;
}

EFI_STATUS hwid_match(const void *hwids_buffer, size_t hwids_length, const Device **ret_device) {
        EFI_STATUS status;

        const Device *devices = hwids_buffer;
        size_t n_devices = hwids_length / sizeof(*devices);

        assert(hwids_length % sizeof(*devices) == 0);
        assert(n_devices > 0);
        assert(devices);

        Uuid hwids[15] = {};
        static const int priority[] = { 3, 6, 8, 10, 4, 5, 7, 9, 11 }; /* From most to least specific. */

        status = populate_board_hwids(hwids);
        if (EFI_STATUS_IS_ERROR(status)) {
                log_error_status(status, "failed to populate board HWIDs");
                return status;
        }

        FOREACH_ELEMENT(i, priority) {
                FOREACH_ARRAY(dev, devices, n_devices)
                        for (size_t j = 0; j < ELEMENTSOF(dev->hwids) && dev->hwids[j].data1; j++)
                                if (memcmp(&hwids[*i], &dev->hwids[j], sizeof(Uuid)) == 0) {
                                        *ret_device = dev;
                                        return EFI_SUCCESS;
                                }
        }

        return EFI_NOT_FOUND;
}
