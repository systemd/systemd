/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2024 Nikita Travkin <nikita@trvn.ru> */

/*
 * Based on Linaro dtbloader implementation.
 * Copyright (c) 2019, Linaro. All rights reserved.
 *
 * https://github.com/aarch64-laptops/edk2/blob/dtbloader-app/EmbeddedPkg/Application/ConfigTableLoader/CHID.c
 */

#include "chid.h"
#include "efi.h"
#include "sha1-fundamental.h"
#include "smbios.h"
#include "util.h"

typedef enum ChidSmbiosFields {
        CHID_SMBIOS_MANUFACTURER,
        CHID_SMBIOS_FAMILY,
        CHID_SMBIOS_PRODUCT_NAME,
        CHID_SMBIOS_PRODUCT_SKU,
        CHID_SMBIOS_BASEBOARD_MANUFACTURER,
        CHID_SMBIOS_BASEBOARD_PRODUCT,
        CHID_SMBIOS_COUNT,
} ChidSmbiosFields;

typedef struct SmbiosInfo {
        char16_t *str[CHID_SMBIOS_COUNT];
} SmbiosInfo;

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

        log_error_status(EFI_SUCCESS, "Manufacturer: %s", raw.manufacturer);
        log_error_status(EFI_SUCCESS, "ProductName: %s", raw.product_name);
        log_error_status(EFI_SUCCESS, "ProductSKU: %s", raw.product_sku);
        log_error_status(EFI_SUCCESS, "Family: %s", raw.family);
        log_error_status(EFI_SUCCESS, "BaseboardProduct: %s", raw.baseboard_product);
        log_error_status(EFI_SUCCESS, "BaseboardManufacturer: %s", raw.baseboard_manufacturer);

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

static void get_chid(SmbiosInfo *info, uint32_t mask, EFI_GUID *ret_chid) {
        assert(mask);
        assert(ret_chid);
        uint8_t hash[SHA1_DIGEST_SIZE] = {};
        EFI_GUID namespace = { 0x12d8ff70, 0x7f4c, 0x7d4c, {} }; /* Swapped to BE */

        struct sha1_ctx ctx = {};
        sha1_init_ctx(&ctx);

        sha1_process_bytes(&namespace, &ctx, sizeof(namespace));

        for (unsigned i = 0; i < CHID_SMBIOS_COUNT; i++)
                if ((mask >> i) & 1) {
                        if (i > 0)
                                sha1_process_bytes(L"&", &ctx, 2);
                        size_t len = strlen16(info->str[i]) * sizeof(*info->str[i]);
                        if (len > 0)
                                sha1_process_bytes(info->str[i], &ctx, len);
                }

        sha1_finish_ctx(&ctx, hash);

        assert_cc(sizeof(hash) >= sizeof(*ret_chid));
        memcpy(ret_chid, hash, sizeof(*ret_chid));

        /* Convert the resulting CHID back to little-endian: */
        ret_chid->Data1 = bswap_32(ret_chid->Data1);
        ret_chid->Data2 = bswap_16(ret_chid->Data2);
        ret_chid->Data3 = bswap_16(ret_chid->Data3);

        /* set specific bits according to RFC4122 Section 4.1.3 */
        ret_chid->Data3 = (ret_chid->Data3 & 0x0fff) | (5 << 12);
        ret_chid->Data4[0] = (ret_chid->Data4[0] & 0x3f) | 0x80;
}

static const uint32_t chid_smbios_table[15] = {
        [3] = (UINT32_C(1) << CHID_SMBIOS_MANUFACTURER) |
              (UINT32_C(1) << CHID_SMBIOS_FAMILY) |
              (UINT32_C(1) << CHID_SMBIOS_PRODUCT_NAME) |
              (UINT32_C(1) << CHID_SMBIOS_PRODUCT_SKU) |
              (UINT32_C(1) << CHID_SMBIOS_BASEBOARD_MANUFACTURER) |
              (UINT32_C(1) << CHID_SMBIOS_BASEBOARD_PRODUCT),

        [4] = (UINT32_C(1) << CHID_SMBIOS_MANUFACTURER) |
              (UINT32_C(1) << CHID_SMBIOS_FAMILY) |
              (UINT32_C(1) << CHID_SMBIOS_PRODUCT_NAME) |
              (UINT32_C(1) << CHID_SMBIOS_PRODUCT_SKU),

        [5] = (UINT32_C(1) << CHID_SMBIOS_MANUFACTURER) |
              (UINT32_C(1) << CHID_SMBIOS_FAMILY) |
              (UINT32_C(1) << CHID_SMBIOS_PRODUCT_NAME),

        [6] = (UINT32_C(1) << CHID_SMBIOS_MANUFACTURER) |
              (UINT32_C(1) << CHID_SMBIOS_PRODUCT_SKU) |
              (UINT32_C(1) << CHID_SMBIOS_BASEBOARD_MANUFACTURER) |
              (UINT32_C(1) << CHID_SMBIOS_BASEBOARD_PRODUCT),

        [7] = (UINT32_C(1) << CHID_SMBIOS_MANUFACTURER) |
              (UINT32_C(1) << CHID_SMBIOS_PRODUCT_SKU),

        [8] = (UINT32_C(1) << CHID_SMBIOS_MANUFACTURER) |
              (UINT32_C(1) << CHID_SMBIOS_PRODUCT_NAME) |
              (UINT32_C(1) << CHID_SMBIOS_BASEBOARD_MANUFACTURER) |
              (UINT32_C(1) << CHID_SMBIOS_BASEBOARD_PRODUCT),

        [9] = (UINT32_C(1) << CHID_SMBIOS_MANUFACTURER) |
              (UINT32_C(1) << CHID_SMBIOS_PRODUCT_NAME),

        [10] = (UINT32_C(1) << CHID_SMBIOS_MANUFACTURER) |
               (UINT32_C(1) << CHID_SMBIOS_FAMILY) |
               (UINT32_C(1) << CHID_SMBIOS_BASEBOARD_MANUFACTURER) |
               (UINT32_C(1) << CHID_SMBIOS_BASEBOARD_PRODUCT),

        [11] = (UINT32_C(1) << CHID_SMBIOS_MANUFACTURER) |
               (UINT32_C(1) << CHID_SMBIOS_FAMILY),

        [13] = (UINT32_C(1) << CHID_SMBIOS_MANUFACTURER) |
               (UINT32_C(1) << CHID_SMBIOS_BASEBOARD_MANUFACTURER) |
               (UINT32_C(1) << CHID_SMBIOS_BASEBOARD_PRODUCT),
};

/**
 * populate_board_hwids() - Read board SMBIOS and produce an array of CHID values as described in
 * https://github.com/fwupd/fwupd/blob/main/docs/hwids.md
 * @hwids:  Pointer to an array of chids to be filled.
 */
static EFI_STATUS populate_board_hwids(EFI_GUID ret_hwids[static 15]) {
        _cleanup_(smbios_info_done) SmbiosInfo info = {};

        if (!ret_hwids)
                return EFI_INVALID_PARAMETER;

        smbios_info_populate(&info);

        for (size_t i = 0; i < ELEMENTSOF(chid_smbios_table); i++)
                if (chid_smbios_table[i] != 0)
                        get_chid(&info, chid_smbios_table[i], &ret_hwids[i]);

        return EFI_SUCCESS;
}

EFI_STATUS hwid_match(const void *hwids_buffer, size_t hwids_length, const Device **ret_device) {
        EFI_STATUS status;

        const Device *devices = hwids_buffer;
        size_t n_devices = hwids_length / sizeof(*devices);

        assert(hwids_length % sizeof(*devices) == 0);
        assert(n_devices > 0);
        assert(devices);

        EFI_GUID hwids[15] = {};
        static const int priority[] = { 3, 6, 8, 10, 4, 5, 7, 9, 11 }; /* From most to least specific. */

        status = populate_board_hwids(hwids);
        if (EFI_STATUS_IS_ERROR(status)) {
                log_error_status(status, "failed to populate board HWIDs");
                return status;
        }

        FOREACH_ELEMENT(i, priority) {
                FOREACH_ARRAY(dev, devices, n_devices)
                        for (size_t j = 0; j < ELEMENTSOF(dev->hwids) && dev->hwids[j].Data1; j++)
                                if (efi_guid_equal(&hwids[*i], &dev->hwids[j])) {
                                        *ret_device = dev;
                                        return EFI_SUCCESS;
                                }
        }

        return EFI_NOT_FOUND;
}
