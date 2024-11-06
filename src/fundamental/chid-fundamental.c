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

#if SD_BOOT
#  include "util.h"
#else
#  include <byteswap.h>
#  include <string.h>
#  include <utf8.h>
#define strlen16 char16_strlen
#endif

#include "chid-fundamental.h"
#include "macro-fundamental.h"
#include "memory-util-fundamental.h"
#include "sha1-fundamental.h"

static void get_chid(const char16_t *const smbios_fields[static _CHID_SMBIOS_FIELDS_MAX], uint32_t mask, EFI_GUID *ret_chid) {
        assert(mask != 0);
        assert(ret_chid);
        const EFI_GUID namespace = { UINT32_C(0x12d8ff70), UINT16_C(0x7f4c), UINT16_C(0x7d4c), {} }; /* Swapped to BE */

        struct sha1_ctx ctx = {};
        sha1_init_ctx(&ctx);

        sha1_process_bytes(&namespace, sizeof(namespace), &ctx);

        for (unsigned i = 0; i < _CHID_SMBIOS_FIELDS_MAX; i++)
                if ((mask >> i) & 1) {
                        if (i > 0)
                                sha1_process_bytes(L"&", 2, &ctx);
                        sha1_process_bytes(smbios_fields[i], strlen16(smbios_fields[i]) * sizeof(char16_t), &ctx);
                }

        uint8_t hash[SHA1_DIGEST_SIZE];
        sha1_finish_ctx(&ctx, hash);

        assert_cc(sizeof(hash) >= sizeof(*ret_chid));
        memcpy(ret_chid, hash, sizeof(*ret_chid));

        /* Convert the resulting CHID back to little-endian: */
        ret_chid->Data1 = bswap_32(ret_chid->Data1);
        ret_chid->Data2 = bswap_16(ret_chid->Data2);
        ret_chid->Data3 = bswap_16(ret_chid->Data3);

        /* set specific bits according to RFC4122 Section 4.1.3 */
        ret_chid->Data3 = (ret_chid->Data3 & 0x0fff) | (5 << 12);
        ret_chid->Data4[0] = (ret_chid->Data4[0] & UINT8_C(0x3f)) | UINT8_C(0x80);
}

static const uint32_t chid_smbios_table[CHID_TYPES_MAX] = {
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

void chid_calculate(const char16_t *const smbios_fields[static _CHID_SMBIOS_FIELDS_MAX], EFI_GUID ret_chids[static CHID_TYPES_MAX]) {
        assert(smbios_fields);
        assert(ret_chids);

        for (size_t i = 0; i < CHID_TYPES_MAX; i++)
                if (chid_smbios_table[i] != 0)
                        get_chid(smbios_fields, chid_smbios_table[i], &ret_chids[i]);
                else
                        memzero(&ret_chids[i], sizeof(EFI_GUID));
}
