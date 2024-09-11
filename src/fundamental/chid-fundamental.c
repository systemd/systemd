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
#  include "efi-string.h"
#else
#  include <string.h>
#  include <uchar.h>

static inline size_t strlen16(const char16_t *s) {
        if (!s)
                return 0;

        size_t len = 0;
        while (*s) {
                s++;
                len++;
        }

        return len;
}

#endif

#include "macro-fundamental.h"
#include "chid-fundamental.h"
#include "sha1-fundamental.h"

static void get_chid(SmbiosInfo *info, uint32_t mask, Uuid *ret_chid) {
        assert(mask);
        assert(ret_chid);
        uint8_t hash[SHA1_DIGEST_SIZE] = {};
        const Uuid namespace = { 0x12d8ff70, 0x7f4c, 0x7d4c, {} }; /* Swapped to BE */

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
        ret_chid->data1 = bswap_32(ret_chid->data1);
        ret_chid->data2 = bswap_16(ret_chid->data2);
        ret_chid->data3 = bswap_16(ret_chid->data3);

        /* set specific bits according to RFC4122 Section 4.1.3 */
        ret_chid->data3 = (ret_chid->data3 & 0x0fff) | (5 << 12);
        ret_chid->data4[0] = (ret_chid->data4[0] & 0x3f) | 0x80;
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

void hwid_calculate(SmbiosInfo *info, Uuid ret_hwids[static 15]) {
        for (size_t i = 0; i < ELEMENTSOF(chid_smbios_table); i++)
                if (chid_smbios_table[i] != 0)
                        get_chid(info, chid_smbios_table[i], &ret_hwids[i]);
}
