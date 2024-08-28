/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2024 Nikita Travkin <nikita@trvn.ru> */

/*
 * Based on Linaro dtbloader implementation.
 * Copyright (c) 2019, Linaro. All rights reserved.
 *
 * https://github.com/aarch64-laptops/edk2/blob/dtbloader-app/EmbeddedPkg/Application/ConfigTableLoader/CHID.c
 */

#include <stdbool.h>
#include <stdarg.h>

#include "efi.h"
#include "util.h"
#include "vmm.h"
#include "chid.h"
#include "proto/Hash2.h"

/**
 * hash_strings() - Hash a list of strings after concatenating them.
 * @alg:      Algorighm to use from HASH_PROTOCOL.
 * @hash:     Pointer to the result buffer.
 * @seed:     Arbitrary data to prepend to payload.
 * @seed_len: Size of seed.
 * @count:    Amount of strings.
 * @...:  One or more char16_t strings to use as message.
 */
static EFI_STATUS hash_strings_sha1(EFI_SHA1_HASH2 *hash, uint8_t *seed, int seed_len, int count, ...)
{
        EFI_GUID alg = EFI_HASH_ALGORITHM_SHA1_GUID;
        EFI_GUID EfiHash2ProtocolGuid = EFI_HASH2_PROTOCOL_GUID;
        EFI_STATUS status;
        EFI_HASH2_PROTOCOL *prot;
        va_list args;
        size_t len;
        uint8_t *str;
        int i;

        status = BS->LocateProtocol(&EfiHash2ProtocolGuid, NULL, (void**)&prot);
        if (EFI_STATUS_IS_ERROR(status))
                return status;

        status = prot->HashInit(prot, &alg);
        if (EFI_STATUS_IS_ERROR(status))
                goto exit;

        if (seed) {
                str = (uint8_t*)seed;
                status = prot->HashUpdate(prot, str, seed_len);
                if (EFI_STATUS_IS_ERROR(status))
                        goto exit;
        }

        va_start(args, count);

        for (i = 0; i < count; ++i) {
                str = va_arg(args, uint8_t*);
                len = StrLen((char16_t*)str) * sizeof(char16_t);

                if (len == 0)
                        continue;

                status = prot->HashUpdate(prot, str, len);
                if (EFI_STATUS_IS_ERROR(status))
                        goto exit;
        }

        status = prot->HashFinal(prot, (EFI_HASH2_OUTPUT*)hash);
        if (EFI_STATUS_IS_ERROR(status))
                goto exit;

        status = EFI_SUCCESS;

exit:
        va_end(args);
        return status;
}

struct smbios_info {
        char16_t *Manufacturer;
        char16_t *ProductName;
        char16_t *ProductSku;
        char16_t *Family;
        char16_t *BaseboardProduct;
        char16_t *BaseboardManufacturer;
};

/**
 * smbios_to_hashable_string() - Convert ascii smbios string to stripped char16_t.
 */
static char16_t *smbios_to_hashable_string(char *str)
{
        int len, i;
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

        len = strlen8(str);

        while (len && str[len-1] == ' ')
                len--;

        ret = xcalloc((len+1) * sizeof(*ret));
        if (!ret)
                return NULL;

        for (i = 0; i < len; ++i)
                ret[i] = str[i];

        return ret;
}

static EFI_STATUS populate_smbios_info(struct smbios_info *info)
{
        struct raw_smbios_info raw;
        EFI_STATUS status;

        status = smbios_populate_raw_info(&raw);
        if (EFI_STATUS_IS_ERROR(status))
                return status;

        info->Manufacturer = smbios_to_hashable_string(raw.Manufacturer);
        info->ProductName = smbios_to_hashable_string(raw.ProductName);
        info->ProductSku = smbios_to_hashable_string(raw.ProductSku);
        info->Family = smbios_to_hashable_string(raw.Family);
        info->BaseboardProduct = smbios_to_hashable_string(raw.BaseboardProduct);
        info->BaseboardManufacturer = smbios_to_hashable_string(raw.BaseboardManufacturer);

        return EFI_SUCCESS;
}

static void free_smbios_info(struct smbios_info *info)
{
        if (info->Manufacturer)
                free(info->Manufacturer);
        if (info->ProductName)
                free(info->ProductName);
        if (info->ProductSku)
                free(info->ProductSku);
        if (info->Family)
                free(info->Family);
        if (info->BaseboardProduct)
                free(info->BaseboardProduct);
        if (info->BaseboardManufacturer)
                free(info->BaseboardManufacturer);
}

static EFI_STATUS get_chid(struct smbios_info *info, int id, EFI_GUID *chid)
{
        EFI_STATUS status;
        EFI_GUID namespace = { 0x12d8ff70, 0x7f4c, 0x7d4c, { 0 } }; /* Swapped to BE */
        EFI_SHA1_HASH2 hash = {0};

        switch (id) {
        case 3:
                status = hash_strings_sha1(&hash, (uint8_t*)&namespace, sizeof(namespace), 11,
                                info->Manufacturer, L"&",
                                info->Family, L"&",
                                info->ProductName, L"&",
                                info->ProductSku, L"&",
                                info->BaseboardManufacturer, L"&",
                                info->BaseboardProduct);
                break;
        case 4:
                status = hash_strings_sha1(&hash, (uint8_t*)&namespace, sizeof(namespace), 7,
                                info->Manufacturer, L"&",
                                info->Family, L"&",
                                info->ProductName, L"&",
                                info->ProductSku);
                break;
        case 5:
                status = hash_strings_sha1(&hash, (uint8_t*)&namespace, sizeof(namespace), 5,
                                info->Manufacturer, L"&",
                                info->Family, L"&",
                                info->ProductName);
                break;
        case 6:
                status = hash_strings_sha1(&hash, (uint8_t*)&namespace, sizeof(namespace), 7,
                                info->Manufacturer, L"&",
                                info->ProductSku, L"&",
                                info->BaseboardManufacturer, L"&",
                                info->BaseboardProduct);
                break;
        case 7:
                status = hash_strings_sha1(&hash, (uint8_t*)&namespace, sizeof(namespace), 3,
                                info->Manufacturer, L"&",
                                info->ProductSku);
                break;
        case 8:
                status = hash_strings_sha1(&hash, (uint8_t*)&namespace, sizeof(namespace), 7,
                                info->Manufacturer, L"&",
                                info->ProductName, L"&",
                                info->BaseboardManufacturer, L"&",
                                info->BaseboardProduct);
                break;
        case 9:
                status = hash_strings_sha1(&hash, (uint8_t*)&namespace, sizeof(namespace), 3,
                                info->Manufacturer, L"&",
                                info->ProductName);
                break;
        case 10:
                status = hash_strings_sha1(&hash, (uint8_t*)&namespace, sizeof(namespace), 7,
                                info->Manufacturer, L"&",
                                info->Family, L"&",
                                info->BaseboardManufacturer, L"&",
                                info->BaseboardProduct);
                break;
        case 11:
                status = hash_strings_sha1(&hash, (uint8_t*)&namespace, sizeof(namespace), 3,
                                info->Manufacturer, L"&",
                                info->Family);
                break;
        case 13:
                status = hash_strings_sha1(&hash, (uint8_t*)&namespace, sizeof(namespace), 5,
                                info->Manufacturer, L"&",
                                info->BaseboardManufacturer, L"&",
                                info->BaseboardProduct);
                break;
        case 14:
                status = hash_strings_sha1(&hash, (uint8_t*)&namespace, sizeof(namespace), 1,
                                info->Manufacturer);
                break;
        default:
                return EFI_SUCCESS; /* Just keep empty to prevent match. */
        }
        if (EFI_STATUS_IS_ERROR(status))
                return status;

        memcpy(chid, hash, sizeof(*chid));

        /* Convert the resulting CHID back to little-endian: */
        chid->Data1 = __builtin_bswap32(chid->Data1);
        chid->Data2 = __builtin_bswap16(chid->Data2);
        chid->Data3 = __builtin_bswap16(chid->Data3);

        /* set specific bits according to RFC4122 Section 4.1.3 */
        chid->Data3    = (chid->Data3 & 0x0fff) | (5 << 12);
        chid->Data4[0] = (chid->Data4[0] & 0x3f) | 0x80;

        return EFI_SUCCESS;
}

/**
 * populate_board_hwids() - Read board SMBIOS and produce an array of CHID values.
 * @hwids:  Pointer to an array of 12 chids to be filled.
 */
static EFI_STATUS populate_board_hwids(EFI_GUID *hwids)
{
        EFI_STATUS status;
        struct smbios_info info;
        int i;

        if (!hwids)
                return EFI_INVALID_PARAMETER;

        status = populate_smbios_info(&info);
        if (EFI_STATUS_IS_ERROR(status))
                return status;

        for (i = 0; i < 15; ++i) {
                status = get_chid(&info, i, &hwids[i]);
                if (EFI_STATUS_IS_ERROR(status))
                        goto exit;
        }

exit:
        free_smbios_info(&info);
        return status;
}

#include "chipid-devices.h"
#include "devicetree.h"

EFI_STATUS hwid_match(const void *dtb_buffer, size_t dtb_length) {
        EFI_STATUS status;
        
        static struct device *cached_dev = NULL;
        EFI_GUID hwids[15] = {0};
        int priority[] = {3, 6, 8, 10, 4, 5 , 7, 9, 11}; /* From most to least specific. */
            
        if (cached_dev != NULL) {
                return devicetree_match_by_compatible(dtb_buffer, dtb_length, cached_dev->Compatible);
        }


        status = populate_board_hwids(hwids);
        if (EFI_STATUS_IS_ERROR(status)) {
                log_error_status(status, "failed to populate board hwids");
                return status;
        }

        for (size_t i = 0; i < ARRAY_SIZE(priority); i++) {
                for (size_t d = 0; d < ARRAY_SIZE(devices); d++) {
                        for (size_t j = 0; j < ARRAY_SIZE(devices[d].Ids) && devices[d].Ids[j].Data1; j++) {
                                if (efi_guid_equal(&hwids[priority[i]], devices[d].Ids[j])) {
                                        cached_dev = &devices[d];
                                        return devicetree_match_by_compatible(dtb_buffer, dtb_length, devices[d].Compatible);
                                }
                        }
                }
        }

        return EFI_NOT_FOUND;
}
