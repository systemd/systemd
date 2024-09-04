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
#include "proto/Hash2.h"
#include "util.h"
#include "vmm.h"

/**
 * hash_strings() - Hash a list of strings after concatenating them.
 * @alg:      Algorighm to use from HASH_PROTOCOL.
 * @hash:     Pointer to the result buffer.
 * @seed:     Arbitrary data to prepend to payload.
 * @seed_len: Size of seed.
 * @count:    Amount of strings.
 * @...:  One or more char16_t strings to use as message.
 */
static EFI_STATUS hash_strings_sha1(EFI_SHA1_HASH2 *hash, uint8_t *seed, int seed_len, int count, ...) {
        EFI_GUID alg = EFI_HASH_ALGORITHM_SHA1_GUID;
        EFI_GUID EfiHash2ProtocolGuid = EFI_HASH2_PROTOCOL_GUID;
        EFI_STATUS status;
        EFI_HASH2_PROTOCOL *prot;
        va_list args;
        size_t len;
        uint8_t *str;
        int i;

        status = BS->LocateProtocol(&EfiHash2ProtocolGuid, NULL, (void **) &prot);
        if (EFI_STATUS_IS_ERROR(status))
                return status;

        status = prot->HashInit(prot, &alg);
        if (EFI_STATUS_IS_ERROR(status))
                goto exit;

        if (seed) {
                str = (uint8_t *) seed;
                status = prot->HashUpdate(prot, str, seed_len);
                if (EFI_STATUS_IS_ERROR(status))
                        goto exit;
        }

        va_start(args, count);

        for (i = 0; i < count; ++i) {
                str = va_arg(args, uint8_t *);
                len = strlen16((char16_t *) str) * sizeof(char16_t);

                if (len == 0)
                        continue;

                status = prot->HashUpdate(prot, str, len);
                if (EFI_STATUS_IS_ERROR(status))
                        goto exit;
        }

        status = prot->HashFinal(prot, (EFI_HASH2_OUTPUT *) hash);
        if (EFI_STATUS_IS_ERROR(status))
                goto exit;

        status = EFI_SUCCESS;

exit:
        va_end(args);
        return status;
}

typedef struct SmbiosInfo {
        char16_t *manufacturer;
        char16_t *product_name;
        char16_t *product_sku;
        char16_t *family;
        char16_t *baseboard_product;
        char16_t *baseboard_manufacturer;
} SmbiosInfo;

/**
 * smbios_to_hashable_string() - Convert ascii smbios string to stripped char16_t.
 */
static char16_t *smbios_to_hashable_string(const char *str) {
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

        while (len && str[len - 1] == ' ')
                len--;

        ret = xcalloc((len + 1) * sizeof(*ret));
        if (!ret)
                return NULL;

        for (i = 0; i < len; ++i)
                ret[i] = str[i];

        return ret;
}

static EFI_STATUS populate_smbios_info(SmbiosInfo *info) {
        RawSmbiosInfo raw;
        EFI_STATUS status;

        status = smbios_raw_info_populate(&raw);
        if (EFI_STATUS_IS_ERROR(status))
                return status;

        info->manufacturer = smbios_to_hashable_string(raw.manufacturer);
        info->product_name = smbios_to_hashable_string(raw.product_name);
        info->product_sku = smbios_to_hashable_string(raw.product_sku);
        info->family = smbios_to_hashable_string(raw.family);
        info->baseboard_product = smbios_to_hashable_string(raw.baseboard_product);
        info->baseboard_manufacturer = smbios_to_hashable_string(raw.baseboard_manufacturer);

        return EFI_SUCCESS;
}

static void smbios_info_clear(SmbiosInfo *info) {
        info->manufacturer = mfree(info->manufacturer);
        info->product_name = mfree(info->product_name);
        info->product_sku = mfree(info->product_sku);
        info->family = mfree(info->family);
        info->baseboard_product = mfree(info->baseboard_product);
        info->baseboard_manufacturer = mfree(info->baseboard_manufacturer);
}

static EFI_STATUS get_chid(SmbiosInfo *info, int id, EFI_GUID *chid) {
        EFI_STATUS status;
        EFI_GUID namespace = { 0x12d8ff70, 0x7f4c, 0x7d4c, { 0 } }; /* Swapped to BE */
        EFI_SHA1_HASH2 hash = { 0 };

        switch (id) {
        case 3:
                status = hash_strings_sha1(
                                &hash,
                                (uint8_t *) &namespace,
                                sizeof(namespace),
                                11,
                                info->manufacturer,
                                L"&",
                                info->family,
                                L"&",
                                info->product_name,
                                L"&",
                                info->product_sku,
                                L"&",
                                info->baseboard_manufacturer,
                                L"&",
                                info->baseboard_product);
                break;
        case 4:
                status = hash_strings_sha1(
                                &hash,
                                (uint8_t *) &namespace,
                                sizeof(namespace),
                                7,
                                info->manufacturer,
                                L"&",
                                info->family,
                                L"&",
                                info->product_name,
                                L"&",
                                info->product_sku);
                break;
        case 5:
                status = hash_strings_sha1(
                                &hash,
                                (uint8_t *) &namespace,
                                sizeof(namespace),
                                5,
                                info->manufacturer,
                                L"&",
                                info->family,
                                L"&",
                                info->product_name);
                break;
        case 6:
                status = hash_strings_sha1(
                                &hash,
                                (uint8_t *) &namespace,
                                sizeof(namespace),
                                7,
                                info->manufacturer,
                                L"&",
                                info->product_sku,
                                L"&",
                                info->baseboard_manufacturer,
                                L"&",
                                info->baseboard_product);
                break;
        case 7:
                status = hash_strings_sha1(
                                &hash,
                                (uint8_t *) &namespace,
                                sizeof(namespace),
                                3,
                                info->manufacturer,
                                L"&",
                                info->product_sku);
                break;
        case 8:
                status = hash_strings_sha1(
                                &hash,
                                (uint8_t *) &namespace,
                                sizeof(namespace),
                                7,
                                info->manufacturer,
                                L"&",
                                info->product_name,
                                L"&",
                                info->baseboard_manufacturer,
                                L"&",
                                info->baseboard_product);
                break;
        case 9:
                status = hash_strings_sha1(
                                &hash,
                                (uint8_t *) &namespace,
                                sizeof(namespace),
                                3,
                                info->manufacturer,
                                L"&",
                                info->product_name);
                break;
        case 10:
                status = hash_strings_sha1(
                                &hash,
                                (uint8_t *) &namespace,
                                sizeof(namespace),
                                7,
                                info->manufacturer,
                                L"&",
                                info->family,
                                L"&",
                                info->baseboard_manufacturer,
                                L"&",
                                info->baseboard_product);
                break;
        case 11:
                status = hash_strings_sha1(
                                &hash,
                                (uint8_t *) &namespace,
                                sizeof(namespace),
                                3,
                                info->manufacturer,
                                L"&",
                                info->family);
                break;
        case 13:
                status = hash_strings_sha1(
                                &hash,
                                (uint8_t *) &namespace,
                                sizeof(namespace),
                                5,
                                info->manufacturer,
                                L"&",
                                info->baseboard_manufacturer,
                                L"&",
                                info->baseboard_product);
                break;
        case 14:
                status = hash_strings_sha1(
                                &hash, (uint8_t *) &namespace, sizeof(namespace), 1, info->manufacturer);
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
        chid->Data3 = (chid->Data3 & 0x0fff) | (5 << 12);
        chid->Data4[0] = (chid->Data4[0] & 0x3f) | 0x80;

        return EFI_SUCCESS;
}

/**
 * populate_board_hwids() - Read board SMBIOS and produce an array of CHID values.
 * @hwids:  Pointer to an array of 12 chids to be filled.
 */
static EFI_STATUS populate_board_hwids(EFI_GUID *hwids) {
        EFI_STATUS status;
        _cleanup_(smbios_info_clear) SmbiosInfo info;
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
        return status;
}

typedef Device {
        const char16_t name[128];
        const char compatible[128];
        EFI_GUID hwids[32];
} Device;

EFI_STATUS hwid_match(const void *hwids_buffer, size_t hwids_length, const char **compatible) {
        EFI_STATUS status;

        const Device *devices = hwids_buffer;
        size_t n_devices = hwids_length / sizeof(*devices);

        assert(hwids_length % sizeof(*devices) == 0);
        assert(n_devices > 0);
        assert(devices);

        static const Device *cached_devices = NULL;
        static size_t cached_index = 0;

        EFI_GUID hwids[15] = { 0 };
        int priority[] = { 3, 6, 8, 10, 4, 5, 7, 9, 11 }; /* From most to least specific. */

        if (cached_devices == devices) {
                // TODO: Print device name somehow?
                *compatible = cached_devices[cached_index].compatible;
                return EFI_SUCCESS;
        }

        cached_devices = devices;

        status = populate_board_hwids(hwids);
        if (EFI_STATUS_IS_ERROR(status)) {
                log_error_status(status, "failed to populate board hwids");
                return status;
        }

        for (size_t i = 0; i < ELEMENTSOF(priority); i++) {
                for (size_t d = 0; d < n_devices; d++) {
                        const Device *dev = &devices[d];
                        for (size_t j = 0; j < ELEMENTSOF(dev->hwids) && dev->hwids[j].Data1; j++) {
                                if (efi_guid_equal(&hwids[priority[i]], &dev->hwids[j])) {
                                        cached_index = d;
                                        // TODO: Print device name somehow?
                                        *compatible = cached_devices[cached_index].compatible;
                                        return EFI_SUCCESS;
                                }
                        }
                }
        }

        return EFI_NOT_FOUND;
}
