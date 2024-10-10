/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once


#if !SD_BOOT
#  include <stdint.h>
typedef struct {
        uint32_t Data1;
        uint16_t Data2;
        uint16_t Data3;
        uint8_t Data4[8];
} EFI_GUID;
#endif
