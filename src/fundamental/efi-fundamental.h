/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

/* Matches EFI API definition of the same structure for userspace */
typedef struct {
        uint32_t Data1;
        uint16_t Data2;
        uint16_t Data3;
        uint8_t Data4[8];
} EFI_GUID;

#if !SD_BOOT
#  include <stdbool.h>
#  include <string.h>
static inline bool efi_guid_equal(const EFI_GUID *a, const EFI_GUID *b) {
        return memcmp(a, b, sizeof(EFI_GUID)) == 0;
}
#endif

typedef struct {
        EFI_GUID SignatureOwner;
        uint8_t	SignatureData[];
} EFI_SIGNATURE_DATA;

typedef struct {
        EFI_GUID SignatureType;
        uint32_t SignatureListSize;
        uint32_t SignatureHeaderSize;
        uint32_t SignatureSize;
        EFI_SIGNATURE_DATA Signatures[];
} EFI_SIGNATURE_LIST;

typedef struct {
        uint32_t dwLength;
        uint16_t wRevision;
        uint16_t wCertificateType;
        uint8_t bCertificate[];
} WIN_CERTIFICATE;

typedef struct {
        WIN_CERTIFICATE Hdr;
        EFI_GUID CertType;
        uint8_t CertData[];
} WIN_CERTIFICATE_UEFI_GUID;

typedef struct {
        uint16_t Year;
        uint8_t Month;
        uint8_t Day;
        uint8_t Hour;
        uint8_t Minute;
        uint8_t Second;
        uint8_t Pad1;
        uint32_t Nanosecond;
        int16_t TimeZone;
        uint8_t Daylight;
        uint8_t Pad2;
} EFI_TIME;

typedef struct {
        EFI_TIME TimeStamp;
        WIN_CERTIFICATE_UEFI_GUID AuthInfo;
} EFI_VARIABLE_AUTHENTICATION_2;

#define GUID_DEF(d1, d2, d3, d4_1, d4_2, d4_3, d4_4, d4_5, d4_6, d4_7, d4_8) \
    { d1, d2, d3, { d4_1, d4_2, d4_3, d4_4, d4_5, d4_6, d4_7, d4_8 } }

/* Creates a EFI_GUID pointer suitable for EFI APIs. Use of const allows the compiler to merge multiple
 * uses (although, currently compilers do that regardless). Most EFI APIs declare their EFI_GUID input
 * as non-const, but almost all of them are in fact const. */
#define MAKE_GUID_PTR(name) ((EFI_GUID *) &(const EFI_GUID) name##_GUID)

#define EFI_GLOBAL_VARIABLE \
        GUID_DEF(0x8be4df61, 0x93ca, 0x11d2, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c)
#define EFI_IMAGE_SECURITY_DATABASE_GUID \
        GUID_DEF(0xd719b2cb, 0x3d3a, 0x4596, 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f)

#define EFI_CERT_X509_GUID \
        GUID_DEF(0xa5c059a1, 0x94e4, 0x4aa7, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72)
#define EFI_CERT_TYPE_PKCS7_GUID \
        GUID_DEF(0x4aafd29d, 0x68df, 0x49ee, 0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7)
