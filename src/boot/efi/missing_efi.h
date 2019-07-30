/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <efi.h>

#ifndef EFI_RNG_PROTOCOL_GUID

#define EFI_RNG_PROTOCOL_GUID                                           \
          { 0x3152bca5, 0xeade, 0x433d, {0x86, 0x2e, 0xc0, 0x1c, 0xdc, 0x29, 0x1f, 0x44} }

typedef EFI_GUID EFI_RNG_ALGORITHM;

#define EFI_RNG_ALGORITHM_SP800_90_HASH_256_GUID       \
     {0xa7af67cb, 0x603b, 0x4d42, {0xba, 0x21, 0x70, 0xbf, 0xb6, 0x29, 0x3f, 0x96} }

#define EFI_RNG_ALGORITHM_SP800_90_HMAC_256_GUID       \
     {0xc5149b43, 0xae85, 0x4f53, {0x99, 0x82, 0xb9, 0x43, 0x35, 0xd3, 0xa9, 0xe7} }

#define EFI_RNG_ALGORITHM_SP800_90_CTR_256_GUID        \
     {0x44f0de6e, 0x4d8c, 0x4045, {0xa8, 0xc7, 0x4d, 0xd1, 0x68, 0x85, 0x6b, 0x9e} }

#define EFI_RNG_ALGORITHM_X9_31_3DES_GUID              \
     {0x63c4785a, 0xca34, 0x4012, {0xa3, 0xc8, 0x0b, 0x6a, 0x32, 0x4f, 0x55, 0x46} }

#define EFI_RNG_ALGORITHM_X9_31_AES_GUID               \
     {0xacd03321, 0x777e, 0x4d3d, {0xb1, 0xc8, 0x20, 0xcf, 0xd8, 0x88, 0x20, 0xc9} }

#define EFI_RNG_ALGORITHM_RAW                          \
     {0xe43176d7, 0xb6e8, 0x4827, {0xb7, 0x84, 0x7f, 0xfd, 0xc4, 0xb6, 0x85, 0x61} }

INTERFACE_DECL(_EFI_RNG_PROTOCOL);

typedef
EFI_STATUS
(EFIAPI *EFI_RNG_GET_INFO) (
  IN      struct _EFI_RNG_PROTOCOL   *This,
  IN OUT  UINTN                      *RNGAlgorithmListSize,
  OUT     EFI_RNG_ALGORITHM          *RNGAlgorithmList
);

typedef
EFI_STATUS
(EFIAPI *EFI_RNG_GET_RNG) (
  IN      struct _EFI_RNG_PROTOCOL   *This,
  IN      EFI_RNG_ALGORITHM          *RNGAlgorithm,           OPTIONAL
  IN      UINTN                      RNGValueLength,
  OUT     UINT8                      *RNGValue
);

typedef struct _EFI_RNG_PROTOCOL {
          EFI_RNG_GET_INFO           GetInfo;
          EFI_RNG_GET_RNG            GetRNG;
} EFI_RNG_PROTOCOL;

#endif
