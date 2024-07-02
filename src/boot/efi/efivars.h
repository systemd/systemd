/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

/*
 * Allocated random UUID, intended to be shared across tools that implement
 * the (ESP)\loader\entries\<vendor>-<revision>.conf convention and the
 * associated EFI variables.
 */
#define LOADER_GUID \
        { 0x4a67b082, 0x0a4c, 0x41cf, { 0xb6, 0xc7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f } }

EFI_STATUS efivar_set_str16(const EFI_GUID *vendor, const char16_t *name, const char16_t *value, uint32_t flags);
EFI_STATUS efivar_set_raw(const EFI_GUID *vendor, const char16_t *name, const void *buf, size_t size, uint32_t flags);
EFI_STATUS efivar_set_uint64_str16(const EFI_GUID *vendor, const char16_t *name, uint64_t i, uint32_t flags);
EFI_STATUS efivar_set_uint32_le(const EFI_GUID *vendor, const char16_t *name, uint32_t value, uint32_t flags);
EFI_STATUS efivar_set_uint64_le(const EFI_GUID *vendor, const char16_t *name, uint64_t value, uint32_t flags);
void efivar_set_time_usec(const EFI_GUID *vendor, const char16_t *name, uint64_t usec);

EFI_STATUS efivar_unset(const EFI_GUID *vendor, const char16_t *name, uint32_t flags);

EFI_STATUS efivar_get_str16(const EFI_GUID *vendor, const char16_t *name, char16_t **ret);
EFI_STATUS efivar_get_raw(const EFI_GUID *vendor, const char16_t *name, void **ret, size_t *ret_size);
EFI_STATUS efivar_get_uint64_str16(const EFI_GUID *vendor, const char16_t *name, uint64_t *ret);
EFI_STATUS efivar_get_uint32_le(const EFI_GUID *vendor, const char16_t *name, uint32_t *ret);
EFI_STATUS efivar_get_uint64_le(const EFI_GUID *vendor, const char16_t *name, uint64_t *ret);
EFI_STATUS efivar_get_boolean_u8(const EFI_GUID *vendor, const char16_t *name, bool *ret);

uint64_t get_os_indications_supported(void);
