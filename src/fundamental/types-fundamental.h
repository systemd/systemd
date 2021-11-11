/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* This defines a number of basic types that are one thing in userspace and another in the UEFI environment,
 * but mostly the same in concept and behaviour.
 *
 * Note: if the definition of these types/values has slightly different semantics in userspace and in the
 * UEFI environment then please prefix its name with "sd_" to make clear these types have special semantics,
 * and *we* defined them. Otherwise, if the types are effectively 100% identical in behaviour in userspace
 * and UEFI environment you can omit the prefix. (Examples: sd_char is 8 bit in userspace and 16 bit in UEFI
 * space hence it should have the sd_ prefix; but size_t in userspace and UINTN in UEFI environment are 100%
 * defined the same way ultimately, hence it's OK to just define size_t as alias to UINTN in UEFI
 * environment, so that size_t can be used everywhere, without any "sd_" prefix.)
 *
 * Note: we generally prefer the userspace names of types and concepts. i.e. if in doubt please name types
 * after the userspace vocabulary, and let's keep UEFI vocabulary specific to the UEFI build environment. */

#ifdef SD_BOOT
#include <efi.h>

typedef BOOLEAN sd_bool;
typedef CHAR16  sd_char;
typedef INTN    sd_int;
typedef UINTN   size_t;

#define sd_true  TRUE
#define sd_false FALSE
#else
#include <stdbool.h>
#include <stdint.h>

typedef bool    sd_bool;
typedef char    sd_char;
typedef int     sd_int;

#define sd_true  true
#define sd_false false

#endif
