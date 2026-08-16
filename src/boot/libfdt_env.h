/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* libfdt requires reimplementing the libfdt_env.h header locally that the vendor's libfdt.h includes,
 * customizing it for the local environment and providing some utility functions that libfdt's public
 * headers require. */

#include "util.h"

#define strchr strchr8
#define strlen strlen8
#define strnlen strnlen8
#define strrchr strrchr8
#define strtoul strtoul8

typedef uint16_t fdt16_t;
typedef uint32_t fdt32_t;
typedef uint64_t fdt64_t;

#define fdt16_to_cpu(x) be16toh(x)
#define fdt32_to_cpu(x) be32toh(x)
#define fdt64_to_cpu(x) be64toh(x)
#define cpu_to_fdt16(x) htobe16(x)
#define cpu_to_fdt32(x) htobe32(x)
#define cpu_to_fdt64(x) htobe64(x)
