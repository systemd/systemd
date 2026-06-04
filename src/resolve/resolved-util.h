/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dlopen.h"

#if ENABLE_DNS_OVER_TLS
#  define DLOPEN_LIBCRYPTO_PRIORITY SD_ELF_NOTE_DLOPEN_PRIORITY_REQUIRED
#else
#  define DLOPEN_LIBCRYPTO_PRIORITY SD_ELF_NOTE_DLOPEN_PRIORITY_RECOMMENDED
#endif

int resolve_system_hostname(char **full_hostname, char **first_label);
