/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dlopen.h"

#include "shared-forward.h"

#if HAVE_LIBIDN2
#ifndef SYSTEMD_CFLAGS_MARKER_LIBIDN2
#  error("missing libidn2_cflags in meson dependency.");
#endif

#include <idn2.h>

#include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(idn2_lookup_u8);
extern const char *(*sym_idn2_strerror)(int rc) _const_;
extern DLSYM_PROTOTYPE(idn2_to_unicode_8z8z);

#define IDN_NOTE(priority)                                              \
        SD_ELF_NOTE_DLOPEN("idn",                                       \
                           "Support for internationalized domain names", \
                           priority,                                    \
                           "libidn2.so.0")

#define DLOPEN_IDN(log_level, priority)                                 \
        ({                                                              \
                IDN_NOTE(priority);                                     \
                dlopen_idn(log_level);                                  \
        })
#else
#define DLOPEN_IDN(log_level, priority) dlopen_idn(log_level)
#endif

int dlopen_idn(int log_level);
