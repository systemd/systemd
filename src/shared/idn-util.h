/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "dlopen-note.h"
#include "shared-forward.h"

#if HAVE_LIBIDN2
#ifndef SYSTEMD_CFLAGS_MARKER_LIBIDN2
#  error "missing libidn2_cflags in meson dependency."
#endif

#include <idn2.h>

#include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(idn2_lookup_u8);
extern const char *(*sym_idn2_strerror)(int rc) _const_;
extern DLSYM_PROTOTYPE(idn2_to_unicode_8z8z);
#endif

int dlopen_idn(int log_level) _dlopen_loader_;

#define DLOPEN_IDN(log_level, priority)                                 \
        ({                                                              \
                LIBIDN2_NOTE(priority);                                 \
                dlopen_idn(log_level);                                  \
        })
