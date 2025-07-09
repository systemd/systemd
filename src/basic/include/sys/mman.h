/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <sys/mman.h>

#include <assert.h>

/* since glibc-2.38 */
#ifndef MFD_NOEXEC_SEAL
#  define MFD_NOEXEC_SEAL 0x0008U
#else
static_assert(MFD_NOEXEC_SEAL == 0x0008U, "");
#endif

/* since glibc-2.38 */
#ifndef MFD_EXEC
#  define MFD_EXEC 0x0010U
#else
static_assert(MFD_EXEC == 0x0010U, "");
#endif
