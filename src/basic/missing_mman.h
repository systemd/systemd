/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/mman.h> /* IWYU pragma: export */

#include "forward.h"

/* since glibc-2.38 */
#ifndef MFD_NOEXEC_SEAL
#  define MFD_NOEXEC_SEAL 0x0008U
#else
assert_cc(MFD_NOEXEC_SEAL == 0x0008U);
#endif

/* since glibc-2.38 */
#ifndef MFD_EXEC
#  define MFD_EXEC 0x0010U
#else
assert_cc(MFD_EXEC == 0x0010U);
#endif
