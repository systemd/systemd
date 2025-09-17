/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <limits.h>

/* HOST_NAME_MAX should be 64 on linux, but musl uses the one by POSIX (255). */
#undef HOST_NAME_MAX
#define HOST_NAME_MAX 64
