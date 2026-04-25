/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if HAVE_LIBUCONTEXT && defined(__GLIBC__)
#include <libucontext/libucontext.h>    /* IWYU pragma: export */

typedef libucontext_ucontext_t ucontext_t;
#define getcontext  libucontext_getcontext
#define setcontext  libucontext_setcontext
#define makecontext libucontext_makecontext
#define swapcontext libucontext_swapcontext
#else
#include_next <ucontext.h>              /* IWYU pragma: export */
#endif
