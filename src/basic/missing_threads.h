/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* If threads.h doesn't exist, then define our own thread_local to match C11's thread_local. */
#if HAVE_THREADS_H
#  include <threads.h>
#elif !(defined(thread_local))
/* Don't break on glibc < 2.16 that doesn't define __STDC_NO_THREADS__
 * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=53769 */
#  if __STDC_VERSION__ >= 201112L && !(defined(__STDC_NO_THREADS__) || (defined(__GNU_LIBRARY__) && __GLIBC__ == 2 && __GLIBC_MINOR__ < 16))
#    define thread_local _Thread_local
#  else
#    define thread_local __thread
#  endif
#endif
