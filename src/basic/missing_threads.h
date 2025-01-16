/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* If threads.h doesn't exist, then define our own thread_local to match C11's thread_local. */
#if HAVE_THREADS_H
#  include <threads.h>
#elif !(defined(thread_local))
#  ifndef __STDC_NO_THREADS__
#    define thread_local _Thread_local
#  else
#    define thread_local __thread
#  endif
#endif
