/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#ifndef _SD_SUSPEND_ANNOTATE
#  if defined(__clang__)
#    define _SD_SUSPEND_ANNOTATE(...) __attribute__((annotate(__VA_ARGS__)))
#  else
#    define _SD_SUSPEND_ANNOTATE(...)
#  endif

#  define _sd_may_suspend_ _SD_SUSPEND_ANNOTATE("sd:may_suspend")
#  define _sd_suspend_ _SD_SUSPEND_ANNOTATE("sd:suspend")
#  define _sd_sync_ _SD_SUSPEND_ANNOTATE("sd:sync")
#  define _sd_await_cleanup_ _SD_SUSPEND_ANNOTATE("sd:await_cleanup")
#  define _sd_scoped_callback_ _SD_SUSPEND_ANNOTATE("sd:scoped_callback")
#  if defined(__clang__)
#    define _SD_SYNC_BEGIN \
        _Pragma("clang attribute push(__attribute__((annotate(\"sd:sync_default\"))), apply_to = function)")
#    define _SD_SYNC_END _Pragma("clang attribute pop")
#  else
#    define _SD_SYNC_BEGIN
#    define _SD_SYNC_END
#  endif
#  define _SD_SUSPEND_JOIN_INNER(a, b) a##b
#  define _SD_SUSPEND_JOIN(a, b) _SD_SUSPEND_JOIN_INNER(a, b)
#  define _SD_AWAIT(expr, uniq) __extension__ (({ int _SD_SUSPEND_JOIN(_sd_await_marker_, uniq) __attribute__((unused)) _SD_SUSPEND_ANNOTATE("sd:await"); (void) 0; }), (expr))
#  define SD_AWAIT(expr) _SD_AWAIT(expr, __COUNTER__)
#endif

#define _may_suspend_ _sd_may_suspend_
#define _sync_ _sd_sync_
/* A _suspend_ function can suspend like a _may_suspend_ function, but it has no synchronous fallback. It
 * aborts when it runs in a blocking region. */
#define _suspend_ _sd_suspend_
/* A _suspend_guard_ function returns true when the caller runs on a fiber outside a blocking region. Code
 * that only calls _suspend_ functions after the guard returned true has a synchronous fallback. */
#define _suspend_guard_ _SD_SUSPEND_ANNOTATE("sd:suspend_guard")
/* Functions declared between SYNC_BEGIN and SYNC_END are _sync_ unless they are declared _may_suspend_ or
 * _suspend_. Put SYNC_BEGIN after the includes, because the region also covers the functions that included
 * headers declare. */
#define SYNC_BEGIN _SD_SYNC_BEGIN
#define SYNC_END _SD_SYNC_END
#define _await_cleanup_ _sd_await_cleanup_
#define _cleanup_await_(func) _cleanup_(func) _await_cleanup_
/* A callback of a _scoped_callback_ type only runs while the function that received it runs. A call to that
 * function can suspend when one of the callbacks that it receives can suspend. */
#define _scoped_callback_ _sd_scoped_callback_
/* Arguments count from zero, so (2, 2) covers the arguments 2, 4, 6 and so on. */
#define _varargs_may_suspend_(first, stride) _SD_SUSPEND_ANNOTATE("sd:varargs", first, stride)

