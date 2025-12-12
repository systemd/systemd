/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/keyctl.h>       /* IWYU pragma: export */
#include <stddef.h>

#if !HAVE_KEYCTL
long missing_keyctl(int cmd, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
#  define keyctl missing_keyctl
#endif

#if !HAVE_ADD_KEY
key_serial_t missing_add_key(const char *type, const char *description, const void *payload, size_t plen, key_serial_t ringid);
#  define add_key missing_add_key
#endif

#if !HAVE_REQUEST_KEY
key_serial_t missing_request_key(const char *type, const char *description, const char *callout_info, key_serial_t destringid);
#  define request_key missing_request_key
#endif
