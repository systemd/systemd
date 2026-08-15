/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/keyctl.h>       /* IWYU pragma: export */
#include <stddef.h>

long keyctl_shim(int cmd, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
#define keyctl keyctl_shim

key_serial_t add_key_shim(const char *type, const char *description, const void *payload, size_t plen, key_serial_t ringid);
#define add_key add_key_shim

key_serial_t request_key_shim(const char *type, const char *description, const char *callout_info, key_serial_t destringid);
#define request_key request_key_shim
