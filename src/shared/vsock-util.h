/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/vm_sockets.h> /* IWYU pragma: export */

int vsock_get_local_cid(unsigned *ret);
int vsock_open_or_warn(int *ret);
int vsock_get_local_cid_or_warn(unsigned *ret);
