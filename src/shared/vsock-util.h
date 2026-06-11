/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/vm_sockets.h>

int vsock_get_local_cid(unsigned *ret);
