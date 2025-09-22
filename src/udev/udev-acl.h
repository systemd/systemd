/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "forward.h"

#if HAVE_ACL
int devnode_acl(int fd, uid_t uid);
#endif
