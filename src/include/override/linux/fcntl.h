/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* We do not use linux/fcntl.h as it conflicts with glibc's fcntl.h. */
#include <fcntl.h>

/* The below are defined in linux/fcntl.h, but not defined in glibc's fcntl.h.
 * They are necessary for linux/pidfd.h, hence define them here. */
#define PIDFD_SELF_THREAD               -10000 /* Current thread. */
#define PIDFD_SELF_THREAD_GROUP         -10001 /* Current thread group leader. */
