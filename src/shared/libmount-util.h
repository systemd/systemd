/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/* This needs to be after sys/mount.h */
#include <libmount.h>

#include "macro.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(struct libmnt_table*, mnt_free_table);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct libmnt_iter*, mnt_free_iter);
