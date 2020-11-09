/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <sys/types.h>

int path_patch_uid(const char *path, uid_t shift, uid_t range);
