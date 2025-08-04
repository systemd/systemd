/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "homework-forward.h"

int home_update_quota_btrfs(UserRecord *h, int fd, const char *path);
int home_update_quota_classic(UserRecord *h, int fd, const char *path);
int home_update_quota_auto(UserRecord *h, int fd, const char *path);
