/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "user-record.h"

int home_update_quota_btrfs(UserRecord *h, const char *path);
int home_update_quota_classic(UserRecord *h, const char *path);
int home_update_quota_auto(UserRecord *h, const char *path);
