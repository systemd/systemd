/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "homework-forward.h"

int home_reconcile_blob_dirs(UserRecord *h, int root_fd, int reconciled);

int home_apply_new_blob_dir(UserRecord *h, Hashmap *blobs);
