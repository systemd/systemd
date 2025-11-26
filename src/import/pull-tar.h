/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"
#include "import-common.h"
#include "import-util.h"

typedef struct TarPull TarPull;

typedef void (*TarPullFinished)(TarPull *p, int error, void *userdata);

int tar_pull_new(TarPull **ret, sd_event *event, const char *image_root, TarPullFinished on_finished, void *userdata);
TarPull* tar_pull_unref(TarPull *p);

DEFINE_TRIVIAL_CLEANUP_FUNC(TarPull*, tar_pull_unref);

int tar_pull_start(TarPull *p, const char *url, const char *local, ImportFlags flags, ImportVerify verify, const struct iovec *checksum);
