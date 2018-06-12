/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-event.h"

#include "import-util.h"
#include "macro.h"

typedef struct TarPull TarPull;

typedef void (*TarPullFinished)(TarPull *pull, int error, void *userdata);

int tar_pull_new(TarPull **pull, sd_event *event, const char *image_root, TarPullFinished on_finished, void *userdata);
TarPull* tar_pull_unref(TarPull *pull);

DEFINE_TRIVIAL_CLEANUP_FUNC(TarPull*, tar_pull_unref);

int tar_pull_start(TarPull *pull, const char *url, const char *local, bool force_local, ImportVerify verify, bool settings);
