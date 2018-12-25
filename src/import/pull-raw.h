/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-event.h"

#include "import-util.h"
#include "macro.h"

typedef struct RawPull RawPull;

typedef void (*RawPullFinished)(RawPull *pull, int error, void *userdata);

int raw_pull_new(
        RawPull **pull, sd_event *event, const char *image_root, RawPullFinished on_finished, void *userdata);
RawPull *raw_pull_unref(RawPull *pull);

DEFINE_TRIVIAL_CLEANUP_FUNC(RawPull *, raw_pull_unref);

int raw_pull_start(RawPull *pull,
                   const char *url,
                   const char *local,
                   bool force_local,
                   ImportVerify verify,
                   bool settings,
                   bool roothash);
