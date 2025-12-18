/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "import-common.h"
#include "import-compress.h"
#include "shared-forward.h"

typedef struct TarExport TarExport;

typedef void (*TarExportFinished)(TarExport *e, int error, void *userdata);

int tar_export_new(TarExport **ret, sd_event *event, TarExportFinished on_finished, void *userdata);
TarExport* tar_export_unref(TarExport *e);

DEFINE_TRIVIAL_CLEANUP_FUNC(TarExport*, tar_export_unref);

int tar_export_start(TarExport *e, const char *path, int fd, ImportCompressType compress, ImportFlags flags);
