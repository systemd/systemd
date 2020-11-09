/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"

#include "import-compress.h"
#include "macro.h"

typedef struct TarExport TarExport;

typedef void (*TarExportFinished)(TarExport *export, int error, void *userdata);

int tar_export_new(TarExport **export, sd_event *event, TarExportFinished on_finished, void *userdata);
TarExport* tar_export_unref(TarExport *export);

DEFINE_TRIVIAL_CLEANUP_FUNC(TarExport*, tar_export_unref);

int tar_export_start(TarExport *export, const char *path, int fd, ImportCompressType compress);
