/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"

#include "import-compress.h"
#include "macro.h"

typedef struct RawExport RawExport;

typedef void (*RawExportFinished)(RawExport *export, int error, void *userdata);

int raw_export_new(RawExport **export, sd_event *event, RawExportFinished on_finished, void *userdata);
RawExport* raw_export_unref(RawExport *export);

DEFINE_TRIVIAL_CLEANUP_FUNC(RawExport*, raw_export_unref);

int raw_export_start(RawExport *export, const char *path, int fd, ImportCompressType compress);
