/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"
#include "import-compress.h"

typedef struct RawExport RawExport;

typedef void (*RawExportFinished)(RawExport *e, int error, void *userdata);

int raw_export_new(RawExport **ret, sd_event *event, RawExportFinished on_finished, void *userdata);
RawExport* raw_export_unref(RawExport *e);

DEFINE_TRIVIAL_CLEANUP_FUNC(RawExport*, raw_export_unref);

int raw_export_start(RawExport *e, const char *path, int fd, ImportCompressType compress);
