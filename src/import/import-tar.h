/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"
#include "import-common.h"

typedef struct TarImport TarImport;

typedef void (*TarImportFinished)(TarImport *i, int error, void *userdata);

int tar_import_new(TarImport **ret, sd_event *event, const char *image_root, TarImportFinished on_finished, void *userdata);
TarImport* tar_import_unref(TarImport *i);

DEFINE_TRIVIAL_CLEANUP_FUNC(TarImport*, tar_import_unref);

int tar_import_start(TarImport *i, int fd, const char *local, ImportFlags flags);
