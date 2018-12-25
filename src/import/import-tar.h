/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-event.h"

#include "import-util.h"
#include "macro.h"

typedef struct TarImport TarImport;

typedef void (*TarImportFinished)(TarImport *import, int error, void *userdata);

int tar_import_new(TarImport **import,
                   sd_event *event,
                   const char *image_root,
                   TarImportFinished on_finished,
                   void *userdata);
TarImport *tar_import_unref(TarImport *import);

DEFINE_TRIVIAL_CLEANUP_FUNC(TarImport *, tar_import_unref);

int tar_import_start(TarImport *import, int fd, const char *local, bool force_local, bool read_only);
