/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-event.h"

#include "import-util.h"
#include "macro.h"

typedef struct RawImport RawImport;

typedef void (*RawImportFinished)(RawImport *import, int error, void *userdata);

int raw_import_new(RawImport **import,
                   sd_event *event,
                   const char *image_root,
                   RawImportFinished on_finished,
                   void *userdata);
RawImport *raw_import_unref(RawImport *import);

DEFINE_TRIVIAL_CLEANUP_FUNC(RawImport *, raw_import_unref);

int raw_import_start(RawImport *i, int fd, const char *local, bool force_local, bool read_only);
