/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "sd-event.h"
#include "macro.h"
#include "import-util.h"

typedef struct RawImport RawImport;

typedef void (*RawImportFinished)(RawImport *import, int error, void *userdata);

int raw_import_new(RawImport **import, sd_event *event, const char *image_root, RawImportFinished on_finished, void *userdata);
RawImport* raw_import_unref(RawImport *import);

DEFINE_TRIVIAL_CLEANUP_FUNC(RawImport*, raw_import_unref);

int raw_import_start(RawImport *i, int fd, const char *local, bool force_local, bool read_only);
