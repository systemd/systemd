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
#include "import-compress.h"

typedef struct RawExport RawExport;

typedef void (*RawExportFinished)(RawExport *export, int error, void *userdata);

int raw_export_new(RawExport **export, sd_event *event, RawExportFinished on_finished, void *userdata);
RawExport* raw_export_unref(RawExport *export);

DEFINE_TRIVIAL_CLEANUP_FUNC(RawExport*, raw_export_unref);

int raw_export_start(RawExport *export, const char *path, int fd, ImportCompressType compress);
