/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

typedef struct RawImport RawImport;

typedef void (*raw_import_on_finished)(RawImport *import, int error, void *userdata);

int raw_import_new(RawImport **import, sd_event *event, const char *image_root, raw_import_on_finished on_finished, void *userdata);
RawImport* raw_import_unref(RawImport *import);

DEFINE_TRIVIAL_CLEANUP_FUNC(RawImport*, raw_import_unref);

int raw_import_pull(RawImport *import, const char *url, const char *local, bool force_local);
int raw_import_cancel(RawImport *import, const char *name);

bool raw_url_is_valid(const char *url);
