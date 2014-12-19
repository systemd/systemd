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
#include "util.h"

typedef struct DckImport DckImport;

typedef void (*dck_import_on_finished)(DckImport *import, int error, void *userdata);

int dck_import_new(DckImport **import, sd_event *event, dck_import_on_finished on_finished, void *userdata);
DckImport* dck_import_unref(DckImport *import);

DEFINE_TRIVIAL_CLEANUP_FUNC(DckImport*, dck_import_unref);

int dck_import_pull(DckImport *import, const char *name, const char *tag, const char *local, bool force_local);
int dck_import_cancel(DckImport *import, const char *name);

bool dck_name_is_valid(const char *name);
bool dck_id_is_valid(const char *id);
#define dck_tag_is_valid(tag) filename_is_valid(tag)
