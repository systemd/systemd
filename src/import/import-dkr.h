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

typedef struct DkrImport DkrImport;

typedef void (*dkr_import_on_finished)(DkrImport *import, int error, void *userdata);

int dkr_import_new(DkrImport **import, sd_event *event, dkr_import_on_finished on_finished, void *userdata);
DkrImport* dkr_import_unref(DkrImport *import);

DEFINE_TRIVIAL_CLEANUP_FUNC(DkrImport*, dkr_import_unref);

int dkr_import_pull(DkrImport *import, const char *index_url, const char *name, const char *tag, const char *local, bool force_local);
int dkr_import_cancel(DkrImport *import, const char *name);

bool dkr_name_is_valid(const char *name);
bool dkr_id_is_valid(const char *id);
#define dkr_tag_is_valid(tag) filename_is_valid(tag)
bool dkr_url_is_valid(const char *url);
