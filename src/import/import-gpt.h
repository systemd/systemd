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

typedef struct GptImport GptImport;

typedef void (*gpt_import_on_finished)(GptImport *import, int error, void *userdata);

int gpt_import_new(GptImport **import, sd_event *event, const char *image_root, gpt_import_on_finished on_finished, void *userdata);
GptImport* gpt_import_unref(GptImport *import);

DEFINE_TRIVIAL_CLEANUP_FUNC(GptImport*, gpt_import_unref);

int gpt_import_pull(GptImport *import, const char *url, const char *local, bool force_local);
int gpt_import_cancel(GptImport *import, const char *name);

bool gpt_url_is_valid(const char *url);
