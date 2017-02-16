#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Zbigniew Jędrzejewski-Szmek

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

#include "journal-importer.h"
#include "journal-remote-write.h"

typedef struct RemoteSource {
        JournalImporter importer;

        Writer *writer;

        sd_event_source *event;
        sd_event_source *buffer_event;
} RemoteSource;

RemoteSource* source_new(int fd, bool passive_fd, char *name, Writer *writer);
void source_free(RemoteSource *source);
int process_source(RemoteSource *source, bool compress, bool seal);
