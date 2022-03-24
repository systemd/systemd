/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

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
int process_source(RemoteSource *source, JournalFileFlags file_flags);
