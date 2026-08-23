/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "compress.h"
#include "forward.h"
#include "journal-importer.h"
#include "journal-remote-write.h"

typedef struct RemoteSource {
        JournalImporter importer;

        Writer *writer;

        sd_event_source *event;
        sd_event_source *buffer_event;
        Compression compression;
        char *encoding;
} RemoteSource;

RemoteSource* source_new(int fd, bool passive_fd, char *name, Writer *writer);
RemoteSource* source_free(RemoteSource *source);
DEFINE_TRIVIAL_CLEANUP_FUNC(RemoteSource*, source_free);
int process_source(RemoteSource *source, JournalFileFlags file_flags);
