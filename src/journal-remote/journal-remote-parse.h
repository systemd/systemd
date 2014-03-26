/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#pragma once

#include "sd-event.h"
#include "journal-remote-write.h"

typedef enum {
        STATE_LINE = 0,    /* waiting to read, or reading line */
        STATE_DATA_START,  /* reading binary data header */
        STATE_DATA,        /* reading binary data */
        STATE_DATA_FINISH, /* expecting newline */
        STATE_EOF,         /* done */
} source_state;

typedef struct RemoteSource {
        char* name;
        int fd;

        char *buf;
        size_t size;
        size_t filled;
        size_t data_size;

        struct iovec_wrapper iovw;

        source_state state;
        dual_timestamp ts;

        sd_event_source *event;
} RemoteSource;

static inline int source_non_empty(RemoteSource *source) {
        assert(source);

        return source->filled > 0;
}

void source_free(RemoteSource *source);
int process_data(RemoteSource *source);
int push_data(RemoteSource *source, const char *data, size_t size);
int process_source(RemoteSource *source, Writer *writer, bool compress, bool seal);
