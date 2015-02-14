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
#include "hashmap.h"
#include "microhttpd-util.h"

#include "journal-remote-parse.h"
#include "journal-remote-write.h"

typedef struct MHDDaemonWrapper MHDDaemonWrapper;

struct MHDDaemonWrapper {
        uint64_t fd;
        struct MHD_Daemon *daemon;

        sd_event_source *event;
};

struct RemoteServer {
        RemoteSource **sources;
        size_t sources_size;
        size_t active;

        sd_event *events;
        sd_event_source *sigterm_event, *sigint_event, *listen_event;

        Hashmap *writers;
        Writer *_single_writer;
        uint64_t event_count;

        bool check_trust;
        Hashmap *daemons;
};
