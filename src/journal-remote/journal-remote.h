/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Zbigniew Jędrzejewski-Szmek
***/

#include "sd-event.h"

#include "hashmap.h"
#include "journal-remote-parse.h"
#include "journal-remote-write.h"
#include "microhttpd-util.h"

typedef struct MHDDaemonWrapper MHDDaemonWrapper;

struct MHDDaemonWrapper {
        uint64_t fd;
        struct MHD_Daemon *daemon;

        sd_event_source *io_event;
        sd_event_source *timer_event;
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
