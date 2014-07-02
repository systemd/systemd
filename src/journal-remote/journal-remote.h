#include <inttypes.h>

#include "sd-event.h"
#include "hashmap.h"
#include "microhttpd-util.h"

#include "journal-remote-parse.h"

typedef struct MHDDaemonWrapper {
        uint64_t fd;
        struct MHD_Daemon *daemon;

        sd_event_source *event;
} MHDDaemonWrapper;

typedef struct RemoteServer {
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
} RemoteServer;
