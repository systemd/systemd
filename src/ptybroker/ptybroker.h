/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"
#include "sd-varlink.h"

#include "list.h"
#include "macro.h"
#include "runtime-scope.h"
#include "ptybroker-forward.h"

struct Manager {
        RuntimeScope scope;
        sd_event *event;
        sd_varlink_server *varlink_server;
        Hashmap *polkit_registry;

        Hashmap *ptys;

        LIST_HEAD(PseudoTTY, ptys_free_queue);
        sd_event_source *ptys_free_queue_event_source;

        sd_event_source *exit_on_idle_event_source;
};

#define BUFFER_MAX (4U * U64_MB)
