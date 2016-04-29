#pragma once

/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

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

#include <sys/types.h>

#include "sd-bus.h"
#include "sd-event.h"

#include "list.h"

typedef struct Operation Operation;

#include "machined.h"

#define OPERATIONS_MAX 64

struct Operation {
        Manager *manager;
        Machine *machine;
        pid_t pid;
        sd_bus_message *message;
        int errno_fd;
        sd_event_source *event_source;
        LIST_FIELDS(Operation, operations);
        LIST_FIELDS(Operation, operations_by_machine);
};

int operation_new(Manager *manager, Machine *machine, pid_t child, sd_bus_message *message, int errno_fd);
Operation *operation_free(Operation *o);
