/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "manager.h"

void bus_send_pending_reload_message(Manager *m);

int bus_init_private(Manager *m);
int bus_init_api(Manager *m);
int bus_init_system(Manager *m);

void bus_done_private(Manager *m);
void bus_done_api(Manager *m);
void bus_done_system(Manager *m);
void bus_done(Manager *m);

int bus_fdset_add_all(Manager *m, FDSet *fds);

void bus_track_serialize(sd_bus_track *t, FILE *f, const char *prefix);

int bus_foreach_bus(Manager *m, sd_bus_track *subscribed2, int (*send_message)(sd_bus *bus, void *userdata), void *userdata);

int bus_forward_agent_released(Manager *m, const char *path);

uint64_t manager_bus_n_queued_write(Manager *m);

void dump_bus_properties(FILE *f);
int bus_manager_introspect_implementations(FILE *out, const char *pattern);
