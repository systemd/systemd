/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

typedef struct Seat Seat;

#include "list.h"
#include "logind-session.h"

struct Seat {
        Manager *manager;
        char *id;

        char *state_file;

        LIST_HEAD(Device, devices);

        Session *active;
        Session *pending_switch;
        LIST_HEAD(Session, sessions);

        Session **positions;
        size_t position_count;

        bool in_gc_queue:1;
        bool started:1;

        LIST_FIELDS(Seat, gc_queue);
};

Seat *seat_new(Manager *m, const char *id);
void seat_free(Seat *s);

int seat_save(Seat *s);
int seat_load(Seat *s);

int seat_apply_acls(Seat *s, Session *old_active);
int seat_set_active(Seat *s, Session *session);
int seat_switch_to(Seat *s, unsigned int num);
int seat_switch_to_next(Seat *s);
int seat_switch_to_previous(Seat *s);
int seat_active_vt_changed(Seat *s, unsigned int vtnr);
int seat_read_active_vt(Seat *s);
int seat_preallocate_vts(Seat *s);

int seat_attach_session(Seat *s, Session *session);
void seat_complete_switch(Seat *s);
void seat_evict_position(Seat *s, Session *session);
void seat_claim_position(Seat *s, Session *session, unsigned int pos);

bool seat_has_vts(Seat *s);
bool seat_is_seat0(Seat *s);
bool seat_can_multi_session(Seat *s);
bool seat_can_tty(Seat *s);
bool seat_has_master_device(Seat *s);
bool seat_can_graphical(Seat *s);

int seat_get_idle_hint(Seat *s, dual_timestamp *t);

int seat_start(Seat *s);
int seat_stop(Seat *s, bool force);
int seat_stop_sessions(Seat *s, bool force);

bool seat_check_gc(Seat *s, bool drop_not_started);
void seat_add_to_gc_queue(Seat *s);

bool seat_name_is_valid(const char *name);

extern const sd_bus_vtable seat_vtable[];

int seat_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error);
int seat_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error);
char *seat_bus_path(Seat *s);

int seat_send_signal(Seat *s, bool new_seat);
int seat_send_changed(Seat *s, const char *properties, ...) _sentinel_;

int bus_seat_method_terminate(sd_bus_message *message, void *userdata, sd_bus_error *error);
