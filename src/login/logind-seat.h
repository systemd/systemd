/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "list.h"
#include "logind-forward.h"

typedef struct Seat {
        Manager *manager;
        char *id;

        char *state_file;

        LIST_HEAD(Device, devices);

        Set *uevents;

        Session *active;
        Session *pending_switch;
        LIST_HEAD(Session, sessions);

        Session **positions;

        bool in_gc_queue:1;
        bool started:1;

        LIST_FIELDS(Seat, gc_queue);
} Seat;

int seat_new(Manager *m, const char *id, Seat **ret);
Seat* seat_free(Seat *s);

DEFINE_TRIVIAL_CLEANUP_FUNC(Seat*, seat_free);

int seat_save(Seat *s);
int seat_load(Seat *s);

int manager_process_device_triggered_by_seat(Manager *m, sd_device *dev);

int seat_set_active(Seat *s, Session *session);
int seat_switch_to(Seat *s, unsigned num);
int seat_switch_to_next(Seat *s);
int seat_switch_to_previous(Seat *s);
int seat_active_vt_changed(Seat *s, unsigned vtnr);
int seat_read_active_vt(Seat *s);
int seat_preallocate_vts(Seat *s);

int seat_attach_session(Seat *s, Session *session);
void seat_complete_switch(Seat *s);
void seat_evict_position(Seat *s, Session *session);
void seat_claim_position(Seat *s, Session *session, unsigned pos);

bool seat_has_vts(Seat *s);
bool seat_is_seat0(Seat *s);
bool seat_can_tty(Seat *s);
bool seat_has_master_device(Seat *s);
bool seat_can_graphical(Seat *s);

int seat_get_idle_hint(Seat *s, dual_timestamp *t);

int seat_start(Seat *s);
int seat_stop(Seat *s, bool force);
int seat_stop_sessions(Seat *s, bool force);

bool seat_may_gc(Seat *s, bool drop_not_started);
void seat_add_to_gc_queue(Seat *s);

bool seat_name_is_valid(const char *name);
bool seat_is_self(const char *name);
bool seat_is_auto(const char *name);
