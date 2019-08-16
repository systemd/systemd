/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

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

int seat_new(Seat **ret, Manager *m, const char *id);
Seat* seat_free(Seat *s);

DEFINE_TRIVIAL_CLEANUP_FUNC(Seat *, seat_free);

int seat_save(Seat *s);
int seat_load(Seat *s);

int seat_apply_acls(Seat *s, Session *old_active);
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
bool seat_can_multi_session(Seat *s);
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

static inline bool SEAT_IS_SELF(const char *name) {
        return isempty(name) || streq(name, "self");
}

static inline bool SEAT_IS_AUTO(const char *name) {
        return streq_ptr(name, "auto");
}
