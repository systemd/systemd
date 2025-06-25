/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "list.h"
#include "logind-forward.h"
#include "pidref.h"
#include "time-util.h"

typedef enum SessionState {
        SESSION_OPENING,  /* Session scope is being created */
        SESSION_ONLINE,   /* Logged in */
        SESSION_ACTIVE,   /* Logged in and in the fg */
        SESSION_CLOSING,  /* Logged out, but scope is still there */
        _SESSION_STATE_MAX,
        _SESSION_STATE_INVALID = -EINVAL,
} SessionState;

typedef enum SessionClass {
        SESSION_USER,               /* A regular user session */
        SESSION_USER_EARLY,         /* A user session, that is not ordered after systemd-user-sessions.service (i.e. for root) */
        SESSION_USER_INCOMPLETE,    /* A user session that is only half-way set up and doesn't pull in the service manager, and can be upgraded to a full user session later */
        SESSION_USER_LIGHT,         /* Just like SESSION_USER, but doesn't pull in service manager */
        SESSION_USER_EARLY_LIGHT,   /* Just like SESSION_USER_EARLY, but doesn't pull in service manager */
        SESSION_GREETER,            /* A login greeter pseudo-session */
        SESSION_LOCK_SCREEN,        /* A lock screen */
        SESSION_BACKGROUND,         /* Things like cron jobs, which are non-interactive */
        SESSION_BACKGROUND_LIGHT,   /* Like SESSION_BACKGROUND, but without the service manager */
        SESSION_MANAGER,            /* The service manager */
        SESSION_MANAGER_EARLY,      /* The service manager for root (which is allowed to run before systemd-user-sessions.service) */
        SESSION_NONE,               /* A session not registered with logind */
        _SESSION_CLASS_MAX,
        _SESSION_CLASS_INVALID = -EINVAL,
} SessionClass;

/* Whether we shall allow sessions of this class to run before 'systemd-user-sessions.service'. It's
 * generally set for root sessions, but no one else. */
#define SESSION_CLASS_IS_EARLY(class) IN_SET((class), SESSION_USER_EARLY, SESSION_USER_EARLY_LIGHT, SESSION_MANAGER_EARLY)

/* Which session classes want their own scope units? (all of them, except the manager, which comes in its own service unit already */
#define SESSION_CLASS_WANTS_SCOPE(class) IN_SET((class),                \
                                                SESSION_USER, SESSION_USER_EARLY, SESSION_USER_INCOMPLETE, SESSION_USER_LIGHT, SESSION_USER_EARLY_LIGHT, \
                                                SESSION_GREETER, SESSION_LOCK_SCREEN, SESSION_BACKGROUND, SESSION_BACKGROUND_LIGHT)

/* Which session classes want their own per-user service manager? */
#define SESSION_CLASS_WANTS_SERVICE_MANAGER(class) IN_SET((class), SESSION_USER, SESSION_USER_EARLY, SESSION_GREETER, SESSION_LOCK_SCREEN, SESSION_BACKGROUND)

/* Which session classes can pin our user tracking? */
#define SESSION_CLASS_PIN_USER(class) (!IN_SET((class), SESSION_MANAGER, SESSION_MANAGER_EARLY, SESSION_NONE))

/* Which session classes decide whether system is idle? (should only cover sessions that have input, and are not idle screens themselves) */
#define SESSION_CLASS_CAN_IDLE(class) (IN_SET((class), SESSION_USER, SESSION_USER_EARLY, SESSION_USER_EARLY_LIGHT, SESSION_USER_LIGHT, SESSION_GREETER))

/* Which session classes have a lock screen concept? */
#define SESSION_CLASS_CAN_LOCK(class) (IN_SET((class), SESSION_USER, SESSION_USER_EARLY, SESSION_USER_EARLY_LIGHT, SESSION_USER_LIGHT))

/* Which sessions are candidates to become "display" sessions */
#define SESSION_CLASS_CAN_DISPLAY(class) (IN_SET((class), SESSION_USER, SESSION_USER_EARLY, SESSION_USER_EARLY_LIGHT, SESSION_USER_LIGHT, SESSION_GREETER))

/* Which sessions classes should be subject to stop-in-idle */
#define SESSION_CLASS_CAN_STOP_ON_IDLE(class) (IN_SET((class), SESSION_USER, SESSION_USER_EARLY, SESSION_USER_LIGHT, SESSION_USER_EARLY_LIGHT))

/* Which session classes can take control of devices */
#define SESSION_CLASS_CAN_TAKE_DEVICE(class) (IN_SET((class), SESSION_USER, SESSION_USER_EARLY, SESSION_USER_LIGHT, SESSION_USER_EARLY_LIGHT, SESSION_GREETER, SESSION_LOCK_SCREEN))

/* Which session classes allow changing session types */
#define SESSION_CLASS_CAN_CHANGE_TYPE(class) (IN_SET((class), SESSION_USER, SESSION_USER_EARLY, SESSION_USER_LIGHT, SESSION_USER_EARLY_LIGHT, SESSION_GREETER, SESSION_LOCK_SCREEN))

/* Which session classes are taken into account when deciding whether shutdown shall be allowed if other users are logged in */
#define SESSION_CLASS_IS_INHIBITOR_LIKE(class) IN_SET((class), SESSION_USER, SESSION_USER_EARLY, SESSION_USER_LIGHT, SESSION_USER_EARLY_LIGHT)

typedef enum SessionType {
        SESSION_UNSPECIFIED,
        SESSION_TTY,
        SESSION_X11,
        SESSION_WAYLAND,
        SESSION_MIR,
        SESSION_WEB,
        _SESSION_TYPE_MAX,
        _SESSION_TYPE_INVALID = -EINVAL,
} SessionType;

#define SESSION_TYPE_IS_GRAPHICAL(type) IN_SET(type, SESSION_X11, SESSION_WAYLAND, SESSION_MIR)

typedef enum KillWhom {
        KILL_LEADER,
        KILL_ALL,
        _KILL_WHOM_MAX,
        _KILL_WHOM_INVALID = -EINVAL,
} KillWhom;

typedef enum TTYValidity {
        TTY_FROM_PAM,
        TTY_FROM_UTMP,
        TTY_UTMP_INCONSISTENT, /* may happen on ssh sessions with multiplexed TTYs */
        _TTY_VALIDITY_MAX,
        _TTY_VALIDITY_INVALID = -EINVAL,
} TTYValidity;

typedef struct Session {
        Manager *manager;

        char *id;

        unsigned position;
        SessionType type;
        SessionType original_type;
        SessionClass class;

        char *state_file;

        User *user;

        dual_timestamp timestamp;

        char *display;
        char *tty;
        TTYValidity tty_validity;

        bool remote;
        char *remote_user;
        char *remote_host;
        char *service;
        char *desktop;

        char *scope;
        char *scope_job;

        Seat *seat;
        unsigned vtnr;
        int vtfd;

        PidRef leader;
        bool leader_fd_saved; /* pidfd of leader uploaded to fdstore */
        pid_t deserialized_pid; /* PID deserialized from state file (for verification when pidfd is used) */
        uint32_t audit_id;

        sd_event_source *leader_pidfd_event_source;

        bool in_gc_queue;
        bool started;
        bool stopping;

        bool was_active;

        bool locked_hint;

        bool idle_hint;
        dual_timestamp idle_hint_timestamp;

        sd_bus_message *create_message;   /* The D-Bus message used to create the session, which we haven't responded to yet */
        sd_bus_message *upgrade_message;  /* The D-Bus message used to upgrade the session class user-incomplete → user, which we haven't responded to yet */

        sd_varlink *create_link; /* The Varlink connection used to create session, which we haven't responded to yet */

        /* Set up when a client requested to release the session via the bus */
        sd_event_source *timer_event_source;

        char *controller;
        Hashmap *devices;
        sd_bus_track *track;

        sd_event_source *stop_on_idle_event_source;

        LIST_FIELDS(Session, sessions_by_user);
        LIST_FIELDS(Session, sessions_by_seat);

        LIST_FIELDS(Session, gc_queue);
} Session;

int session_new(Manager *m, const char *id, Session **ret);
Session* session_free(Session *s);

DEFINE_TRIVIAL_CLEANUP_FUNC(Session*, session_free);

void session_set_user(Session *s, User *u);
int session_set_leader_consume(Session *s, PidRef _leader);
bool session_may_gc(Session *s, bool drop_not_started);
void session_add_to_gc_queue(Session *s);
int session_activate(Session *s);
bool session_is_active(Session *s);
int session_get_idle_hint(Session *s, dual_timestamp *t);
int session_set_idle_hint(Session *s, bool b);
int session_get_locked_hint(Session *s);
int session_set_locked_hint(Session *s, bool b);
void session_set_type(Session *s, SessionType t);
void session_set_class(Session *s, SessionClass c);
int session_set_display(Session *s, const char *display);
int session_set_tty(Session *s, const char *tty);
int session_start(Session *s, sd_bus_message *properties, sd_bus_error *error);
int session_stop(Session *s, bool force);
int session_finalize(Session *s);
int session_release(Session *s);
int session_save(Session *s);
int session_load(Session *s);
int session_kill(Session *s, KillWhom whom, int signo, sd_bus_error *error);

SessionState session_get_state(Session *u);

const char* session_state_to_string(SessionState t) _const_;
SessionState session_state_from_string(const char *s) _pure_;

const char* session_type_to_string(SessionType t) _const_;
SessionType session_type_from_string(const char *s) _pure_;

const char* session_class_to_string(SessionClass t) _const_;
SessionClass session_class_from_string(const char *s) _pure_;

const char* kill_whom_to_string(KillWhom k) _const_;
KillWhom kill_whom_from_string(const char *s) _pure_;

const char* tty_validity_to_string(TTYValidity t) _const_;
TTYValidity tty_validity_from_string(const char *s) _pure_;

void session_leave_vt(Session *s);

bool session_is_controller(Session *s, const char *sender);
int session_set_controller(Session *s, const char *sender, bool force, bool prepare);
void session_drop_controller(Session *s);

bool session_job_pending(Session *s);

int session_send_create_reply(Session *s, const sd_bus_error *error);

bool session_is_self(const char *name);
bool session_is_auto(const char *name);
