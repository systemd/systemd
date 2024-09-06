/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct User User;

#include "conf-parser.h"
#include "list.h"
#include "logind.h"
#include "user-record.h"

typedef enum UserState {
        USER_OFFLINE,    /* Not logged in at all */
        USER_OPENING,    /* Is logging in */
        USER_LINGERING,  /* Lingering has been enabled by the admin for this user */
        USER_ONLINE,     /* User logged in */
        USER_ACTIVE,     /* User logged in and has a session in the fg */
        USER_CLOSING,    /* User logged out, but processes still remain and lingering is not enabled */
        _USER_STATE_MAX,
        _USER_STATE_INVALID = -EINVAL,
} UserState;

typedef enum UserGCMode {
        USER_GC_BY_ANY,         /* any session pins this user */
        USER_GC_BY_PIN,         /* only sessions with an explicitly pinning class pin this user */
        _USER_GC_MODE_MAX,
        _USER_GC_MODE_INVALID = -EINVAL,
} UserGCMode;

struct User {
        Manager *manager;

        UserRecord *user_record;

        char *state_file;
        char *runtime_path;

        /* user-UID.slice */
        char *slice;

        /* user-runtime-dir@UID.service */
        char *runtime_dir_unit;
        char *runtime_dir_job;

        /* user@UID.service */
        bool service_manager_started;
        char *service_manager_unit;
        char *service_manager_job;

        Session *display;

        dual_timestamp timestamp;      /* When this User object was 'started' the first time */
        usec_t last_session_timestamp; /* When the number of sessions of this user went from 1 to 0 the last time */

        /* Set up when the last session of the user logs out */
        sd_event_source *timer_event_source;

        UserGCMode gc_mode;
        bool in_gc_queue:1;

        bool started:1;       /* Whenever the user being started, has been started or is being stopped again
                                 (tracked through user-runtime-dir@.service) */
        bool stopping:1;      /* Whenever the user is being stopped or has been stopped. */

        LIST_HEAD(Session, sessions);
        LIST_FIELDS(User, gc_queue);
};

int user_new(Manager *m, UserRecord *ur, User **ret);
User *user_free(User *u);

DEFINE_TRIVIAL_CLEANUP_FUNC(User*, user_free);

int user_start_service_manager(User *u);
int user_start(User *u);

bool user_may_gc(User *u, bool drop_not_started);
void user_add_to_gc_queue(User *u);
int user_stop(User *u, bool force);
int user_finalize(User *u);
UserState user_get_state(User *u);
int user_get_idle_hint(User *u, dual_timestamp *t);
int user_save(User *u);
int user_load(User *u);
int user_kill(User *u, int signo);
int user_check_linger_file(const User *u);
void user_elect_display(User *u);
void user_update_last_session_timer(User *u);

const char* user_state_to_string(UserState s) _const_;
UserState user_state_from_string(const char *s) _pure_;

const char* user_gc_mode_to_string(UserGCMode m) _const_;
UserGCMode user_gc_mode_from_string(const char *s) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_compat_user_tasks_max);
