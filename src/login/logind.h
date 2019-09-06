/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#include "sd-bus.h"
#include "sd-device.h"
#include "sd-event.h"

#include "conf-parser.h"
#include "hashmap.h"
#include "list.h"
#include "set.h"
#include "time-util.h"

typedef struct Manager Manager;

#include "logind-action.h"
#include "logind-button.h"
#include "logind-device.h"
#include "logind-inhibit.h"

struct Manager {
        sd_event *event;
        sd_bus *bus;

        Hashmap *devices;
        Hashmap *seats;
        Hashmap *sessions;
        Hashmap *sessions_by_leader;
        Hashmap *users;
        Hashmap *inhibitors;
        Hashmap *buttons;
        Hashmap *brightness_writers;

        LIST_HEAD(Seat, seat_gc_queue);
        LIST_HEAD(Session, session_gc_queue);
        LIST_HEAD(User, user_gc_queue);

        sd_device_monitor *device_seat_monitor, *device_monitor, *device_vcsa_monitor, *device_button_monitor;

        sd_event_source *console_active_event_source;

#if ENABLE_UTMP
        sd_event_source *utmp_event_source;
#endif

        int console_active_fd;

        unsigned n_autovts;

        unsigned reserve_vt;
        int reserve_vt_fd;

        Seat *seat0;

        char **kill_only_users, **kill_exclude_users;
        bool kill_user_processes;

        unsigned long session_counter;
        unsigned long inhibit_counter;

        Hashmap *session_units;
        Hashmap *user_units;

        usec_t inhibit_delay_max;
        usec_t user_stop_delay;

        /* If an action is currently being executed or is delayed,
         * this is != 0 and encodes what is being done */
        InhibitWhat action_what;

        /* If a shutdown/suspend was delayed due to a inhibitor this
           contains the unit name we are supposed to start after the
           delay is over */
        const char *action_unit;

        /* If a shutdown/suspend is currently executed, then this is
         * the job of it */
        char *action_job;
        sd_event_source *inhibit_timeout_source;

        char *scheduled_shutdown_type;
        usec_t scheduled_shutdown_timeout;
        sd_event_source *scheduled_shutdown_timeout_source;
        uid_t scheduled_shutdown_uid;
        char *scheduled_shutdown_tty;
        sd_event_source *nologin_timeout_source;
        bool unlink_nologin;

        char *wall_message;
        unsigned enable_wall_messages;
        sd_event_source *wall_message_timeout_source;

        bool shutdown_dry_run;

        sd_event_source *idle_action_event_source;
        usec_t idle_action_usec;
        usec_t idle_action_not_before_usec;
        HandleAction idle_action;

        HandleAction handle_power_key;
        HandleAction handle_suspend_key;
        HandleAction handle_hibernate_key;
        HandleAction handle_lid_switch;
        HandleAction handle_lid_switch_ep;
        HandleAction handle_lid_switch_docked;

        bool power_key_ignore_inhibited;
        bool suspend_key_ignore_inhibited;
        bool hibernate_key_ignore_inhibited;
        bool lid_switch_ignore_inhibited;

        bool remove_ipc;

        Hashmap *polkit_registry;

        usec_t holdoff_timeout_usec;
        sd_event_source *lid_switch_ignore_event_source;

        uint64_t runtime_dir_size;
        uint64_t user_tasks_max;
        uint64_t sessions_max;
        uint64_t inhibitors_max;
};

void manager_reset_config(Manager *m);
int manager_parse_config_file(Manager *m);

int manager_add_device(Manager *m, const char *sysfs, bool master, Device **ret_device);
int manager_add_button(Manager *m, const char *name, Button **ret_button);
int manager_add_seat(Manager *m, const char *id, Seat **ret_seat);
int manager_add_session(Manager *m, const char *id, Session **ret_session);
int manager_add_user(Manager *m, uid_t uid, gid_t gid, const char *name, const char *home, User **ret_user);
int manager_add_user_by_name(Manager *m, const char *name, User **ret_user);
int manager_add_user_by_uid(Manager *m, uid_t uid, User **ret_user);
int manager_add_inhibitor(Manager *m, const char* id, Inhibitor **ret_inhibitor);

int manager_process_seat_device(Manager *m, sd_device *d);
int manager_process_button_device(Manager *m, sd_device *d);

int manager_spawn_autovt(Manager *m, unsigned vtnr);

bool manager_shall_kill(Manager *m, const char *user);

int manager_get_idle_hint(Manager *m, dual_timestamp *t);

int manager_get_user_by_pid(Manager *m, pid_t pid, User **user);
int manager_get_session_by_pid(Manager *m, pid_t pid, Session **session);

bool manager_is_lid_closed(Manager *m);
bool manager_is_docked_or_external_displays(Manager *m);
bool manager_is_on_external_power(void);
bool manager_all_buttons_ignored(Manager *m);

int manager_read_utmp(Manager *m);
void manager_connect_utmp(Manager *m);
void manager_reconnect_utmp(Manager *m);

extern const sd_bus_vtable manager_vtable[];

/* gperf lookup function */
const struct ConfigPerfItem* logind_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

int manager_set_lid_switch_ignore(Manager *m, usec_t until);

CONFIG_PARSER_PROTOTYPE(config_parse_n_autovts);
CONFIG_PARSER_PROTOTYPE(config_parse_tmpfs_size);

int manager_setup_wall_message_timer(Manager *m);
bool logind_wall_tty_filter(const char *tty, void *userdata);
