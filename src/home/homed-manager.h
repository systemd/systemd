/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <openssl/evp.h>

#include "sd-bus.h"
#include "sd-device.h"
#include "sd-event.h"
#include "sd-varlink.h"

typedef struct Manager Manager;

#include "hashmap.h"
#include "homed-home.h"

/* The LUKS free disk space rebalancing logic goes through this state machine */
typedef enum RebalanceState {
        REBALANCE_OFF,       /* No rebalancing enabled */
        REBALANCE_IDLE,      /* Rebalancing enabled, but currently nothing scheduled */
        REBALANCE_WAITING,   /* Rebalancing has been requested for a later point in time */
        REBALANCE_PENDING,   /* Rebalancing has been requested and will be executed ASAP */
        REBALANCE_SHRINKING, /* Rebalancing ongoing, and we are running all shrinking operations */
        REBALANCE_GROWING,   /* Rebalancing ongoing, and we are running all growing operations */
        _REBALANCE_STATE_MAX,
        _REBALANCE_STATE_INVALID = -1,
} RebalanceState;

struct Manager {
        sd_event *event;
        sd_bus *bus;

        Hashmap *polkit_registry;

        Hashmap *homes_by_uid;
        Hashmap *homes_by_name;
        Hashmap *homes_by_worker_pid;
        Hashmap *homes_by_sysfs;

        bool scan_slash_home;
        UserStorage default_storage;
        char *default_file_system_type;

        sd_event_source *inotify_event_source;

        /* An event source we receive sd_notify() messages from our worker from */
        sd_event_source *notify_socket_event_source;

        sd_device_monitor *device_monitor;

        sd_event_source *deferred_rescan_event_source;
        sd_event_source *deferred_gc_event_source;
        sd_event_source *deferred_auto_login_event_source;

        sd_event_source *rebalance_event_source;

        Home *gc_focus;

        sd_varlink_server *varlink_server;
        char *userdb_service;

        EVP_PKEY *private_key; /* actually a pair of private and public key */
        Hashmap *public_keys; /* key name [char*] → public key [EVP_PKEY*] */

        RebalanceState rebalance_state;
        usec_t rebalance_interval_usec;

        /* In order to allow synchronous rebalance requests via bus calls we maintain two pools of bus
         * messages: 'rebalance_pending_methods' are the method calls we are currently operating on and
         * running a rebalancing operation for. 'rebalance_queued_method_calls' are the method calls that
         * have been queued since then and that we'll operate on once we complete the current run. */
        Set *rebalance_pending_method_calls, *rebalance_queued_method_calls;
};

int manager_new(Manager **ret);
Manager* manager_free(Manager *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

int manager_startup(Manager *m);

int manager_augment_record_with_uid(Manager *m, UserRecord *hr);

int manager_enqueue_rescan(Manager *m);
int manager_enqueue_gc(Manager *m, Home *focus);

int manager_schedule_rebalance(Manager *m, bool immediately);
int manager_reschedule_rebalance(Manager *m);

int manager_verify_user_record(Manager *m, UserRecord *hr);

int manager_acquire_key_pair(Manager *m);
int manager_sign_user_record(Manager *m, UserRecord *u, UserRecord **ret, sd_bus_error *error);

int bus_manager_emit_auto_login_changed(Manager *m);

int manager_get_home_by_name(Manager *m, const char *user_name, Home **ret);
