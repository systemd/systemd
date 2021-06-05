/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <openssl/evp.h>

#include "sd-bus.h"
#include "sd-device.h"
#include "sd-event.h"

typedef struct Manager Manager;

#include "hashmap.h"
#include "homed-home.h"
#include "varlink.h"

#define HOME_UID_MIN 60001
#define HOME_UID_MAX 60513

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

        Home *gc_focus;

        VarlinkServer *varlink_server;
        char *userdb_service;

        EVP_PKEY *private_key; /* actually a pair of private and public key */
        Hashmap *public_keys; /* key name [char*] → publick key [EVP_PKEY*] */
};

int manager_new(Manager **ret);
Manager* manager_free(Manager *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

int manager_startup(Manager *m);

int manager_augment_record_with_uid(Manager *m, UserRecord *hr);

int manager_enqueue_rescan(Manager *m);
int manager_enqueue_gc(Manager *m, Home *focus);

int manager_verify_user_record(Manager *m, UserRecord *hr);

int manager_acquire_key_pair(Manager *m);
int manager_sign_user_record(Manager *m, UserRecord *u, UserRecord **ret, sd_bus_error *error);

int bus_manager_emit_auto_login_changed(Manager *m);
