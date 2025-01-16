/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Home Home;

#include "hashmap.h"
#include "homed-manager.h"
#include "homed-operation.h"
#include "list.h"
#include "ordered-set.h"
#include "stat-util.h"
#include "user-record.h"

typedef enum HomeState {
        HOME_UNFIXATED,               /* home exists, but local record does not */
        HOME_ABSENT,                  /* local record exists, but home does not */
        HOME_INACTIVE,                /* record and home exist, but is not logged in */
        HOME_DIRTY,                   /* like HOME_INACTIVE, but the home directory wasn't cleanly deactivated */
        HOME_FIXATING,                /* generating local record from home */
        HOME_FIXATING_FOR_ACTIVATION, /* fixating in order to activate soon */
        HOME_FIXATING_FOR_ACQUIRE,    /* fixating because Acquire() was called */
        HOME_ACTIVATING,
        HOME_ACTIVATING_FOR_ACQUIRE,  /* activating because Acquire() was called */
        HOME_DEACTIVATING,
        HOME_ACTIVE,                  /* logged in right now */
        HOME_LINGERING,               /* not logged in anymore, but we didn't manage to deactivate (because some process keeps it busy?) but we'll keep trying */
        HOME_LOCKING,
        HOME_LOCKED,
        HOME_UNLOCKING,
        HOME_UNLOCKING_FOR_ACQUIRE,   /* unlocking because Acquire() was called */
        HOME_CREATING,
        HOME_REMOVING,
        HOME_UPDATING,
        HOME_UPDATING_WHILE_ACTIVE,
        HOME_RESIZING,
        HOME_RESIZING_WHILE_ACTIVE,
        HOME_PASSWD,
        HOME_PASSWD_WHILE_ACTIVE,
        HOME_AUTHENTICATING,
        HOME_AUTHENTICATING_WHILE_ACTIVE,
        HOME_AUTHENTICATING_FOR_ACQUIRE,  /* authenticating because Acquire() was called */
        _HOME_STATE_MAX,
        _HOME_STATE_INVALID = -EINVAL,
} HomeState;

static inline bool HOME_STATE_IS_ACTIVE(HomeState state) {
        return IN_SET(state,
                      HOME_ACTIVE,
                      HOME_LINGERING,
                      HOME_UPDATING_WHILE_ACTIVE,
                      HOME_RESIZING_WHILE_ACTIVE,
                      HOME_PASSWD_WHILE_ACTIVE,
                      HOME_AUTHENTICATING_WHILE_ACTIVE,
                      HOME_AUTHENTICATING_FOR_ACQUIRE);
}

static inline bool HOME_STATE_IS_EXECUTING_OPERATION(HomeState state) {
        return IN_SET(state,
                      HOME_FIXATING,
                      HOME_FIXATING_FOR_ACTIVATION,
                      HOME_FIXATING_FOR_ACQUIRE,
                      HOME_ACTIVATING,
                      HOME_ACTIVATING_FOR_ACQUIRE,
                      HOME_DEACTIVATING,
                      HOME_LOCKING,
                      HOME_UNLOCKING,
                      HOME_UNLOCKING_FOR_ACQUIRE,
                      HOME_CREATING,
                      HOME_REMOVING,
                      HOME_UPDATING,
                      HOME_UPDATING_WHILE_ACTIVE,
                      HOME_RESIZING,
                      HOME_RESIZING_WHILE_ACTIVE,
                      HOME_PASSWD,
                      HOME_PASSWD_WHILE_ACTIVE,
                      HOME_AUTHENTICATING,
                      HOME_AUTHENTICATING_WHILE_ACTIVE,
                      HOME_AUTHENTICATING_FOR_ACQUIRE);
}

static inline bool HOME_STATE_SHALL_PIN(HomeState state) {
        /* Like HOME_STATE_IS_ACTIVE() – but HOME_LINGERING is missing! */
        return IN_SET(state,
                      HOME_ACTIVE,
                      HOME_UPDATING_WHILE_ACTIVE,
                      HOME_RESIZING_WHILE_ACTIVE,
                      HOME_PASSWD_WHILE_ACTIVE,
                      HOME_AUTHENTICATING_WHILE_ACTIVE,
                      HOME_AUTHENTICATING_FOR_ACQUIRE);
}

#define HOME_STATE_SHALL_REBALANCE(state) HOME_STATE_SHALL_PIN(state)

static inline bool HOME_STATE_MAY_RETRY_DEACTIVATE(HomeState state) {
        /* Indicates when to leave the deactivate retry timer active */
        return IN_SET(state,
                      HOME_ACTIVE,
                      HOME_LINGERING,
                      HOME_DEACTIVATING,
                      HOME_LOCKING,
                      HOME_UNLOCKING,
                      HOME_UNLOCKING_FOR_ACQUIRE,
                      HOME_UPDATING_WHILE_ACTIVE,
                      HOME_RESIZING_WHILE_ACTIVE,
                      HOME_PASSWD_WHILE_ACTIVE,
                      HOME_AUTHENTICATING_WHILE_ACTIVE,
                      HOME_AUTHENTICATING_FOR_ACQUIRE);
}

struct Home {
        Manager *manager;

        /* The fields this record can be looked up by. This is kinda redundant, as the same information is
         * available in the .record field, but we keep separate copies of these keys to make memory
         * management for the hashmaps easier. */
        char *user_name;
        char **aliases;
        uid_t uid;

        char *sysfs; /* When found via plugged in device, the sysfs path to it */

        /* Note that the 'state' field is only set to a state while we are doing something (i.e. activating,
         * deactivating, creating, removing, and such), or when the home is an "unfixated" one. When we are
         * done with an operation we invalidate the state. This is hint for home_get_state() to check the
         * state on request as needed from the mount table and similar. */
        HomeState state;
        int signed_locally; /* signed only by us */

        UserRecord *record;

        pid_t worker_pid;
        int worker_stdout_fd;
        sd_event_source *worker_event_source;
        int worker_error_code;

        /* The message we are currently processing, and thus need to reply to on completion */
        Operation *current_operation;

        /* Stores the raw, plaintext passwords, but only for short periods of time */
        UserRecord *secret;

        /* When we create a home area and that fails, we should possibly unregister the record altogether
         * again, which is remembered in this boolean. */
        bool unregister_on_failure;

        /* The reading side of a FIFO stored in /run/systemd/home/, the writing side being used for reference
         * counting. The references dropped to zero as soon as we see EOF. This concept exists twice: once
         * for clients that are fine if we suspend the home directory on system suspend, and once for clients
         * that are not ok with that. This allows us to determine for each home whether there are any clients
         * that support unsuspend. */
        sd_event_source *ref_event_source_please_suspend;
        sd_event_source *ref_event_source_dont_suspend;

        /* Any pending operations we still need to execute. These are for operations we want to queue if we
         * can't execute them right-away. */
        OrderedSet *pending_operations;

        /* A defer event source that processes pending acquire/release/eof events. We have a common
         * dispatcher that processes all three kinds of events. */
        sd_event_source *pending_event_source;

        /* Did we send out a D-Bus notification about this entry? */
        bool announced;

        /* Used to coalesce bus PropertiesChanged events */
        sd_event_source *deferred_change_event_source;

        /* An fd to the top-level home directory we keep while logged in, to keep the dir busy */
        int pin_fd;

        /* A time event used to repeatedly try to unmount home dir after use if it didn't work on first try */
        sd_event_source *retry_deactivate_event_source;

        /* An fd that locks the backing file of LUKS home dirs with a BSD lock. */
        int luks_lock_fd;

        /* Space metrics during rebalancing */
        uint64_t rebalance_size, rebalance_usage, rebalance_free, rebalance_min, rebalance_weight, rebalance_goal;

        /* Whether a rebalance operation is pending */
        bool rebalance_pending;
};

int home_new(Manager *m, UserRecord *hr, const char *sysfs, Home **ret);
Home *home_free(Home *h);

DEFINE_TRIVIAL_CLEANUP_FUNC(Home*, home_free);

int home_set_record(Home *h, UserRecord *hr);
int home_save_record(Home *h);
int home_unlink_record(Home *h);

int home_fixate(Home *h, UserRecord *secret, sd_bus_error *error);
int home_activate(Home *h, bool if_referenced, UserRecord *secret, sd_bus_error *error);
int home_authenticate(Home *h, UserRecord *secret, sd_bus_error *error);
int home_deactivate(Home *h, bool force, sd_bus_error *error);
int home_create(Home *h, UserRecord *secret, Hashmap *blobs, uint64_t flags, sd_bus_error *error);
int home_remove(Home *h, sd_bus_error *error);
int home_update(Home *h, UserRecord *new_record, Hashmap *blobs, uint64_t flags, sd_bus_error *error);
int home_resize(Home *h, uint64_t disk_size, UserRecord *secret, sd_bus_error *error);
int home_passwd(Home *h, UserRecord *new_secret, UserRecord *old_secret, sd_bus_error *error);
int home_unregister(Home *h, sd_bus_error *error);
int home_lock(Home *h, sd_bus_error *error);
int home_unlock(Home *h, UserRecord *secret, sd_bus_error *error);

bool home_is_referenced(Home *h);
bool home_shall_suspend(Home *h);
HomeState home_get_state(Home *h);

int home_get_disk_status(
                Home *h,
                uint64_t *ret_disk_size,
                uint64_t *ret_disk_usage,
                uint64_t *ret_disk_free,
                uint64_t *ret_disk_ceiling,
                uint64_t *ret_disk_floor,
                statfs_f_type_t *ret_fstype,
                mode_t *ret_access_mode);

void home_process_notify(Home *h, char **l, int fd);

int home_killall(Home *h);

int home_augment_status(Home *h, UserRecordLoadFlags flags, UserRecord **ret);

int home_create_fifo(Home *h, bool please_suspend);
int home_schedule_operation(Home *h, Operation *o, sd_bus_error *error);

int home_auto_login(Home *h, char ***ret_seats);

int home_set_current_message(Home *h, sd_bus_message *m);

int home_wait_for_worker(Home *h);

bool home_shall_rebalance(Home *h);

bool home_is_busy(Home *h);

const char* home_state_to_string(HomeState state);
HomeState home_state_from_string(const char *s);
