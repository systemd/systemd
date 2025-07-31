/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "common-signal.h"
#include "journal-file.h"
#include "journald-config.h"
#include "journald-forward.h"
#include "list.h"
#include "ratelimit.h"
#include "socket-util.h"

typedef struct JournalStorageSpace {
        usec_t   timestamp;

        uint64_t available;
        uint64_t limit;

        uint64_t vfs_used; /* space used by journal files */
        uint64_t vfs_available;
} JournalStorageSpace;

typedef struct JournalStorage {
        const char *name;
        char *path;

        JournalMetrics metrics;
        JournalStorageSpace space;
} JournalStorage;

/* This structure will be kept in $RUNTIME_DIRECTORY/seqnum and is mapped by journald, and is used to
 * maintain the sequence number counter with its seqnum ID */
typedef struct SeqnumData {
        sd_id128_t id;
        uint64_t seqnum;
} SeqnumData;

typedef struct Manager {
        char *namespace;

        int syslog_fd;
        int native_fd;
        int stdout_fd;
        int dev_kmsg_fd;
        int audit_fd;
        int hostname_fd;
        int notify_fd;
        int forward_socket_fd;

        sd_event *event;

        sd_event_source *syslog_event_source;
        sd_event_source *native_event_source;
        sd_event_source *stdout_event_source;
        sd_event_source *dev_kmsg_event_source;
        sd_event_source *audit_event_source;
        sd_event_source *sync_event_source;
        sd_event_source *sigusr1_event_source;
        sd_event_source *sigusr2_event_source;
        sd_event_source *sigterm_event_source;
        sd_event_source *sigint_event_source;
        sd_event_source *sigrtmin1_event_source;
        sd_event_source *hostname_event_source;
        sd_event_source *notify_event_source;
        sd_event_source *watchdog_event_source;
        sd_event_source *idle_event_source;
        struct sigrtmin18_info sigrtmin18_info;

        JournalFile *runtime_journal;
        JournalFile *system_journal;
        OrderedHashmap *user_journals;

        SeqnumData *seqnum;

        char *buffer;

        OrderedHashmap *ratelimit_groups_by_id;

        JournalStorage runtime_storage;
        JournalStorage system_storage;

        bool send_watchdog;
        bool sent_notify_ready;
        bool sync_scheduled;

        unsigned n_forward_syslog_missed;
        usec_t last_warn_forward_syslog_missed;

        usec_t oldest_file_usec;

        LIST_HEAD(StdoutStream, stdout_streams);
        LIST_HEAD(StdoutStream, stdout_streams_notify_queue);
        unsigned n_stdout_streams;

        MMapCache *mmap;

        Set *deferred_closes;

        uint64_t *kernel_seqnum;
        RateLimit kmsg_own_ratelimit;

        char machine_id_field[STRLEN("_MACHINE_ID=") + SD_ID128_STRING_MAX];
        char boot_id_field[STRLEN("_BOOT_ID=") + SD_ID128_STRING_MAX];
        char *hostname_field;
        char *namespace_field;
        char *runtime_directory;

        /* Cached cgroup root, so that we don't have to query that all the time */
        char *cgroup_root;

        usec_t watchdog_usec;

        usec_t last_realtime_clock;

        /* Caching of client metadata */
        Hashmap *client_contexts;
        Prioq *client_contexts_lru;

        usec_t last_cache_pid_flush;

        ClientContext *my_context; /* the context of journald itself */
        ClientContext *pid1_context; /* the context of PID 1 */

        sd_varlink_server *varlink_server;

        /* timestamp of most recently processed log messages from each source (CLOCK_REALTIME for the first
         * two, CLOCK_BOOTTIME for the other) */
        usec_t native_timestamp, syslog_timestamp, dev_kmsg_timestamp;

        /* Pending synchronization requests, ordered by their timestamp */
        Prioq *sync_req_realtime_prioq;
        Prioq *sync_req_boottime_prioq;

        /* Pending synchronization requests with non-zero rqlen counter */
        LIST_HEAD(SyncReq, sync_req_pending_rqlen);

        /* These structs are used to preserve configurations set by credentials and command line.
         *   - config - main configuration used by journald manager,
         *   - config_by_cred - configuration set by credentials,
         *   - config_by_conf - configuration set by configuration file,
         *   - config_by_cmdline - configuration set by command line.
         * The priority order of the sub-configurations is:
         *     config_by_cmdline > config_by_conf > config_by_cred
         * where A > B means that if the two have the same setting, A's value overrides B's value for that
         * setting. */
        JournalConfig config;
        JournalConfig config_by_cred;
        JournalConfig config_by_conf;
        JournalConfig config_by_cmdline;
} Manager;

#define MANAGER_MACHINE_ID(s) ((s)->machine_id_field + STRLEN("_MACHINE_ID="))

/* Extra fields for any log messages */
#define N_IOVEC_META_FIELDS 24

/* Extra fields for log messages that contain OBJECT_PID= (i.e. log about another process) */
#define N_IOVEC_OBJECT_FIELDS 18

/* Maximum number of fields we'll add in for driver (i.e. internal) messages */
#define N_IOVEC_PAYLOAD_FIELDS 16

/* kmsg: Maximum number of extra fields we'll import from the kernel's /dev/kmsg */
#define N_IOVEC_KERNEL_FIELDS 64

/* kmsg: Maximum number of extra fields we'll import from udev's devices */
#define N_IOVEC_UDEV_FIELDS 32

/* audit: Maximum number of extra fields we'll import from audit messages */
#define N_IOVEC_AUDIT_FIELDS 64

void manager_dispatch_message(Manager *m, struct iovec *iovec, size_t n, size_t k, ClientContext *c, const struct timeval *tv, int priority, pid_t object_pid);
void manager_driver_message_internal(Manager *m, pid_t object_pid, const char *format, ...) _sentinel_;
#define manager_driver_message(...) manager_driver_message_internal(__VA_ARGS__, NULL)

int manager_new(Manager **ret);
int manager_set_namespace(Manager *m, const char *namespace);
int manager_init(Manager *m);
Manager* manager_free(Manager *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);
void manager_full_sync(Manager *m, bool wait);
void manager_vacuum(Manager *m, bool verbose);
void manager_rotate(Manager *m);
void manager_full_rotate(Manager *m);
int manager_flush_to_var(Manager *m, bool require_flag_file);
void manager_full_flush(Manager *m);
int manager_relinquish_var(Manager *m);
void manager_maybe_append_tags(Manager *m);
int manager_process_datagram(sd_event_source *es, int fd, uint32_t revents, void *userdata);
void manager_space_usage_message(Manager *m, JournalStorage *storage);

int manager_start_or_stop_idle_timer(Manager *m);
void manager_reopen_journals(Manager *m, const JournalConfig *old);

int manager_map_seqnum_file(Manager *m, const char *fname, size_t size, void **ret);
void manager_unmap_seqnum_file(void *p, size_t size);
int manager_unlink_seqnum_file(Manager *m, const char *fname);
