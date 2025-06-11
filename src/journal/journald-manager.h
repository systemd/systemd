/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "common-signal.h"
#include "journal-file.h"
#include "journald-forward.h"
#include "list.h"
#include "ratelimit.h"
#include "socket-util.h"

typedef enum Storage {
        STORAGE_AUTO,
        STORAGE_VOLATILE,
        STORAGE_PERSISTENT,
        STORAGE_NONE,
        _STORAGE_MAX,
        _STORAGE_INVALID = -EINVAL,
} Storage;

typedef enum SplitMode {
        SPLIT_UID,
        SPLIT_LOGIN, /* deprecated */
        SPLIT_NONE,
        _SPLIT_MAX,
        _SPLIT_INVALID = -EINVAL,
} SplitMode;

typedef struct JournalCompressOptions {
        bool enabled;
        uint64_t threshold_bytes;
} JournalCompressOptions;

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

typedef struct JournalConfig {
        SocketAddress forward_to_socket;
        Storage storage;

        bool forward_to_kmsg;
        bool forward_to_syslog;
        bool forward_to_console;
        bool forward_to_wall;

        int max_level_store;
        int max_level_syslog;
        int max_level_kmsg;
        int max_level_console;
        int max_level_wall;
        int max_level_socket;
} JournalConfig;

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
        usec_t sync_interval_usec;
        usec_t ratelimit_interval;
        unsigned ratelimit_burst;

        JournalStorage runtime_storage;
        JournalStorage system_storage;

        JournalCompressOptions compress;
        int set_audit;
        bool seal;
        bool read_kmsg;

        bool send_watchdog;
        bool sent_notify_ready;
        bool sync_scheduled;

        unsigned n_forward_syslog_missed;
        usec_t last_warn_forward_syslog_missed;

        usec_t max_retention_usec;
        usec_t max_file_usec;
        usec_t oldest_file_usec;

        LIST_HEAD(StdoutStream, stdout_streams);
        LIST_HEAD(StdoutStream, stdout_streams_notify_queue);
        unsigned n_stdout_streams;

        char *tty_path;

        SplitMode split_mode;

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

        size_t line_max;

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

#define JOURNAL_CONFIG_INIT                                                                     \
        (JournalConfig) {                                                                       \
                .forward_to_socket = (SocketAddress) { .sockaddr.sa.sa_family = AF_UNSPEC },    \
                .storage = _STORAGE_INVALID,                                                    \
                .forward_to_kmsg = false,                                                       \
                .forward_to_syslog = false,                                                     \
                .forward_to_console = false,                                                    \
                .forward_to_wall = false,                                                       \
                .max_level_store = -1,                                                          \
                .max_level_syslog = -1,                                                         \
                .max_level_kmsg = -1,                                                           \
                .max_level_console = -1,                                                        \
                .max_level_wall = -1,                                                           \
        }

/* gperf lookup function */
const struct ConfigPerfItem* journald_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

CONFIG_PARSER_PROTOTYPE(config_parse_storage);
CONFIG_PARSER_PROTOTYPE(config_parse_line_max);
CONFIG_PARSER_PROTOTYPE(config_parse_compress);
CONFIG_PARSER_PROTOTYPE(config_parse_forward_to_socket);

const char* storage_to_string(Storage s) _const_;
Storage storage_from_string(const char *s) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_split_mode);

const char* split_mode_to_string(SplitMode s) _const_;
SplitMode split_mode_from_string(const char *s) _pure_;

int manager_new(Manager **ret, const char *namespace);
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

int manager_map_seqnum_file(Manager *m, const char *fname, size_t size, void **ret);
