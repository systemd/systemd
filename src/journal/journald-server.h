/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <sys/types.h>

#include "sd-event.h"
#include "sd-varlink.h"

typedef struct Server Server;

#include "common-signal.h"
#include "conf-parser.h"
#include "hashmap.h"
#include "journal-file.h"
#include "journald-context.h"
#include "journald-stream.h"
#include "list.h"
#include "prioq.h"
#include "ratelimit.h"
#include "socket-util.h"
#include "time-util.h"

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

struct Server {
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
        bool seal;
        bool read_kmsg;
        int set_audit;

        bool forward_to_kmsg;
        bool forward_to_syslog;
        bool forward_to_console;
        bool forward_to_wall;
        SocketAddress forward_to_socket;

        unsigned n_forward_syslog_missed;
        usec_t last_warn_forward_syslog_missed;

        usec_t max_retention_usec;
        usec_t max_file_usec;
        usec_t oldest_file_usec;

        LIST_HEAD(StdoutStream, stdout_streams);
        LIST_HEAD(StdoutStream, stdout_streams_notify_queue);
        unsigned n_stdout_streams;

        char *tty_path;

        int max_level_store;
        int max_level_syslog;
        int max_level_kmsg;
        int max_level_console;
        int max_level_wall;
        int max_level_socket;

        Storage storage;
        SplitMode split_mode;

        MMapCache *mmap;

        Set *deferred_closes;

        uint64_t *kernel_seqnum;
        bool dev_kmsg_readable:1;
        RateLimit kmsg_own_ratelimit;

        bool send_watchdog:1;
        bool sent_notify_ready:1;
        bool sync_scheduled:1;

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
};

#define SERVER_MACHINE_ID(s) ((s)->machine_id_field + STRLEN("_MACHINE_ID="))

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

void server_dispatch_message(Server *s, struct iovec *iovec, size_t n, size_t m, ClientContext *c, const struct timeval *tv, int priority, pid_t object_pid);
void server_driver_message(Server *s, pid_t object_pid, const char *message_id, const char *format, ...) _sentinel_ _printf_(4,0);

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

int server_new(Server **ret);
int server_init(Server *s, const char *namespace);
Server* server_free(Server *s);
DEFINE_TRIVIAL_CLEANUP_FUNC(Server*, server_free);
void server_vacuum(Server *s, bool verbose);
void server_rotate(Server *s);
int server_flush_to_var(Server *s, bool require_flag_file);
void server_maybe_append_tags(Server *s);
int server_process_datagram(sd_event_source *es, int fd, uint32_t revents, void *userdata);
void server_space_usage_message(Server *s, JournalStorage *storage);

int server_start_or_stop_idle_timer(Server *s);

int server_map_seqnum_file(Server *s, const char *fname, size_t size, void **ret);
