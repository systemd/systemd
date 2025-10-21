/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journal-file.h"
#include "journald-forward.h"
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
        int enabled;
        uint64_t threshold_bytes;
} JournalCompressOptions;

typedef enum AuditSetMode {
        AUDIT_NO = 0, /* Disables the kernel audit subsystem on start. */
        AUDIT_YES,    /* Enables the kernel audit subsystem on start. */
        AUDIT_KEEP,   /* Keep the current kernel audit subsystem state. */
        _AUDIT_SET_MODE_MAX,
        _AUDIT_SET_MODE_INVALID = -EINVAL,
} AuditSetMode;

typedef struct JournalConfig {
        /* Storage=, cred: journal.storage */
        Storage storage;
        /* Compress= */
        JournalCompressOptions compress;
        /* Seal= */
        int seal;
        /* ReadKMsg= */
        int read_kmsg;
        /* Audit= */
        AuditSetMode set_audit;
        /* SyncIntervalSec= */
        usec_t sync_interval_usec;
        /* RateLimitIntervalSec= */
        usec_t ratelimit_interval;
        /* RateLimitBurst= */
        unsigned ratelimit_burst;
        /* SystemMaxUse=, SystemMaxFileSize=, SystemKeepFree=, SystemMaxFiles= */
        JournalMetrics system_storage_metrics;
        /* RuntimeMaxUse=, RuntimeMaxFileSize=, RuntimeKeepFree=, RuntimeMaxFiles= */
        JournalMetrics runtime_storage_metrics;
        /* MaxRetentionSec= */
        usec_t max_retention_usec;
        /* MaxFileSec= */
        usec_t max_file_usec;
        /* ForwardToSyslog=, proc: systemd.journald.forward_to_syslog */
        int forward_to_syslog;
        /* ForwardToKMsg=, proc: systemd.journald.forward_to_kmsg */
        int forward_to_kmsg;
        /* ForwardToConsole=, proc: systemd.journald.forward_to_console */
        int forward_to_console;
        /* ForwardToWall=, proc: systemd.journald.forward_to_wall */
        int forward_to_wall;
        /* ForwardToSocket=, cred: journal.forward_to_socket */
        SocketAddress forward_to_socket;
        /* TTYPath= */
        char *tty_path;
        /* MaxLevelStore=, proc: systemd.journald.max_level_store */
        int max_level_store;
        /* MaxLevelSyslog=, proc: systemd.journald.max_level_syslog */
        int max_level_syslog;
        /* MaxLevelKMsg=, proc: systemd.journald.max_level_kmsg */
        int max_level_kmsg;
        /* MaxLevelConsole=, proc: systemd.journald.max_level_console */
        int max_level_console;
        /* MaxLevelWall=, systemd.journald.max_level_wall */
        int max_level_wall;
        /* MaxLevelSocket=, systemd.journald.max_level_socket */
        int max_level_socket;
        /* SplitMode= */
        SplitMode split_mode;
        /* LineMax= */
        size_t line_max;
} JournalConfig;

void journal_config_done(JournalConfig *c);
void journal_config_set_defaults(JournalConfig *c);
void manager_merge_configs(Manager *m);
void manager_load_config(Manager *m);
int manager_dispatch_reload_signal(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata);

/* Defined in generated journald-gperf.c */
const struct ConfigPerfItem* journald_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

const char* storage_to_string(Storage s) _const_;
Storage storage_from_string(const char *s) _pure_;

const char* split_mode_to_string(SplitMode s) _const_;
SplitMode split_mode_from_string(const char *s) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_storage);
CONFIG_PARSER_PROTOTYPE(config_parse_line_max);
CONFIG_PARSER_PROTOTYPE(config_parse_compress);
CONFIG_PARSER_PROTOTYPE(config_parse_forward_to_socket);
CONFIG_PARSER_PROTOTYPE(config_parse_split_mode);
CONFIG_PARSER_PROTOTYPE(config_parse_audit_set_mode);
