/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/devlink.h>

#include "list.h"

#include "devlink-key.h"
#include "devlink-match.h"
#include "devlinkd-manager.h"

#define DEVLINK_COMMON_SECTIONS "Match\0"

typedef struct Devlink {
        DevlinkKey key;
        Manager *manager;
        unsigned n_ref;
        char *filename;
        char **dropins;
        bool in_hashmap;
        bool in_ifname_tracker;
        bool expected_removal;
        sd_event_source *expected_removal_timeout_event_source;
        Hashmap *stats_by_path;
        LIST_FIELDS(struct Devlink, ifname_tracker);
} Devlink;

typedef enum DevlinkMonitorCommandRetval {
        /* Success. */
        DEVLINK_MONITOR_COMMAND_RETVAL_OK,
        /* Indicate that the object should be deleted. */
        DEVLINK_MONITOR_COMMAND_RETVAL_DELETE,
} DevlinkMonitorCommandRetval;

typedef struct DevlinkMonitorCommand {
        enum devlink_command cmd;
        /* Returns negative value in case of error, on success
         * a value of enum DevlinkMonitorCommandRetval. */
        int (*msg_process)(Devlink *devlink, DevlinkKey *lookup_key,
                           sd_netlink_message *message);
        /* Command is going to be used for enumeration if this is true. */
        bool enumerate;
        /* For buggy objects that send reply with wrong cmd, specify cmd value used
         * to override enumeration reply cmd, 0 in case no override needed. */
        enum devlink_command cmd_override;
} DevlinkMonitorCommand;

typedef struct DevlinkVTable {
        /* How much memory does an object of this unit type need. */
        size_t object_size;

        /* Config file sections this devlnk kind understands, separated
         * by NUL chars. */
        const char *sections;

        /* Matchsets bitfields, ended by 0 */
        const DevlinkMatchSet *matchsets;

        /* Allocate object on demand, in opposite to the ones created during config files loading. */
        bool alloc_on_demand;

        void (*init)(Devlink *devlink);

        /* This should free all kind-specific variables. It should be
         * idempotent. */
        void (*done)(Devlink *devlink);

        int (*log_prefix)(const Devlink *devlink, char *buf, int len);

        int (*config_verify)(const Devlink *devlink, const char *filename);

        /* Array of monitor commands, the first one is used
         * for enumeration messages processing. */
        const DevlinkMonitorCommand *genl_monitor_cmds;
        unsigned genl_monitor_cmds_count;

        /* For buggy objects that don't send notification, there
         * is a need for periodic enumerations. */
        bool genl_need_periodic_enumeration;
} DevlinkVTable;

extern const DevlinkVTable * const devlink_vtable[_DEVLINK_KIND_MAX];

#define _DEVLINK_VTABLE(kind) (kind != _DEVLINK_KIND_INVALID ? devlink_vtable[kind] : NULL)
#define DEVLINK_VTABLE(n) _DEVLINK_VTABLE((n)->key.kind)

#define devlink_for_each_kind(_iterator)                                  \
        for (_iterator = 0;                                               \
             _iterator < _DEVLINK_KIND_MAX;                               \
             _iterator++)

/* For casting a devlink into the various devlink kinds */
#define DEFINE_DEVLINK_CAST(type, structname)                             \
        static inline structname* DEVLINK_##type(Devlink *devlink) {      \
                if (_unlikely_(!devlink ||                                \
                               devlink->key.kind != DEVLINK_KIND_##type)) \
                        return NULL;                                      \
                                                                          \
                return (structname*) devlink;                             \
        }                                                                 \
        static inline const structname*                                   \
        DEVLINK_CONST_##type(const Devlink *devlink) {                    \
                if (_unlikely_(!devlink ||                                \
                               devlink->key.kind != DEVLINK_KIND_##type)) \
                        return NULL;                                      \
                                                                          \
                return (const structname*) devlink;                       \
        }

/* For casting the various devlink kinds into a devlink */
#define DEVLINK(devlink) (&(devlink)->meta)

#define devlink_log_internal(key, level, error, file, line, func, fmt, ...)        \
        ({                                                                          \
                const DevlinkKey *__key = (key);                                    \
                int __level = (level), __devlink_macro_error = (error);             \
                char __buf[LINE_MAX], *__pos = __buf;                               \
                int __len = sizeof(__buf);                                          \
                                                                                    \
                BUFFER_APPEND(__pos, __len, "%s", devlink_kind_to_string(__key->kind)); \
                devlink_match_log_prefix(&__pos, &__len, &__key->match, __key->matchset); \
                BUFFER_APPEND(__pos, __len, ": ");                                  \
                (void) snprintf(__pos, __len, fmt, ##__VA_ARGS__);                  \
                                                                                    \
                log_internal(__level, __devlink_macro_error, file, line, func, "%s", __buf); \
        })

Devlink *devlink_unref(Devlink *devlink);
Devlink *devlink_ref(Devlink *devlink);
DEFINE_TRIVIAL_DESTRUCTOR(devlink_destroy_callback, Devlink, devlink_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(Devlink*, devlink_unref);

Devlink *devlink_get_may_create(Manager *m, DevlinkKey *key);
Devlink *devlink_get_may_create_filtered(Manager *m, DevlinkKey *key, DevlinkMatchSet matchset);
Devlink *devlink_get(Manager *m, DevlinkKey *key);

int devlink_config_load(Manager *m);
int devlink_config_reload(Manager *m);
void devlink_genl_process_message(sd_netlink_message *message,
                                  Manager *m, DevlinkKind kind,
                                  const DevlinkMonitorCommand *monitor_cmd);

#define devlink_genl_message_new(cont, cmd, ret) \
        sd_genl_message_new(cont->manager->genl, DEVLINK_GENL_NAME, cmd, ret)

void devlink_expected_removal_set(Devlink *devlink);
void devlink_expected_removal_clear(Devlink *devlink);

/* gperf */
const struct ConfigPerfItem* devlink_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

#define log_devlink_full_errno_zerook(cont, level, error, ...)                      \
        ({                                                                          \
                errno = ERRNO_VALUE(error);                                         \
                devlink_log_internal(&cont->key, level, error, PROJECT_FILE,        \
                                     __LINE__, __func__, ##__VA_ARGS__);            \
        })

#define log_devlink_full_errno(cont, level, error, ...)                             \
        ({                                                                          \
                int _error = (error);                                               \
                ASSERT_NON_ZERO(_error);                                            \
                log_devlink_full_errno_zerook(cont, level, _error, __VA_ARGS__);    \
        })

#define log_devlink_full(cont, level, ...) (void) log_devlink_full_errno_zerook(cont, level, 0, __VA_ARGS__)

#define log_devlink_debug(cont, ...)   log_devlink_full(cont, LOG_DEBUG, __VA_ARGS__)
#define log_devlink_info(cont, ...)    log_devlink_full(cont, LOG_INFO, __VA_ARGS__)
#define log_devlink_notice(cont, ...)  log_devlink_full(cont, LOG_NOTICE, __VA_ARGS__)
#define log_devlink_warning(cont, ...) log_devlink_full(cont, LOG_WARNING,  __VA_ARGS__)
#define log_devlink_error(cont, ...)   log_devlink_full(cont, LOG_ERR, __VA_ARGS__)

#define log_devlink_debug_errno(cont, error, ...)   log_devlink_full_errno(cont, LOG_DEBUG, error, __VA_ARGS__)
#define log_devlink_info_errno(cont, error, ...)    log_devlink_full_errno(cont, LOG_INFO, error, __VA_ARGS__)
#define log_devlink_notice_errno(cont, error, ...)  log_devlink_full_errno(cont, LOG_NOTICE, error, __VA_ARGS__)
#define log_devlink_warning_errno(cont, error, ...) log_devlink_full_errno(cont, LOG_WARNING, error, __VA_ARGS__)
#define log_devlink_error_errno(cont, error, ...)   log_devlink_full_errno(cont, LOG_ERR, error, __VA_ARGS__)
