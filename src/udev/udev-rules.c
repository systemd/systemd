/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <ctype.h>
#include <fnmatch.h>
#include <unistd.h>

#include "sd-json.h"
#include "sd-messages.h"

#include "alloc-util.h"
#include "architecture.h"
#include "chase.h"                      /* IWYU pragma: keep */
#include "conf-files.h"
#include "conf-parser.h"
#include "confidential-virt.h"
#include "constants.h"
#include "device-private.h"
#include "device-util.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "escape.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "glob-util.h"
#include "hashmap.h"
#include "list.h"
#include "memstream-util.h"
#include "netif-naming-scheme.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "strxcpyx.h"
#include "sysctl-util.h"
#include "syslog-util.h"
#include "udev-builtin.h"
#include "udev-dump.h"
#include "udev-event.h"
#include "udev-format.h"
#include "udev-node.h"
#include "udev-rules.h"
#include "udev-spawn.h"
#include "udev-trace.h"
#include "udev-util.h"
#include "udev-worker.h"
#include "uid-classification.h"
#include "user-record.h"
#include "user-util.h"
#include "userdb.h"
#include "virt.h"

#define RULES_DIRS ((const char* const*) CONF_PATHS_STRV("udev/rules.d"))

typedef enum {
        OP_MATCH,        /* == */
        OP_NOMATCH,      /* != */
        OP_ADD,          /* += */
        OP_REMOVE,       /* -= */
        OP_ASSIGN,       /* = */
        OP_ASSIGN_FINAL, /* := */
        _OP_TYPE_MAX,
        _OP_TYPE_INVALID = -EINVAL,
} UdevRuleOperatorType;

typedef enum {
        MATCH_TYPE_EMPTY,            /* empty string */
        MATCH_TYPE_PLAIN,            /* no special characters */
        MATCH_TYPE_PLAIN_WITH_EMPTY, /* no special characters with empty string, e.g., "|foo" */
        MATCH_TYPE_GLOB,             /* shell globs ?,*,[] */
        MATCH_TYPE_GLOB_WITH_EMPTY,  /* shell globs ?,*,[] with empty string, e.g., "|foo*" */
        MATCH_TYPE_SUBSYSTEM,        /* "subsystem", "bus", or "class" */
        _MATCH_TYPE_MAX,

        _MATCH_TYPE_MASK                 = (1 << 5) - 1,
        MATCH_REMOVE_TRAILING_WHITESPACE = 1 << 5,  /* Remove trailing whitespaces in attribute */
        MATCH_CASE_INSENSITIVE           = 1 << 6,  /* string or pattern is matched case-insensitively */
        _MATCH_TYPE_INVALID              = -EINVAL,
} UdevRuleMatchType;

assert_cc(_MATCH_TYPE_MAX <= _MATCH_TYPE_MASK);

typedef enum {
        SUBST_TYPE_PLAIN,  /* no substitution */
        SUBST_TYPE_FORMAT, /* % or $ */
        SUBST_TYPE_SUBSYS, /* "[<SUBSYSTEM>/<KERNEL>]<attribute>" format */
        _SUBST_TYPE_MAX,
        _SUBST_TYPE_INVALID = -EINVAL,
} UdevRuleSubstituteType;

typedef enum {
        /* lvalues which take match or nomatch operator */
        TK_M_ACTION,                        /* string, device_get_action() */
        TK_M_DEVPATH,                       /* path, sd_device_get_devpath() */
        TK_M_KERNEL,                        /* string, sd_device_get_sysname() */
        TK_M_DEVLINK,                       /* strv, sd_device_get_devlink_first(), sd_device_get_devlink_next() */
        TK_M_NAME,                          /* string, name of network interface */
        TK_M_ENV,                           /* string, device property, takes key through attribute */
        TK_M_CONST,                         /* string, system-specific hard-coded constant */
        TK_M_TAG,                           /* strv, sd_device_get_tag_first(), sd_device_get_tag_next() */
        TK_M_SUBSYSTEM,                     /* string, sd_device_get_subsystem() */
        TK_M_DRIVER,                        /* string, sd_device_get_driver() */
        TK_M_ATTR,                          /* string, takes filename through attribute, sd_device_get_sysattr_value(), udev_resolve_subsys_kernel(), etc. */
        TK_M_SYSCTL,                        /* string, takes kernel parameter through attribute */

        /* matches parent parameters */
        TK_M_PARENTS_KERNEL,                /* string */
        TK_M_PARENTS_SUBSYSTEM,             /* string */
        TK_M_PARENTS_DRIVER,                /* string */
        TK_M_PARENTS_ATTR,                  /* string */
        TK_M_PARENTS_TAG,                   /* strv */

        TK_M_TEST,                          /* path, optionally mode_t can be specified by attribute, test the existence of a file */
        TK_M_PROGRAM,                       /* string, execute a program */
        TK_M_IMPORT_FILE,                   /* path */
        TK_M_IMPORT_PROGRAM,                /* string, import properties from the result of program */
        TK_M_IMPORT_BUILTIN,                /* string, import properties from the result of built-in command */
        TK_M_IMPORT_DB,                     /* string, import properties from database */
        TK_M_IMPORT_CMDLINE,                /* string, kernel command line */
        TK_M_IMPORT_PARENT,                 /* string, parent property */
        TK_M_RESULT,                        /* string, result of TK_M_PROGRAM */

#define _TK_M_MAX (TK_M_RESULT + 1)
#define _TK_A_MIN _TK_M_MAX

        /* lvalues which take one of assign operators */
        TK_A_OPTIONS_DUMP,                  /* no argument */
        TK_A_OPTIONS_STRING_ESCAPE_NONE,    /* no argument */
        TK_A_OPTIONS_STRING_ESCAPE_REPLACE, /* no argument */
        TK_A_OPTIONS_DB_PERSIST,            /* no argument */
        TK_A_OPTIONS_INOTIFY_WATCH,         /* boolean */
        TK_A_OPTIONS_DEVLINK_PRIORITY,      /* int */
        TK_A_OPTIONS_LOG_LEVEL,             /* string of log level or "reset" */
        TK_A_OWNER,                         /* user name */
        TK_A_GROUP,                         /* group name */
        TK_A_MODE,                          /* mode string */
        TK_A_OWNER_ID,                      /* uid_t */
        TK_A_GROUP_ID,                      /* gid_t */
        TK_A_MODE_ID,                       /* mode_t */
        TK_A_TAG,                           /* string */
        TK_A_OPTIONS_STATIC_NODE,           /* device path, /dev/... */
        TK_A_SECLABEL,                      /* string with attribute */
        TK_A_ENV,                           /* string with attribute */
        TK_A_NAME,                          /* ifname */
        TK_A_DEVLINK,                       /* string */
        TK_A_ATTR,                          /* string with attribute */
        TK_A_SYSCTL,                        /* string with attribute */
        TK_A_RUN_BUILTIN,                   /* string */
        TK_A_RUN_PROGRAM,                   /* string */

        _TK_TYPE_MAX,
        _TK_TYPE_INVALID = -EINVAL,
} UdevRuleTokenType;

typedef enum {
        LINE_HAS_NAME         = 1 << 0, /* has NAME= */
        LINE_HAS_DEVLINK      = 1 << 1, /* has SYMLINK=, OWNER=, GROUP= or MODE= */
        LINE_HAS_STATIC_NODE  = 1 << 2, /* has OPTIONS=static_node */
        LINE_HAS_GOTO         = 1 << 3, /* has GOTO= */
        LINE_HAS_LABEL        = 1 << 4, /* has LABEL= */
        LINE_UPDATE_SOMETHING = 1 << 5, /* has other TK_A_* or TK_M_IMPORT tokens */
        LINE_IS_REFERENCED    = 1 << 6, /* is referenced by GOTO */
} UdevRuleLineType;

typedef struct UdevRuleFile UdevRuleFile;
typedef struct UdevRuleLine UdevRuleLine;
typedef struct UdevRuleToken UdevRuleToken;

struct UdevRuleToken {
        UdevRuleTokenType type:8;
        UdevRuleOperatorType op:8;
        UdevRuleMatchType match_type:8;
        UdevRuleSubstituteType attr_subst_type:8;
        const char *value;
        void *data;

        const char *token_str; /* original token string for logging */

        UdevRuleLine *rule_line;
        LIST_FIELDS(UdevRuleToken, tokens);
};

struct UdevRuleLine {
        char *line;
        char *line_for_logging;
        unsigned line_number;
        UdevRuleLineType type;

        const char *label;
        const char *goto_label;
        UdevRuleLine *goto_line;

        UdevRuleFile *rule_file;
        LIST_HEAD(UdevRuleToken, tokens);
        LIST_FIELDS(UdevRuleLine, rule_lines);
};

struct UdevRuleFile {
        char *filename;
        unsigned issues; /* used by "udevadm verify" */

        UdevRules *rules;
        LIST_HEAD(UdevRuleLine, rule_lines);
        LIST_FIELDS(UdevRuleFile, rule_files);
};

struct UdevRules {
        ResolveNameTiming resolve_name_timing;
        Hashmap *known_users;
        Hashmap *known_groups;
        Hashmap *stats_by_path;
        LIST_HEAD(UdevRuleFile, rule_files);
};

#define LINE_GET_RULES(line)                                            \
        ASSERT_PTR(ASSERT_PTR(ASSERT_PTR(line)->rule_file)->rules)

static bool token_is_for_parents(UdevRuleToken *token) {
        return token->type >= TK_M_PARENTS_KERNEL && token->type <= TK_M_PARENTS_TAG;
}

/*** Logging helpers ***/

#define log_udev_event_syntax(event, token, level, message_id, fmt, ...) \
        ({                                                              \
                UdevEvent *_event = (event);                            \
                UdevRuleToken *_token = ASSERT_PTR(token);              \
                int _level = (level);                                   \
                sd_device *_d = token_is_for_parents(_token) ? _event->dev_parent : _event->dev; \
                const char *_sysname = NULL;                            \
                                                                        \
                if (_d && log_get_max_level() >= LOG_PRI(_level))       \
                        (void) sd_device_get_sysname(_d, &_sysname);    \
                log_struct(_level,                                      \
                           LOG_MESSAGE("%s:%u %s:" fmt,                 \
                                       strna(_token->rule_line->rule_file ? _token->rule_line->rule_file->filename : NULL), \
                                       _token->rule_line->line_number,  \
                                       _token->token_str,               \
                                       __VA_ARGS__),                    \
                           LOG_MESSAGE_ID(message_id),                  \
                           LOG_ITEM("DEVICE=%s", strempty(_sysname)));  \
        })

#define _log_udev_rule_file_full(device, device_u, file, file_u, line_nr, level, level_u, error, fmt, ...) \
        ({                                                              \
                int level_u = (level);                                  \
                sd_device *device_u = (device);                         \
                UdevRuleFile *file_u = (file);                          \
                                                                        \
                if (!device_u && file_u)                                \
                        file_u->issues |= (1U << level_u);              \
                                                                        \
                log_device_full_errno_zerook(                           \
                                device_u, level_u, error, "%s:%u " fmt, \
                                strna(file_u ? file_u->filename : NULL), \
                                line_nr,  ##__VA_ARGS__);               \
        })

#define log_udev_rule_file_full(device, file, line_nr, level, error, fmt, ...) \
        _log_udev_rule_file_full(device, UNIQ_T(d, UNIQ), file, UNIQ_T(f, UNIQ), line_nr, level, UNIQ_T(l, UNIQ), error, fmt, ##__VA_ARGS__)

#define _log_udev_rule_line_full(device, line, line_u, ...)             \
        ({                                                              \
                UdevRuleLine *line_u = ASSERT_PTR(line);                \
                                                                        \
                log_udev_rule_file_full(                                \
                                device,                                 \
                                line_u->rule_file, line_u->line_number, \
                                __VA_ARGS__);                           \
        })

#define log_udev_rule_line_full(device, line, ...)     \
        _log_udev_rule_line_full(device, line, UNIQ_T(l, UNIQ), __VA_ARGS__)

/* Mainly used when applying tokens to the event device. */
#define _log_event_full_errno_zerook(event, event_u, token, token_u, level, error, fmt, ...) \
        ({                                                              \
                UdevEvent *event_u = ASSERT_PTR(event);                 \
                UdevRuleToken *token_u = ASSERT_PTR(token);             \
                                                                        \
                log_udev_rule_line_full(                                \
                                token_is_for_parents(token_u) ? event_u->dev_parent : event_u->dev, \
                                token_u->rule_line,                     \
                                level, error, "%s: " fmt,               \
                                token_u->token_str, ##__VA_ARGS__);     \
        })

#define log_event_full_errno_zerook(event, token, ...)  \
        _log_event_full_errno_zerook(event, UNIQ_T(e, UNIQ), token, UNIQ_T(t, UNIQ), __VA_ARGS__)

#define _log_event_full_errno(event, token, level, error, error_u, ...) \
        ({                                                              \
                int error_u = (error);                                  \
                ASSERT_NON_ZERO(error_u);                               \
                log_event_full_errno_zerook(                            \
                                event, token, level, error_u,           \
                                __VA_ARGS__);                           \
        })

#define log_event_full_errno(event, token, level, error, ...)   \
        _log_event_full_errno(event, token, level, error, UNIQ_T(e, UNIQ), __VA_ARGS__)

#define log_event_full(event, token, level, ...)   (void) log_event_full_errno_zerook(event, token, level, 0, __VA_ARGS__)

#define log_event_debug(event, token, ...)   log_event_full(event, token, LOG_DEBUG, __VA_ARGS__)
#define log_event_info(event, token, ...)    log_event_full(event, token, LOG_INFO, __VA_ARGS__)
#define log_event_notice(event, token, ...)  log_event_full(event, token, LOG_NOTICE, __VA_ARGS__)
#define log_event_warning(event, token, ...) log_event_full(event, token, LOG_WARNING, __VA_ARGS__)
#define log_event_error(event, token, ...)   log_event_full(event, token, LOG_ERR, __VA_ARGS__)

#define log_event_debug_errno(event, token, error, ...)   log_event_full_errno(event, token, LOG_DEBUG, error, __VA_ARGS__)
#define log_event_info_errno(event, token, error, ...)    log_event_full_errno(event, token, LOG_INFO, error, __VA_ARGS__)
#define log_event_notice_errno(event, token, error, ...)  log_event_full_errno(event, token, LOG_NOTICE, error, __VA_ARGS__)
#define log_event_warning_errno(event, token, error, ...) log_event_full_errno(event, token, LOG_WARNING, error, __VA_ARGS__)
#define log_event_error_errno(event, token, error, ...)   log_event_full_errno(event, token, LOG_ERR, error, __VA_ARGS__)

#define _log_event_trace_errno(event, event_u, ...)                     \
        ({                                                              \
                UdevEvent *event_u = ASSERT_PTR(event);                 \
                                                                        \
                event_u->trace ?                                        \
                        log_event_debug_errno(event_u, __VA_ARGS__) :   \
                        (void) 0;                                       \
        })

#define log_event_trace_errno(event, ...)                               \
        _log_event_trace_errno(event, UNIQ_T(e, UNIQ), __VA_ARGS__)

#define _log_event_trace(event, event_u, ...)                           \
        ({                                                              \
                UdevEvent *event_u = ASSERT_PTR(event);                 \
                                                                        \
                event_u->trace ?                                        \
                        log_event_debug(event_u, __VA_ARGS__) :         \
                        (void) 0;                                       \
        })

#define log_event_trace(event, ...)                                     \
        _log_event_trace(event, UNIQ_T(e, UNIQ), __VA_ARGS__)

#define _log_event_result(event, token, result, result_u)               \
        ({                                                              \
                bool result_u = (result);                               \
                                                                        \
                log_event_trace(event, token, "%s",                     \
                                result_u ? "PASS" : "FAIL");            \
                result_u;                                               \
        })

#define log_event_result(event, token, result)                          \
        _log_event_result(event, token, result, UNIQ_T(r, UNIQ))

#define log_event_done(event, token)                                    \
        ({                                                              \
                log_event_trace(event, token, "DONE");                  \
                true;                                                   \
        })

#define _log_event_final_set(event, token, token_u)                     \
        ({                                                              \
                UdevRuleToken *token_u = ASSERT_PTR(token);             \
                                                                        \
                log_event_trace(event, token_u,                         \
                                "Already assigned final value, ignoring further %s.", \
                                token_u->op == OP_REMOVE ? "modification" : "assignment"); \
                true;                                                   \
        })

#define log_event_final_set(event, token)                       \
        _log_event_final_set(event, token, UNIQ_T(t, UNIQ))

#define _log_event_truncated(event, token, token_u, what, format)       \
        ({                                                              \
                UdevRuleToken *token_u = ASSERT_PTR(token);             \
                                                                        \
                token_u->type < _TK_M_MAX ?                             \
                        log_event_debug(event, token_u,                 \
                                        "The %s is truncated while substituting into \"%s\", assuming the token fails.", \
                                        what, (const char*) format) :   \
                        log_event_warning(                              \
                                        event, token_u,                 \
                                        "The %s is truncated while substituting into \"%s\", refusing to apply the token.", \
                                        what, (const char*) format);    \
        })

#define log_event_truncated(event, token, what, format)                 \
        _log_event_truncated(event, token, UNIQ_T(t, UNIQ), what, format)

#define _log_event_line(event, event_u, line, ...)                      \
        ({                                                              \
                UdevEvent *event_u = ASSERT_PTR(event);                 \
                                                                        \
                event_u->trace ?                                        \
                        log_udev_rule_line_full(                        \
                                        event_u->dev, line,             \
                                        LOG_DEBUG, 0, __VA_ARGS__) :    \
                        0;                                              \
        })

#define log_event_line(event, line, ...)                                \
        _log_event_line(event, UNIQ_T(e, UNIQ), line, __VA_ARGS__)

/* Mainly used when parsing .rules files. */
#define log_file_full_errno_zerook(...)                                 \
        log_udev_rule_file_full(NULL, __VA_ARGS__)

#define log_file_error(file, line_nr, ...)                              \
        log_file_full_errno_zerook(file, line_nr, LOG_ERR, 0, __VA_ARGS__)

#define log_line_full_errno_zerook(...)                                 \
        log_udev_rule_line_full(NULL, __VA_ARGS__)

#define log_line_full_errno(line, level, error, ...)                    \
        log_udev_rule_line_full(NULL, line, level, error, __VA_ARGS__)

#define log_line_full(line, level, ...)  (void) log_line_full_errno_zerook(line, level, 0, __VA_ARGS__)

#define log_line_debug(line, ...)   log_line_full(line, LOG_DEBUG, __VA_ARGS__)
#define log_line_info(line, ...)    log_line_full(line, LOG_INFO, __VA_ARGS__)
#define log_line_notice(line, ...)  log_line_full(line, LOG_NOTICE, __VA_ARGS__)
#define log_line_warning(line, ...) log_line_full(line, LOG_WARNING, __VA_ARGS__)
#define log_line_error(line, ...)   log_line_full(line, LOG_ERR, __VA_ARGS__)

#define log_line_debug_errno(line, error, ...)   log_line_full_errno(line, LOG_DEBUG, error, __VA_ARGS__)
#define log_line_info_errno(line, error, ...)    log_line_full_errno(line, LOG_INFO, error, __VA_ARGS__)
#define log_line_notice_errno(line, error, ...)  log_line_full_errno(line, LOG_NOTICE, error, __VA_ARGS__)
#define log_line_warning_errno(line, error, ...) log_line_full_errno(line, LOG_WARNING, error, __VA_ARGS__)
#define log_line_error_errno(line, error, ...)   log_line_full_errno(line, LOG_ERR, error, __VA_ARGS__)

#define _log_line_invalid_token(line, key, type)                \
        log_line_error_errno(line, SYNTHETIC_ERRNO(EINVAL),     \
                             "Invalid %s for %s.", type, key)

#define log_line_invalid_op(line, key)   _log_line_invalid_token(line, key, "operator")
#define log_line_invalid_attr(line, key) _log_line_invalid_token(line, key, "attribute")
#define log_line_invalid_prefix(line, key) _log_line_invalid_token(line, key, "prefix 'i'")

#define log_line_invalid_attr_format(line, key, attr, offset, hint)   \
        log_line_error_errno(line, SYNTHETIC_ERRNO(EINVAL),           \
                             "Invalid attribute \"%s\" for %s (char %zu: %s), ignoring.", \
                             attr, key, offset, hint)
#define log_line_invalid_value(line, key, value, offset, hint)        \
        log_line_error_errno(line, SYNTHETIC_ERRNO(EINVAL),             \
                             "Invalid value \"%s\" for %s (char %zu: %s), ignoring.", \
                             value, key, offset, hint)

/*** Other functions ***/

static UdevRuleToken* udev_rule_token_free(UdevRuleToken *token) {
        if (!token)
                return NULL;

        if (token->rule_line)
                LIST_REMOVE(tokens, token->rule_line->tokens, token);

        return mfree(token);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(UdevRuleToken*, udev_rule_token_free);

static void udev_rule_line_clear_tokens(UdevRuleLine *rule_line) {
        assert(rule_line);

        LIST_FOREACH(tokens, i, rule_line->tokens)
                udev_rule_token_free(i);
}

static UdevRuleLine* udev_rule_line_free(UdevRuleLine *rule_line) {
        if (!rule_line)
                return NULL;

        udev_rule_line_clear_tokens(rule_line);

        if (rule_line->rule_file)
                LIST_REMOVE(rule_lines, rule_line->rule_file->rule_lines, rule_line);

        free(rule_line->line);
        free(rule_line->line_for_logging);
        return mfree(rule_line);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(UdevRuleLine*, udev_rule_line_free);

static UdevRuleFile* udev_rule_file_free(UdevRuleFile *rule_file) {
        if (!rule_file)
                return NULL;

        LIST_FOREACH(rule_lines, i, rule_file->rule_lines)
                udev_rule_line_free(i);

        if (rule_file->rules)
                LIST_REMOVE(rule_files, rule_file->rules->rule_files, rule_file);

        free(rule_file->filename);
        return mfree(rule_file);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(UdevRuleFile*, udev_rule_file_free);

UdevRules* udev_rules_free(UdevRules *rules) {
        if (!rules)
                return NULL;

        LIST_FOREACH(rule_files, i, rules->rule_files)
                udev_rule_file_free(i);

        hashmap_free(rules->known_users);
        hashmap_free(rules->known_groups);
        hashmap_free(rules->stats_by_path);
        return mfree(rules);
}

static int rule_resolve_user(UdevRuleLine *rule_line, const char *name, uid_t *ret) {
        Hashmap **known_users = &LINE_GET_RULES(rule_line)->known_users;
        int r;

        assert(name);
        assert(ret);

        void *val = hashmap_get(*known_users, name);
        if (val) {
                *ret = PTR_TO_UID(val);
                return 0;
        }

        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
        r = userdb_by_name(name, /* match= */ NULL,
                           USERDB_SUPPRESS_SHADOW | USERDB_PARSE_NUMERIC | USERDB_SYNTHESIZE_NUMERIC,
                           &ur);
        if (r < 0)
                return log_line_error_errno(rule_line, r,
                                            "Failed to resolve user '%s', ignoring: %s",
                                            name, STRERROR_USER(r));
        if (!uid_is_system(ur->uid))
                log_struct(LOG_WARNING,
                           LOG_MESSAGE("%s:%u User %s configured to own a device node is not a system user. "
                                       "Support for device node ownership by non-system accounts is deprecated and will be removed in the future.",
                                       rule_line->rule_file->filename, rule_line->line_number, name),
                           LOG_MESSAGE_ID(SD_MESSAGE_SYSTEM_ACCOUNT_REQUIRED_STR));

        _cleanup_free_ char *n = strdup(name);
        if (!n)
                return log_oom();

        r = hashmap_ensure_put(known_users, &string_hash_ops_free, n, UID_TO_PTR(ur->uid));
        if (r < 0)
                return log_oom();

        TAKE_PTR(n);
        *ret = ur->uid;
        return 0;
}

static int rule_resolve_group(UdevRuleLine *rule_line, const char *name, gid_t *ret) {
        Hashmap **known_groups = &LINE_GET_RULES(rule_line)->known_groups;
        int r;

        assert(name);
        assert(ret);

        void *val = hashmap_get(*known_groups, name);
        if (val) {
                *ret = PTR_TO_GID(val);
                return 0;
        }

        _cleanup_(group_record_unrefp) GroupRecord *gr = NULL;
        r = groupdb_by_name(name, /* match= */ NULL,
                            USERDB_SUPPRESS_SHADOW | USERDB_PARSE_NUMERIC | USERDB_SYNTHESIZE_NUMERIC,
                            &gr);
        if (r < 0)
                return log_line_error_errno(rule_line, r,
                                            "Failed to resolve group '%s', ignoring: %s",
                                            name, STRERROR_GROUP(r));
        if (!gid_is_system(gr->gid))
                log_struct(LOG_WARNING,
                           LOG_MESSAGE("%s:%u Group %s configured to own a device node is not a system group. "
                                       "Support for device node ownership by non-system accounts is deprecated and will be removed in the future.",
                                       rule_line->rule_file->filename, rule_line->line_number, name),
                           LOG_MESSAGE_ID(SD_MESSAGE_SYSTEM_ACCOUNT_REQUIRED_STR));

        _cleanup_free_ char *n = strdup(name);
        if (!n)
                return log_oom();

        r = hashmap_ensure_put(known_groups, &string_hash_ops_free, n, GID_TO_PTR(gr->gid));
        if (r < 0)
                return log_oom();

        TAKE_PTR(n);
        *ret = gr->gid;
        return 0;
}

static UdevRuleSubstituteType rule_get_substitution_type(const char *str) {
        assert(str);

        if (str[0] == '[')
                return SUBST_TYPE_SUBSYS;
        if (strchr(str, '%') || strchr(str, '$'))
                return SUBST_TYPE_FORMAT;
        return SUBST_TYPE_PLAIN;
}

static bool type_has_nulstr_value(UdevRuleTokenType type) {
        return type < TK_M_TEST || type == TK_M_RESULT;
}

static int rule_line_add_token(
                UdevRuleLine *rule_line,
                UdevRuleTokenType type,
                UdevRuleOperatorType op,
                char *value,
                void *data,
                bool is_case_insensitive,
                const char *token_str) {

        _cleanup_(udev_rule_token_freep) UdevRuleToken *token = NULL;
        UdevRuleMatchType match_type = _MATCH_TYPE_INVALID;
        UdevRuleSubstituteType subst_type = _SUBST_TYPE_INVALID;

        assert(rule_line);
        assert(type >= 0 && type < _TK_TYPE_MAX);
        assert(op >= 0 && op < _OP_TYPE_MAX);

        if (type < _TK_M_MAX) {
                assert(value);
                assert(IN_SET(op, OP_MATCH, OP_NOMATCH));

                if (type == TK_M_SUBSYSTEM && STR_IN_SET(value, "subsystem", "bus", "class"))
                        match_type = MATCH_TYPE_SUBSYSTEM;
                else if (isempty(value))
                        match_type = MATCH_TYPE_EMPTY;
                else if (streq(value, "?*")) {
                        /* Convert KEY=="?*" -> KEY!="" */
                        match_type = MATCH_TYPE_EMPTY;
                        op = op == OP_MATCH ? OP_NOMATCH : OP_MATCH;
                } else if (string_is_glob(value))
                        match_type = MATCH_TYPE_GLOB;
                else
                        match_type = MATCH_TYPE_PLAIN;

                if (type_has_nulstr_value(type)) {
                        /* Convert value string to nulstr. */
                        bool bar = true, empty = false;
                        char *a, *b;

                        for (a = b = value; *a != '\0'; a++) {
                                if (*a != '|') {
                                        *b++ = *a;
                                        bar = false;
                                } else {
                                        if (bar)
                                                empty = true;
                                        else
                                                *b++ = '\0';
                                        bar = true;
                                }
                        }
                        *b = '\0';

                        /* Make sure the value is end, so NULSTR_FOREACH can read correct match */
                        if (b < a)
                                b[1] = '\0';

                        if (bar)
                                empty = true;

                        if (empty) {
                                if (match_type == MATCH_TYPE_GLOB)
                                        match_type = MATCH_TYPE_GLOB_WITH_EMPTY;
                                if (match_type == MATCH_TYPE_PLAIN)
                                        match_type = MATCH_TYPE_PLAIN_WITH_EMPTY;
                        }
                }
        }

        if (IN_SET(type, TK_M_ATTR, TK_M_PARENTS_ATTR)) {
                size_t len;

                assert(value);
                assert(data);
                assert(match_type >= 0 && match_type < _MATCH_TYPE_MAX);

                len = strlen(value);
                if (len > 0 && !isspace(value[len - 1]))
                        match_type |= MATCH_REMOVE_TRAILING_WHITESPACE;

                subst_type = rule_get_substitution_type(data);
        }

        SET_FLAG(match_type, MATCH_CASE_INSENSITIVE, is_case_insensitive);

        token = new(UdevRuleToken, 1);
        if (!token)
                return -ENOMEM;

        *token = (UdevRuleToken) {
                .type = type,
                .op = op,
                .value = value,
                .data = data,
                .match_type = match_type,
                .attr_subst_type = subst_type,
                .token_str = token_str,
                .rule_line = rule_line,
        };

        LIST_APPEND(tokens, rule_line->tokens, token);

        if (token->type == TK_A_NAME)
                SET_FLAG(rule_line->type, LINE_HAS_NAME, true);

        else if (IN_SET(token->type, TK_A_DEVLINK,
                        TK_A_OWNER, TK_A_GROUP, TK_A_MODE,
                        TK_A_OWNER_ID, TK_A_GROUP_ID, TK_A_MODE_ID))
                SET_FLAG(rule_line->type, LINE_HAS_DEVLINK, true);

        else if (token->type == TK_A_OPTIONS_STATIC_NODE)
                SET_FLAG(rule_line->type, LINE_HAS_STATIC_NODE, true);

        else if (token->type >= _TK_A_MIN ||
                 IN_SET(token->type, TK_M_PROGRAM,
                        TK_M_IMPORT_FILE, TK_M_IMPORT_PROGRAM, TK_M_IMPORT_BUILTIN,
                        TK_M_IMPORT_DB, TK_M_IMPORT_CMDLINE, TK_M_IMPORT_PARENT))
                SET_FLAG(rule_line->type, LINE_UPDATE_SOMETHING, true);

        TAKE_PTR(token);
        return 0;
}

static void check_value_format_and_warn(UdevRuleLine *line, const char *key, const char *value, bool nonempty) {
        size_t offset;
        const char *hint;

        if (nonempty && isempty(value))
                log_line_invalid_value(line, key, value, (size_t) 0, "empty value");
        else if (udev_check_format(value, &offset, &hint) < 0)
                log_line_invalid_value(line, key, value, offset + 1, hint);
}

static int check_attr_format_and_warn(UdevRuleLine *line, const char *key, const char *value) {
        size_t offset;
        const char *hint;

        if (isempty(value))
                return log_line_invalid_attr(line, key);
        if (udev_check_format(value, &offset, &hint) < 0)
                log_line_invalid_attr_format(line, key, value, offset + 1, hint);
        return 0;
}

static int parse_token(
                UdevRuleLine *rule_line,
                const char *key,
                char *attr,
                UdevRuleOperatorType op,
                char *value,
                bool is_case_insensitive,
                const char *token_str) {

        ResolveNameTiming resolve_name_timing = LINE_GET_RULES(rule_line)->resolve_name_timing;
        bool is_match = IN_SET(op, OP_MATCH, OP_NOMATCH);
        int r;

        assert(key);
        assert(value);

        if (!is_match && is_case_insensitive)
                return log_line_error_errno(rule_line, SYNTHETIC_ERRNO(EINVAL),
                                            "Invalid prefix 'i' for '%s'. The 'i' prefix can be specified only for '==' or '!=' operator.", key);

        if (streq(key, "ACTION")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);

                r = rule_line_add_token(rule_line, TK_M_ACTION, op, value, NULL, is_case_insensitive, token_str);
        } else if (streq(key, "DEVPATH")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);

                r = rule_line_add_token(rule_line, TK_M_DEVPATH, op, value, NULL, is_case_insensitive, token_str);
        } else if (streq(key, "KERNEL")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);

                r = rule_line_add_token(rule_line, TK_M_KERNEL, op, value, NULL, is_case_insensitive, token_str);
        } else if (streq(key, "SYMLINK")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match) {
                        check_value_format_and_warn(rule_line, key, value, false);
                        r = rule_line_add_token(rule_line, TK_A_DEVLINK, op, value, NULL, /* is_case_insensitive= */ false, token_str);
                } else
                        r = rule_line_add_token(rule_line, TK_M_DEVLINK, op, value, NULL, is_case_insensitive, token_str);
        } else if (streq(key, "NAME")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (op == OP_REMOVE)
                        return log_line_invalid_op(rule_line, key);
                if (op == OP_ADD) {
                        log_line_warning(rule_line, "%s key takes '==', '!=', '=', or ':=' operator, assuming '='.", key);
                        op = OP_ASSIGN;
                }

                if (!is_match) {
                        if (streq(value, "%k"))
                                return log_line_error_errno(rule_line, SYNTHETIC_ERRNO(EINVAL),
                                                            "Ignoring NAME=\"%%k\", as it will take no effect.");
                        if (isempty(value))
                                return log_line_error_errno(rule_line, SYNTHETIC_ERRNO(EINVAL),
                                                            "Ignoring NAME=\"\", as udev will not delete any network interfaces.");
                        check_value_format_and_warn(rule_line, key, value, false);

                        r = rule_line_add_token(rule_line, TK_A_NAME, op, value, NULL, /* is_case_insensitive= */ false, token_str);
                } else
                        r = rule_line_add_token(rule_line, TK_M_NAME, op, value, NULL, is_case_insensitive, token_str);
        } else if (streq(key, "ENV")) {
                if (isempty(attr))
                        return log_line_invalid_attr(rule_line, key);
                if (op == OP_REMOVE)
                        return log_line_invalid_op(rule_line, key);
                if (op == OP_ASSIGN_FINAL) {
                        log_line_warning(rule_line, "%s key takes '==', '!=', '=', or '+=' operator, assuming '='.", key);
                        op = OP_ASSIGN;
                }

                if (!is_match) {
                        if (!device_property_can_set(attr))
                                return log_line_error_errno(rule_line, SYNTHETIC_ERRNO(EINVAL),
                                                            "Invalid ENV attribute. '%s' cannot be set.", attr);

                        check_value_format_and_warn(rule_line, key, value, false);

                        r = rule_line_add_token(rule_line, TK_A_ENV, op, value, attr, /* is_case_insensitive= */ false, token_str);
                } else
                        r = rule_line_add_token(rule_line, TK_M_ENV, op, value, attr, is_case_insensitive, token_str);
        } else if (streq(key, "CONST")) {
                if (isempty(attr) || !STR_IN_SET(attr, "arch", "virt"))
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);
                r = rule_line_add_token(rule_line, TK_M_CONST, op, value, attr, is_case_insensitive, token_str);
        } else if (streq(key, "TAG")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (op == OP_ASSIGN_FINAL) {
                        log_line_warning(rule_line, "%s key takes '==', '!=', '=', or '+=' operator, assuming '='.", key);
                        op = OP_ASSIGN;
                }

                if (!is_match) {
                        check_value_format_and_warn(rule_line, key, value, true);

                        r = rule_line_add_token(rule_line, TK_A_TAG, op, value, NULL, /* is_case_insensitive= */ false, token_str);
                } else
                        r = rule_line_add_token(rule_line, TK_M_TAG, op, value, NULL, is_case_insensitive, token_str);
        } else if (streq(key, "SUBSYSTEM")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);

                if (STR_IN_SET(value, "bus", "class"))
                        log_line_warning(rule_line, "\"%s\" must be specified as \"subsystem\".", value);

                r = rule_line_add_token(rule_line, TK_M_SUBSYSTEM, op, value, NULL, is_case_insensitive, token_str);
        } else if (streq(key, "DRIVER")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);

                r = rule_line_add_token(rule_line, TK_M_DRIVER, op, value, NULL, is_case_insensitive, token_str);
        } else if (streq(key, "ATTR")) {
                r = check_attr_format_and_warn(rule_line, key, attr);
                if (r < 0)
                        return r;
                if (op == OP_REMOVE)
                        return log_line_invalid_op(rule_line, key);
                if (IN_SET(op, OP_ADD, OP_ASSIGN_FINAL)) {
                        log_line_warning(rule_line, "%s key takes '==', '!=', or '=' operator, assuming '='.", key);
                        op = OP_ASSIGN;
                }

                if (!is_match) {
                        check_value_format_and_warn(rule_line, key, value, false);
                        r = rule_line_add_token(rule_line, TK_A_ATTR, op, value, attr, /* is_case_insensitive= */ false, token_str);
                } else
                        r = rule_line_add_token(rule_line, TK_M_ATTR, op, value, attr, is_case_insensitive, token_str);
        } else if (streq(key, "SYSCTL")) {
                r = check_attr_format_and_warn(rule_line, key, attr);
                if (r < 0)
                        return r;
                if (op == OP_REMOVE)
                        return log_line_invalid_op(rule_line, key);
                if (IN_SET(op, OP_ADD, OP_ASSIGN_FINAL)) {
                        log_line_warning(rule_line, "%s key takes '==', '!=', or '=' operator, assuming '='.", key);
                        op = OP_ASSIGN;
                }

                if (!is_match) {
                        check_value_format_and_warn(rule_line, key, value, false);
                        r = rule_line_add_token(rule_line, TK_A_SYSCTL, op, value, attr, /* is_case_insensitive= */ false, token_str);
                } else
                        r = rule_line_add_token(rule_line, TK_M_SYSCTL, op, value, attr, is_case_insensitive, token_str);
        } else if (streq(key, "KERNELS")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);

                r = rule_line_add_token(rule_line, TK_M_PARENTS_KERNEL, op, value, NULL, is_case_insensitive, token_str);
        } else if (streq(key, "SUBSYSTEMS")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);

                r = rule_line_add_token(rule_line, TK_M_PARENTS_SUBSYSTEM, op, value, NULL, is_case_insensitive, token_str);
        } else if (streq(key, "DRIVERS")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);

                r = rule_line_add_token(rule_line, TK_M_PARENTS_DRIVER, op, value, NULL, is_case_insensitive, token_str);
        } else if (streq(key, "ATTRS")) {
                r = check_attr_format_and_warn(rule_line, key, attr);
                if (r < 0)
                        return r;
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);

                if (startswith(attr, "device/"))
                        log_line_warning(rule_line, "'device' link may not be available in future kernels.");
                if (strstr(attr, "../"))
                        log_line_warning(rule_line, "Direct reference to parent sysfs directory, may break in future kernels.");

                r = rule_line_add_token(rule_line, TK_M_PARENTS_ATTR, op, value, attr, is_case_insensitive, token_str);
        } else if (streq(key, "TAGS")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);

                r = rule_line_add_token(rule_line, TK_M_PARENTS_TAG, op, value, NULL, is_case_insensitive, token_str);
        } else if (streq(key, "TEST")) {
                mode_t mode = MODE_INVALID;

                if (!isempty(attr)) {
                        r = parse_mode(attr, &mode);
                        if (r < 0)
                                return log_line_error_errno(rule_line, r, "Failed to parse mode '%s': %m", attr);
                }
                check_value_format_and_warn(rule_line, key, value, true);
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);
                if (is_case_insensitive)
                        return log_line_invalid_prefix(rule_line, key);

                r = rule_line_add_token(rule_line, TK_M_TEST, op, value, MODE_TO_PTR(mode), is_case_insensitive, token_str);
        } else if (streq(key, "PROGRAM")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                check_value_format_and_warn(rule_line, key, value, true);
                if (op == OP_REMOVE)
                        return log_line_invalid_op(rule_line, key);
                if (!is_match)
                        op = OP_MATCH;
                if (is_case_insensitive)
                        return log_line_invalid_prefix(rule_line, key);

                r = rule_line_add_token(rule_line, TK_M_PROGRAM, op, value, NULL, /* is_case_insensitive= */ false, token_str);
        } else if (streq(key, "IMPORT")) {
                if (isempty(attr))
                        return log_line_invalid_attr(rule_line, key);
                check_value_format_and_warn(rule_line, key, value, true);
                if (op == OP_REMOVE)
                        return log_line_invalid_op(rule_line, key);
                if (!is_match)
                        op = OP_MATCH;
                if (is_case_insensitive)
                        return log_line_invalid_prefix(rule_line, key);

                if (streq(attr, "file"))
                        r = rule_line_add_token(rule_line, TK_M_IMPORT_FILE, op, value, NULL, /* is_case_insensitive= */ false, token_str);
                else if (streq(attr, "program")) {
                        UdevBuiltinCommand cmd;

                        cmd = udev_builtin_lookup(value);
                        if (cmd >= 0) {
                                log_line_debug(rule_line, "Found builtin command '%s' for %s, replacing attribute.", value, key);
                                r = rule_line_add_token(rule_line, TK_M_IMPORT_BUILTIN, op, value, UDEV_BUILTIN_CMD_TO_PTR(cmd), /* is_case_insensitive= */ false, token_str);
                        } else
                                r = rule_line_add_token(rule_line, TK_M_IMPORT_PROGRAM, op, value, NULL, /* is_case_insensitive= */ false, token_str);
                } else if (streq(attr, "builtin")) {
                        UdevBuiltinCommand cmd;

                        cmd = udev_builtin_lookup(value);
                        if (cmd < 0)
                                return log_line_error_errno(rule_line, SYNTHETIC_ERRNO(EINVAL),
                                                            "Unknown builtin command: %s", value);
                        r = rule_line_add_token(rule_line, TK_M_IMPORT_BUILTIN, op, value, UDEV_BUILTIN_CMD_TO_PTR(cmd), /* is_case_insensitive= */ false, token_str);
                } else if (streq(attr, "db"))
                        r = rule_line_add_token(rule_line, TK_M_IMPORT_DB, op, value, NULL, /* is_case_insensitive= */ false, token_str);
                else if (streq(attr, "cmdline"))
                        r = rule_line_add_token(rule_line, TK_M_IMPORT_CMDLINE, op, value, NULL, /* is_case_insensitive= */ false, token_str);
                else if (streq(attr, "parent"))
                        r = rule_line_add_token(rule_line, TK_M_IMPORT_PARENT, op, value, NULL, /* is_case_insensitive= */ false, token_str);
                else
                        return log_line_invalid_attr(rule_line, key);
        } else if (streq(key, "RESULT")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);

                r = rule_line_add_token(rule_line, TK_M_RESULT, op, value, NULL, is_case_insensitive, token_str);
        } else if (streq(key, "OPTIONS")) {
                char *tmp;

                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (is_match || op == OP_REMOVE)
                        return log_line_invalid_op(rule_line, key);
                if (op == OP_ADD)
                        op = OP_ASSIGN;

                if (streq(value, "dump"))
                        r = rule_line_add_token(rule_line, TK_A_OPTIONS_DUMP, op, NULL, UINT_TO_PTR(SD_JSON_FORMAT_OFF), /* is_case_insensitive= */ false, token_str);
                else if (streq(value, "dump-json"))
                        r = rule_line_add_token(rule_line, TK_A_OPTIONS_DUMP, op, NULL, UINT_TO_PTR(SD_JSON_FORMAT_NEWLINE), /* is_case_insensitive= */ false, token_str);
                else if (streq(value, "string_escape=none"))
                        r = rule_line_add_token(rule_line, TK_A_OPTIONS_STRING_ESCAPE_NONE, op, NULL, NULL, /* is_case_insensitive= */ false, token_str);
                else if (streq(value, "string_escape=replace"))
                        r = rule_line_add_token(rule_line, TK_A_OPTIONS_STRING_ESCAPE_REPLACE, op, NULL, NULL, /* is_case_insensitive= */ false, token_str);
                else if (streq(value, "db_persist"))
                        r = rule_line_add_token(rule_line, TK_A_OPTIONS_DB_PERSIST, op, NULL, NULL, /* is_case_insensitive= */ false, token_str);
                else if (streq(value, "watch"))
                        r = rule_line_add_token(rule_line, TK_A_OPTIONS_INOTIFY_WATCH, op, NULL, INT_TO_PTR(1), /* is_case_insensitive= */ false, token_str);
                else if (streq(value, "nowatch"))
                        r = rule_line_add_token(rule_line, TK_A_OPTIONS_INOTIFY_WATCH, op, NULL, INT_TO_PTR(0), /* is_case_insensitive= */ false, token_str);
                else if ((tmp = startswith(value, "static_node=")))
                        r = rule_line_add_token(rule_line, TK_A_OPTIONS_STATIC_NODE, op, tmp, NULL, /* is_case_insensitive= */ false, token_str);
                else if ((tmp = startswith(value, "link_priority="))) {
                        int prio;

                        r = safe_atoi(tmp, &prio);
                        if (r < 0)
                                return log_line_error_errno(rule_line, r, "Failed to parse link priority '%s': %m", tmp);
                        r = rule_line_add_token(rule_line, TK_A_OPTIONS_DEVLINK_PRIORITY, op, NULL, INT_TO_PTR(prio), /* is_case_insensitive= */ false, token_str);
                } else if ((tmp = startswith(value, "log_level="))) {
                        int level;

                        if (streq(tmp, "reset"))
                                level = -1;
                        else {
                                level = log_level_from_string(tmp);
                                if (level < 0)
                                        return log_line_error_errno(rule_line, level, "Failed to parse log level '%s': %m", tmp);
                        }
                        r = rule_line_add_token(rule_line, TK_A_OPTIONS_LOG_LEVEL, op, NULL, INT_TO_PTR(level), /* is_case_insensitive= */ false, token_str);
                } else {
                        log_line_warning(rule_line, "Invalid value for OPTIONS key, ignoring: '%s'", value);
                        return 0;
                }
        } else if (streq(key, "OWNER")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (is_match || op == OP_REMOVE)
                        return log_line_invalid_op(rule_line, key);
                if (op == OP_ADD) {
                        log_line_warning(rule_line, "%s key takes '=' or ':=' operator, assuming '='.", key);
                        op = OP_ASSIGN;
                }

                if (in_charset(value, DIGITS) ||
                    (resolve_name_timing == RESOLVE_NAME_EARLY &&
                     rule_get_substitution_type(value) == SUBST_TYPE_PLAIN)) {
                        uid_t uid = UID_INVALID;  /* avoid false maybe-uninitialized warning */

                        r = rule_resolve_user(rule_line, value, &uid);
                        if (r < 0)
                                return r;
                        assert(uid_is_valid(uid));

                        r = rule_line_add_token(rule_line, TK_A_OWNER_ID, op, NULL, UID_TO_PTR(uid), /* is_case_insensitive= */ false, token_str);
                } else if (resolve_name_timing != RESOLVE_NAME_NEVER) {
                        check_value_format_and_warn(rule_line, key, value, true);
                        r = rule_line_add_token(rule_line, TK_A_OWNER, op, value, NULL, /* is_case_insensitive= */ false, token_str);
                } else {
                        log_line_debug(rule_line, "User name resolution is disabled, ignoring %s=\"%s\".", key, value);
                        return 0;
                }
        } else if (streq(key, "GROUP")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (is_match || op == OP_REMOVE)
                        return log_line_invalid_op(rule_line, key);
                if (op == OP_ADD) {
                        log_line_warning(rule_line, "%s key takes '=' or ':=' operator, assuming '='.", key);
                        op = OP_ASSIGN;
                }

                if (in_charset(value, DIGITS) ||
                    (resolve_name_timing == RESOLVE_NAME_EARLY &&
                     rule_get_substitution_type(value) == SUBST_TYPE_PLAIN)) {
                        gid_t gid = GID_INVALID;  /* avoid false maybe-uninitialized warning */

                        r = rule_resolve_group(rule_line, value, &gid);
                        if (r < 0)
                                return r;
                        assert(gid_is_valid(gid));

                        r = rule_line_add_token(rule_line, TK_A_GROUP_ID, op, NULL, GID_TO_PTR(gid), /* is_case_insensitive= */ false, token_str);
                } else if (resolve_name_timing != RESOLVE_NAME_NEVER) {
                        check_value_format_and_warn(rule_line, key, value, true);
                        r = rule_line_add_token(rule_line, TK_A_GROUP, op, value, NULL, /* is_case_insensitive= */ false, token_str);
                } else {
                        log_line_debug(rule_line, "Resolving group name is disabled, ignoring GROUP=\"%s\".", value);
                        return 0;
                }
        } else if (streq(key, "MODE")) {
                mode_t mode;

                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (is_match || op == OP_REMOVE)
                        return log_line_invalid_op(rule_line, key);
                if (op == OP_ADD) {
                        log_line_warning(rule_line, "%s key takes '=' or ':=' operator, assuming '='.", key);
                        op = OP_ASSIGN;
                }

                if (parse_mode(value, &mode) >= 0)
                        r = rule_line_add_token(rule_line, TK_A_MODE_ID, op, NULL, MODE_TO_PTR(mode), /* is_case_insensitive= */ false, token_str);
                else {
                        check_value_format_and_warn(rule_line, key, value, true);
                        r = rule_line_add_token(rule_line, TK_A_MODE, op, value, NULL, /* is_case_insensitive= */ false, token_str);
                }
        } else if (streq(key, "SECLABEL")) {
                if (isempty(attr))
                        return log_line_invalid_attr(rule_line, key);
                check_value_format_and_warn(rule_line, key, value, true);
                if (is_match || op == OP_REMOVE)
                        return log_line_invalid_op(rule_line, key);
                if (op == OP_ASSIGN_FINAL) {
                        log_line_warning(rule_line, "%s key takes '=' or '+=' operator, assuming '='.", key);
                        op = OP_ASSIGN;
                }

                r = rule_line_add_token(rule_line, TK_A_SECLABEL, op, value, attr, /* is_case_insensitive= */ false, token_str);
        } else if (streq(key, "RUN")) {
                if (is_match || op == OP_REMOVE)
                        return log_line_invalid_op(rule_line, key);
                check_value_format_and_warn(rule_line, key, value, true);
                if (!attr || streq(attr, "program"))
                        r = rule_line_add_token(rule_line, TK_A_RUN_PROGRAM, op, value, NULL, /* is_case_insensitive= */ false, token_str);
                else if (streq(attr, "builtin")) {
                        UdevBuiltinCommand cmd;

                        cmd = udev_builtin_lookup(value);
                        if (cmd < 0)
                                return log_line_error_errno(rule_line, SYNTHETIC_ERRNO(EINVAL),
                                                             "Unknown builtin command '%s', ignoring.", value);
                        r = rule_line_add_token(rule_line, TK_A_RUN_BUILTIN, op, value, UDEV_BUILTIN_CMD_TO_PTR(cmd), /* is_case_insensitive= */ false, token_str);
                } else
                        return log_line_invalid_attr(rule_line, key);
        } else if (streq(key, "GOTO")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (op != OP_ASSIGN)
                        return log_line_invalid_op(rule_line, key);
                if (FLAGS_SET(rule_line->type, LINE_HAS_GOTO)) {
                        log_line_warning(rule_line, "Contains multiple GOTO keys, ignoring GOTO=\"%s\".", value);
                        return 0;
                }

                rule_line->goto_label = value;
                SET_FLAG(rule_line->type, LINE_HAS_GOTO, true);
                return 1;
        } else if (streq(key, "LABEL")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (op != OP_ASSIGN)
                        return log_line_invalid_op(rule_line, key);
                if (FLAGS_SET(rule_line->type, LINE_HAS_LABEL))
                        log_line_warning(rule_line, "Contains multiple LABEL keys, ignoring LABEL=\"%s\".",
                                         rule_line->label);

                rule_line->label = value;
                SET_FLAG(rule_line->type, LINE_HAS_LABEL, true);
                return 1;
        } else
                return log_line_error_errno(rule_line, SYNTHETIC_ERRNO(EINVAL), "Invalid key '%s'.", key);
        if (r < 0)
                return log_oom();

        return 1;
}

static UdevRuleOperatorType parse_operator(const char *op) {
        assert(op);

        if (startswith(op, "=="))
                return OP_MATCH;
        if (startswith(op, "!="))
                return OP_NOMATCH;
        if (startswith(op, "+="))
                return OP_ADD;
        if (startswith(op, "-="))
                return OP_REMOVE;
        if (startswith(op, "="))
                return OP_ASSIGN;
        if (startswith(op, ":="))
                return OP_ASSIGN_FINAL;

        return _OP_TYPE_INVALID;
}

static void check_token_delimiters(UdevRuleLine *rule_line, const char *line) {
        assert(rule_line);

        size_t n_comma = 0;
        bool ws_before_comma = false, ws_after_comma = false;
        const char *p;

        for (p = line; !isempty(p); ++p) {
                if (*p == ',')
                        ++n_comma;
                else if (strchr(WHITESPACE, *p)) {
                        if (n_comma > 0)
                                ws_after_comma = true;
                        else
                                ws_before_comma = true;
                } else
                        break;
        }

        if (line == rule_line->line) {
                /* this is the first token of the rule */
                if (n_comma > 0)
                        log_line_notice(rule_line, "style: stray leading comma.");
        } else if (isempty(p)) {
                /* there are no more tokens in the rule */
                if (n_comma > 0)
                        log_line_notice(rule_line, "style: stray trailing comma.");
        } else {
                /* single comma is expected */
                if (n_comma == 0)
                        log_line_notice(rule_line, "style: a comma between tokens is expected.");
                else if (n_comma > 1)
                        log_line_notice(rule_line, "style: more than one comma between tokens.");

                /* whitespace after comma is expected */
                if (n_comma > 0) {
                        if (ws_before_comma)
                                log_line_notice(rule_line, "style: stray whitespace before comma.");
                        if (!ws_after_comma)
                                log_line_notice(rule_line, "style: whitespace after comma is expected.");
                } else if (!ws_before_comma && !ws_after_comma)
                        log_line_notice(rule_line, "style: whitespace between tokens is expected.");
        }
}

int udev_rule_parse_value(char *str, char **ret_value, char **ret_endpos, bool *ret_is_case_insensitive) {
        char *i, *j;
        bool is_escaped = false, is_case_insensitive = false;

        assert(str);
        assert(ret_value);
        assert(ret_endpos);
        assert(ret_is_case_insensitive);

        /* check if string is prefixed with:
         * - "e" for escaped
         * - "i" for case insensitive match
         *
         * Note both e and i can be set but do not allow duplicates ("eei", "eii"). */
        for (const char *k = str; *k != '"' && k < str + 2; k++)
                if (*k == 'e' && !is_escaped)
                        is_escaped = true;
                else if (*k == 'i' && !is_case_insensitive)
                        is_case_insensitive = true;
                else
                        return -EINVAL;

        /* value must be double quotated */
        str += is_escaped + is_case_insensitive;
        if (str[0] != '"')
                return -EINVAL;

        if (!is_escaped) {
                /* unescape double quotation '\"'->'"' */
                for (j = str, i = str + 1; *i != '"'; i++, j++) {
                        if (*i == '\0')
                                return -EINVAL;
                        if (i[0] == '\\' && i[1] == '"')
                                i++;
                        *j = *i;
                }
                j[0] = '\0';
                /*
                 * The return value must be terminated by two subsequent NULs
                 * so it could be safely interpreted as nulstr.
                 */
                j[1] = '\0';
        } else {
                _cleanup_free_ char *unescaped = NULL;
                ssize_t l;

                /* find the end position of value */
                for (i = str + 1; *i != '"'; i++) {
                        if (i[0] == '\\')
                                i++;
                        if (*i == '\0')
                                return -EINVAL;
                }
                i[0] = '\0';

                l = cunescape_length(str + 1, i - (str + 1), 0, &unescaped);
                if (l < 0)
                        return l;

                assert(l <= i - (str + 1));
                memcpy(str, unescaped, l + 1);
                /*
                 * The return value must be terminated by two subsequent NULs
                 * so it could be safely interpreted as nulstr.
                 */
                str[l + 1] = '\0';
        }

        *ret_value = str;
        *ret_endpos = i + 1;
        *ret_is_case_insensitive = is_case_insensitive;
        return 0;
}

static int parse_line(char **line, char **ret_key, char **ret_attr, UdevRuleOperatorType *ret_op, char **ret_value, bool *ret_is_case_insensitive) {
        char *key_begin, *key_end, *attr, *tmp;
        UdevRuleOperatorType op;
        int r;

        assert(line);
        assert(*line);
        assert(ret_key);
        assert(ret_op);
        assert(ret_value);
        assert(ret_is_case_insensitive);

        key_begin = skip_leading_chars(*line, WHITESPACE ",");

        if (isempty(key_begin))
                return 0;

        for (key_end = key_begin; ; key_end++) {
                if (key_end[0] == '\0')
                        return -EINVAL;
                if (strchr(WHITESPACE "={", key_end[0]))
                        break;
                if (strchr("+-!:", key_end[0]) && key_end[1] == '=')
                        break;
        }
        if (key_end[0] == '{') {
                attr = key_end + 1;
                tmp = strchr(attr, '}');
                if (!tmp)
                        return -EINVAL;
                *tmp++ = '\0';
        } else {
                attr = NULL;
                tmp = key_end;
        }

        tmp = skip_leading_chars(tmp, NULL);
        op = parse_operator(tmp);
        if (op < 0)
                return -EINVAL;

        key_end[0] = '\0';

        tmp += op == OP_ASSIGN ? 1 : 2;
        tmp = skip_leading_chars(tmp, NULL);
        r = udev_rule_parse_value(tmp, ret_value, line, ret_is_case_insensitive);
        if (r < 0)
                return r;

        *ret_key = key_begin;
        *ret_attr = attr;
        *ret_op = op;
        return 1;
}

static void check_tokens_order(UdevRuleLine *rule_line) {
        bool has_result = false;

        assert(rule_line);

        LIST_FOREACH(tokens, t, rule_line->tokens)
                if (t->type == TK_M_RESULT)
                        has_result = true;
                else if (has_result && t->type == TK_M_PROGRAM) {
                        log_line_warning(rule_line, "Reordering RESULT check after PROGRAM assignment.");
                        break;
                }
}

static void sort_tokens(UdevRuleLine *rule_line) {
        assert(rule_line);

        UdevRuleToken *old_tokens = TAKE_PTR(rule_line->tokens);

        while (old_tokens) {
                UdevRuleToken *min_token = NULL;

                LIST_FOREACH(tokens, t, old_tokens)
                        if (!min_token || min_token->type > t->type)
                                min_token = t;

                LIST_REMOVE(tokens, old_tokens, min_token);
                LIST_APPEND(tokens, rule_line->tokens, min_token);
        }
}

static int rule_add_line(UdevRuleFile *rule_file, const char *line, unsigned line_nr, bool extra_checks) {
        _cleanup_(udev_rule_line_freep) UdevRuleLine *rule_line = NULL;
        char *p;
        int r;

        assert(rule_file);
        assert(line);

        if (isempty(line))
                return 0;

        rule_line = new(UdevRuleLine, 1);
        if (!rule_line)
                return log_oom();

        *rule_line = (UdevRuleLine) {
                .line = strdup(line),
                .line_for_logging = strdup(line),
                .line_number = line_nr,
        };
        if (!rule_line->line || !rule_line->line_for_logging)
                return log_oom();

        rule_line->rule_file = rule_file;
        LIST_APPEND(rule_lines, rule_file->rule_lines, rule_line);

        for (p = rule_line->line; !isempty(p); ) {
                char *key, *attr, *value;
                UdevRuleOperatorType op;
                bool is_case_insensitive;

                if (extra_checks)
                        check_token_delimiters(rule_line, p);

                r = parse_line(&p, &key, &attr, &op, &value, &is_case_insensitive);
                if (r < 0)
                        return log_line_error_errno(rule_line, r, "Invalid key/value pair, ignoring.");
                if (r == 0)
                        break;

                char *token_str = rule_line->line_for_logging + (key - rule_line->line);
                token_str[p - key] = '\0';
                r = parse_token(rule_line, key, attr, op, value, is_case_insensitive, token_str);
                if (r < 0)
                        return r;
        }

        if (rule_line->type == 0) {
                log_line_warning(rule_line, "The line has no effect, ignoring.");
                return 0;
        }

        if (extra_checks)
                check_tokens_order(rule_line);

        sort_tokens(rule_line);
        TAKE_PTR(rule_line);
        return 0;
}

static void rule_resolve_goto(UdevRuleFile *rule_file) {
        assert(rule_file);

        /* link GOTOs to LABEL rules in this file to be able to fast-forward */
        LIST_FOREACH(rule_lines, line, rule_file->rule_lines) {
                if (!FLAGS_SET(line->type, LINE_HAS_GOTO))
                        continue;

                LIST_FOREACH(rule_lines, i, line->rule_lines_next)
                        if (streq_ptr(i->label, line->goto_label)) {
                                line->goto_line = i;
                                SET_FLAG(i->type, LINE_IS_REFERENCED, true);
                                break;
                        }

                if (!line->goto_line) {
                        log_line_error(line, "GOTO=\"%s\" has no matching label, ignoring.",
                                       line->goto_label);

                        SET_FLAG(line->type, LINE_HAS_GOTO, false);
                        line->goto_label = NULL;

                        if ((line->type & ~(LINE_HAS_LABEL|LINE_IS_REFERENCED)) == 0) {
                                log_line_warning(line, "The line has no effect any more, dropping.");
                                /* LINE_IS_REFERENCED implies LINE_HAS_LABEL */
                                if (line->type & LINE_HAS_LABEL)
                                        udev_rule_line_clear_tokens(line);
                                else
                                        udev_rule_line_free(line);
                        }
                }
        }
}

static bool token_data_is_string(UdevRuleTokenType type) {
        return IN_SET(type, TK_M_ENV,
                            TK_M_CONST,
                            TK_M_ATTR,
                            TK_M_SYSCTL,
                            TK_M_PARENTS_ATTR,
                            TK_A_SECLABEL,
                            TK_A_ENV,
                            TK_A_ATTR,
                            TK_A_SYSCTL);
}

static bool token_type_and_data_eq(const UdevRuleToken *a, const UdevRuleToken *b) {
        assert(a);
        assert(b);

        return a->type == b->type &&
               (token_data_is_string(a->type) ? streq_ptr(a->data, b->data) : (a->data == b->data));
}

static bool nulstr_eq(const char *a, const char *b) {
        NULSTR_FOREACH(i, a)
                if (!nulstr_contains(b, i))
                        return false;

        NULSTR_FOREACH(i, b)
                if (!nulstr_contains(a, i))
                        return false;

        return true;
}

static bool token_type_and_value_eq(const UdevRuleToken *a, const UdevRuleToken *b) {
        assert(a);
        assert(b);

        if (a->type != b->type ||
            a->match_type != b->match_type)
                return false;

        /* token value is ignored for certain match types */
        if (IN_SET(a->match_type, MATCH_TYPE_EMPTY, MATCH_TYPE_SUBSYSTEM))
                return true;

        return type_has_nulstr_value(a->type) ? nulstr_eq(a->value, b->value) :
                                                streq_ptr(a->value, b->value);
}

static bool conflicting_op(UdevRuleOperatorType a, UdevRuleOperatorType b) {
        return (a == OP_MATCH && b == OP_NOMATCH) ||
               (a == OP_NOMATCH && b == OP_MATCH);
}

/* test whether all fields besides UdevRuleOperatorType of two tokens match */
static bool tokens_eq(const UdevRuleToken *a, const UdevRuleToken *b) {
        assert(a);
        assert(b);

        return a->attr_subst_type == b->attr_subst_type &&
               token_type_and_value_eq(a, b) &&
               token_type_and_data_eq(a, b);
}

static bool nulstr_tokens_conflict(const UdevRuleToken *a, const UdevRuleToken *b) {
        assert(a);
        assert(b);

        if (!(a->type == b->type &&
              type_has_nulstr_value(a->type) &&
              a->op == b->op &&
              a->op == OP_MATCH &&
              a->match_type == b->match_type &&
              a->attr_subst_type == b->attr_subst_type &&
              token_type_and_data_eq(a, b)))
                return false;

        if (a->match_type == MATCH_TYPE_PLAIN) {
                NULSTR_FOREACH(i, a->value)
                        if (nulstr_contains(b->value, i))
                                return false;
                return true;
        }

        if (a->match_type == MATCH_TYPE_GLOB) {
                NULSTR_FOREACH(i, a->value) {
                        size_t i_n = strcspn(i, GLOB_CHARS);
                        if (i_n == 0)
                                return false;
                        NULSTR_FOREACH(j, b->value) {
                                size_t j_n = strcspn(j, GLOB_CHARS);
                                if (j_n == 0 || strneq(i, j, MIN(i_n, j_n)))
                                        return false;
                        }

                }
                return true;
        }

        return false;
}

static void udev_check_unused_labels(UdevRuleLine *line) {
        assert(line);

        if (FLAGS_SET(line->type, LINE_HAS_LABEL) &&
            !FLAGS_SET(line->type, LINE_IS_REFERENCED))
                log_line_notice(line, "style: LABEL=\"%s\" is unused.", line->label);
}

static void udev_check_conflicts_duplicates(UdevRuleLine *line) {
        assert(line);

        bool conflicts = false, duplicates = false;

        LIST_FOREACH(tokens, token, line->tokens)
                LIST_FOREACH(tokens, i, token->tokens_next) {
                        bool new_conflicts = false, new_duplicates = false;

                        if (tokens_eq(token, i)) {
                                if (!duplicates && token->op == i->op)
                                        new_duplicates = true;
                                if (!conflicts && conflicting_op(token->op, i->op))
                                        new_conflicts = true;
                        } else if (!conflicts && nulstr_tokens_conflict(token, i))
                                new_conflicts = true;
                        else
                                continue;

                        if (new_duplicates) {
                                duplicates = new_duplicates;
                                log_line_warning(line, "duplicate expressions.");
                        }
                        if (new_conflicts) {
                                conflicts = new_conflicts;
                                log_line_error(line, "conflicting match expressions, the line has no effect.");
                        }
                        if (conflicts && duplicates)
                                return;
                }
}

static void udev_check_rule_line(UdevRuleLine *line) {
        udev_check_unused_labels(line);
        udev_check_conflicts_duplicates(line);
}

int udev_rules_parse_file(UdevRules *rules, const ConfFile *c, bool extra_checks, UdevRuleFile **ret) {
        _cleanup_(udev_rule_file_freep) UdevRuleFile *rule_file = NULL;
        _cleanup_free_ char *name = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(rules);
        assert(c);
        assert(c->fd >= 0);
        assert(c->original_path);

        f = fopen(FORMAT_PROC_FD_PATH(c->fd), "re");
        if (!f) {
                if (extra_checks)
                        return -errno;

                return log_warning_errno(errno, "Failed to open %s, ignoring: %m", c->original_path);
        }

        r = hashmap_put_stats_by_path(&rules->stats_by_path, c->original_path, &c->st);
        if (r < 0)
                return log_warning_errno(r, "Failed to save stat for %s, ignoring: %m", c->original_path);

        (void) stat_warn_permissions(c->original_path, &c->st);

        log_debug("Reading rules file: %s", c->original_path);

        name = strdup(c->original_path);
        if (!name)
                return log_oom();

        rule_file = new(UdevRuleFile, 1);
        if (!rule_file)
                return log_oom();

        *rule_file = (UdevRuleFile) {
                .filename = TAKE_PTR(name),
                .rules = rules,
        };

        LIST_APPEND(rule_files, rules->rule_files, rule_file);

        _cleanup_free_ char *continuation = NULL;
        unsigned line_nr = 0, current_line_nr = 0;
        bool ignore_line = false;
        for (;;) {
                _cleanup_free_ char *buf = NULL;
                size_t len;
                char *line;

                r = read_line(f, UDEV_LINE_SIZE, &buf);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                current_line_nr++;
                if (!continuation)
                        line_nr = current_line_nr;

                line = skip_leading_chars(buf, NULL);

                /* Lines beginning with '#' are ignored regardless of line continuation. */
                if (line[0] == '#')
                        continue;

                len = strlen(line);

                if (continuation && !ignore_line) {
                        if (strlen(continuation) + len >= UDEV_LINE_SIZE)
                                ignore_line = true;

                        if (!strextend(&continuation, line))
                                return log_oom();

                        if (!ignore_line) {
                                line = continuation;
                                len = strlen(line);
                        }
                }

                if (len > 0 && line[len - 1] == '\\') {
                        if (ignore_line)
                                continue;

                        line[len - 1] = '\0';
                        if (!continuation) {
                                continuation = strdup(line);
                                if (!continuation)
                                        return log_oom();
                        }

                        continue;
                }

                if (ignore_line)
                        log_file_error(rule_file, line_nr, "Line is too long, ignored.");
                else if (len > 0)
                        (void) rule_add_line(rule_file, line, line_nr, extra_checks);

                continuation = mfree(continuation);
                ignore_line = false;
        }

        if (continuation)
                log_file_error(rule_file, line_nr,
                               "Unexpected EOF after line continuation, line ignored.");

        rule_resolve_goto(rule_file);

        if (extra_checks)
                LIST_FOREACH(rule_lines, line, rule_file->rule_lines)
                        udev_check_rule_line(line);

        if (ret)
                *ret = rule_file;

        TAKE_PTR(rule_file);
        return 0;
}

unsigned udev_rule_file_get_issues(UdevRuleFile *rule_file) {
        assert(rule_file);

        return rule_file->issues;
}

UdevRules* udev_rules_new(ResolveNameTiming resolve_name_timing) {
        assert(resolve_name_timing >= 0 && resolve_name_timing < _RESOLVE_NAME_TIMING_MAX);

        UdevRules *rules = new(UdevRules, 1);
        if (!rules)
                return NULL;

        *rules = (UdevRules) {
                .resolve_name_timing = resolve_name_timing,
        };

        return rules;
}

int udev_rules_load(UdevRules **ret_rules, ResolveNameTiming resolve_name_timing, char * const *extra) {
        _cleanup_(udev_rules_freep) UdevRules *rules = NULL;
        _cleanup_strv_free_ char **directories = NULL;
        int r;

        rules = udev_rules_new(resolve_name_timing);
        if (!rules)
                return -ENOMEM;

        if (!strv_isempty(extra)) {
                directories = strv_copy(extra);
                if (!directories)
                        return -ENOMEM;
        }

        r = strv_extend_strv(&directories, CONF_PATHS_STRV("udev/rules.d"), /* filter_duplicates= */ false);
        if (r < 0)
                return r;

        ConfFile **files = NULL;
        size_t n_files = 0;

        CLEANUP_ARRAY(files, n_files, conf_file_free_many);

        r = conf_files_list_strv_full(".rules", /* root= */ NULL, CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED,
                                      (const char* const*) directories, &files, &n_files);
        if (r < 0)
                return log_debug_errno(r, "Failed to enumerate rules files: %m");

        FOREACH_ARRAY(i, files, n_files) {
                ConfFile *c = *i;

                r = udev_rules_parse_file(rules, c, /* extra_checks= */ false, /* ret= */ NULL);
                if (r < 0)
                        log_debug_errno(r, "Failed to read rules file '%s', ignoring: %m", c->original_path);
        }

        *ret_rules = TAKE_PTR(rules);
        return 0;
}

bool udev_rules_should_reload(UdevRules *rules) {
        _cleanup_hashmap_free_ Hashmap *stats_by_path = NULL;
        int r;

        if (!rules)
                return true;

        r = config_get_stats_by_path(".rules", NULL, 0, RULES_DIRS, /* check_dropins= */ false, &stats_by_path);
        if (r < 0) {
                log_warning_errno(r, "Failed to get stats of udev rules, ignoring: %m");
                return true;
        }

        if (!stats_by_path_equal(rules->stats_by_path, stats_by_path)) {
                log_debug("Udev rules need reloading");
                return true;
        }

        return false;
}

static bool apply_format_full(
                UdevEvent *event,
                UdevRuleToken *token,
                const char *format,
                char *result,
                size_t result_size,
                bool replace_whitespace,
                const char *what) {

        assert(event);
        assert(token);
        assert(format);
        assert(result);
        assert(what);

        bool truncated = false;
        (void) udev_event_apply_format(event, format, result, result_size, replace_whitespace, &truncated);
        if (truncated) {
                log_event_truncated(event, token, what, format);
                return false;
        }

        if (event->trace && !streq(format, result))
                log_event_trace(event, token, "Format substitution: \"%s\" -> \"%s\"", format, result);

        return true;
}

static bool apply_format_value(
                UdevEvent *event,
                UdevRuleToken *token,
                char *result,
                size_t result_size,
                const char *what) {

        return apply_format_full(event, token, token->value, result, result_size, /* replace_whitespace= */ false, what);
}

static bool apply_format_attr(
                UdevEvent *event,
                UdevRuleToken *token,
                char *result,
                size_t result_size,
                const char *what) {

        return apply_format_full(event, token, token->data, result, result_size, /* replace_whitespace= */ false, what);
}

static bool token_match_string(UdevEvent *event, UdevRuleToken *token, const char *str, bool log_result) {
        const char *value;
        bool match = false, case_insensitive;

        assert(event);
        assert(token);
        assert(token->value);
        assert(token->type < _TK_M_MAX);

        str = strempty(str);
        value = token->value;
        case_insensitive = FLAGS_SET(token->match_type, MATCH_CASE_INSENSITIVE);

        switch (token->match_type & _MATCH_TYPE_MASK) {
        case MATCH_TYPE_EMPTY:
                match = isempty(str);
                break;
        case MATCH_TYPE_SUBSYSTEM:
                if (case_insensitive)
                        match = STRCASE_IN_SET(str, "subsystem", "class", "bus");
                else
                        match = STR_IN_SET(str, "subsystem", "class", "bus");
                break;
        case MATCH_TYPE_PLAIN_WITH_EMPTY:
                if (isempty(str)) {
                        match = true;
                        break;
                }
                _fallthrough_;
        case MATCH_TYPE_PLAIN:
                NULSTR_FOREACH(i, value)
                        if (case_insensitive ? strcaseeq(i, str) : streq(i, str)) {
                                match = true;
                                break;
                        }
                break;
        case MATCH_TYPE_GLOB_WITH_EMPTY:
                if (isempty(str)) {
                        match = true;
                        break;
                }
                _fallthrough_;
        case MATCH_TYPE_GLOB:
                NULSTR_FOREACH(i, value)
                        if ((fnmatch(i, str, case_insensitive ? FNM_CASEFOLD : 0) == 0)) {
                                match = true;
                                break;
                        }
                break;
        default:
                assert_not_reached();
        }

        bool result = token->op == (match ? OP_MATCH : OP_NOMATCH);

        if (event->trace)
                switch (token->match_type & _MATCH_TYPE_MASK) {
                case MATCH_TYPE_EMPTY:
                        log_event_trace(event, token, "String \"%s\" is%s empty%s",
                                        strempty(str), match ? "" : " not",
                                        log_result ? result ? ": PASS" : ": FAIL" : ".");
                        break;
                case MATCH_TYPE_SUBSYSTEM:
                        log_event_trace(event, token,
                                        "String \"%s\" matches %s of \"subsystem\", \"class\", or \"bus\"%s",
                                        strempty(str), match ? "one" : "neither",
                                        log_result ? result ? ": PASS" : ": FAIL" : ".");
                        break;
                case MATCH_TYPE_PLAIN_WITH_EMPTY:
                case MATCH_TYPE_PLAIN:
                case MATCH_TYPE_GLOB_WITH_EMPTY:
                case MATCH_TYPE_GLOB: {
                        _cleanup_free_ char *joined = NULL;
                        unsigned c = 0;

                        if (IN_SET(token->match_type & _MATCH_TYPE_MASK, MATCH_TYPE_PLAIN_WITH_EMPTY, MATCH_TYPE_GLOB_WITH_EMPTY)) {
                                (void) strextend_with_separator(&joined, ", ", "\"\"");
                                c++;
                        }

                        NULSTR_FOREACH(i, value) {
                                (void) strextendf_with_separator(&joined, ", ", "\"%s\"", i);
                                c++;
                        }

                        assert(c > 0);
                        log_event_trace(event, token, "String \"%s\" %s %s%s",
                                        strempty(str),
                                        match ? (c > 1 ? "matches one of" : "matches") : (c > 1 ? "matches neither of" : "does not match"),
                                        strempty(joined),
                                        log_result ? result ? ": PASS" : ": FAIL" : ".");
                        break;
                }
                default:
                        assert_not_reached();
                }

        return result;
}

static bool token_match_attr(UdevRuleToken *token, sd_device *dev, UdevEvent *event) {
        char nbuf[UDEV_NAME_SIZE], vbuf[UDEV_NAME_SIZE];
        const char *name, *value;
        int r;

        assert(token);
        assert(IN_SET(token->type, TK_M_ATTR, TK_M_PARENTS_ATTR));
        assert(dev);
        assert(event);

        name = token->data;

        switch (token->attr_subst_type) {
        case SUBST_TYPE_FORMAT:
                if (!apply_format_attr(event, token, nbuf, sizeof(nbuf), "sysfs attribute name"))
                        return false;

                name = nbuf;
                _fallthrough_;
        case SUBST_TYPE_PLAIN:
                r = sd_device_get_sysattr_value(dev, name, &value);
                if (r < 0) {
                        log_event_trace_errno(event, token, r, "Cannot read sysfs attribute%s%s%s: %m",
                                              name != token->data ? " \"" : "",
                                              name != token->data ? name : "",
                                              name != token->data ? "\"" : "");
                        return false;
                }

                /* remove trailing whitespace, if not asked to match for it */
                if (FLAGS_SET(token->match_type, MATCH_REMOVE_TRAILING_WHITESPACE)) {
                        strscpy(vbuf, sizeof(vbuf), value);
                        value = delete_trailing_chars(vbuf, NULL);
                }

                return token_match_string(event, token, value, /* log_result= */ true);

        case SUBST_TYPE_SUBSYS:
                r = udev_resolve_subsys_kernel(name, vbuf, sizeof(vbuf), true);
                if (r < 0) {
                        log_event_trace_errno(event, token, r, "Cannot read sysfs attribute: %m");
                        return false;
                }

                /* remove trailing whitespace, if not asked to match for it */
                if (FLAGS_SET(token->match_type, MATCH_REMOVE_TRAILING_WHITESPACE))
                        delete_trailing_chars(vbuf, NULL);

                return token_match_string(event, token, vbuf, /* log_result= */ true);

        default:
                assert_not_reached();
        }
}

static int get_property_from_string(char *line, char **ret_key, char **ret_value) {
        char *key, *val;
        size_t len;

        assert(line);
        assert(ret_key);
        assert(ret_value);

        /* find key */
        key = skip_leading_chars(line, NULL);

        /* comment or empty line */
        if (IN_SET(key[0], '#', '\0')) {
                *ret_key = *ret_value = NULL;
                return 0;
        }

        /* split key/value */
        val = strchr(key, '=');
        if (!val)
                return -EINVAL;
        *val++ = '\0';

        key = strstrip(key);
        if (isempty(key))
                return -EINVAL;

        val = strstrip(val);
        if (isempty(val))
                return -EINVAL;

        /* unquote */
        if (IN_SET(val[0], '"', '\'')) {
                len = strlen(val);
                if (len == 1 || val[len-1] != val[0])
                        return -EINVAL;
                val[len-1] = '\0';
                val++;
        }

        *ret_key = key;
        *ret_value = val;
        return 1;
}

static int attr_subst_subdir(char attr[static UDEV_PATH_SIZE]) {
        _cleanup_closedir_ DIR *dir = NULL;
        char buf[UDEV_PATH_SIZE], *p;
        const char *tail;
        size_t len, size;
        bool truncated;

        assert(attr);

        tail = strstr(attr, "/*/");
        if (!tail)
                return 0;

        len = tail - attr + 1; /* include slash at the end */
        tail += 2; /* include slash at the beginning */

        p = buf;
        size = sizeof(buf);
        size -= strnpcpy_full(&p, size, attr, len, &truncated);
        if (truncated)
                return -ENOENT;

        dir = opendir(buf);
        if (!dir)
                return -errno;

        FOREACH_DIRENT_ALL(de, dir, break) {
                if (de->d_name[0] == '.')
                        continue;

                strscpyl_full(p, size, &truncated, de->d_name, tail, NULL);
                if (truncated)
                        continue;

                if (faccessat(dirfd(dir), p, F_OK, 0) < 0)
                        continue;

                strcpy(attr, buf);
                return 0;
        }

        return -ENOENT;
}

static size_t udev_replace_ifname_strict(char *str) {
        size_t replaced = 0;

        assert(str);

        /* See ifname_valid_full(). */

        for (char *p = str; *p != '\0'; p++)
                if (!ifname_valid_char(*p)) {
                        *p = '_';
                        replaced++;
                }

        return replaced;
}

static void udev_replace_ifname(UdevEvent *event, UdevRuleToken *token, char *buf) {
        assert(event);
        assert(token);
        assert(buf);

        size_t count;
        if (naming_scheme_has(NAMING_REPLACE_STRICTLY))
                count = udev_replace_ifname_strict(buf);
        else
                count = udev_replace_chars(buf, "/");
        if (count > 0)
                log_event_trace(event, token,
                                "Replaced %zu character(s) from network interface name, results to \"%s\"",
                                count, buf);
}

static void udev_replace_chars_and_log(UdevEvent *event, UdevRuleToken *token, char *buf, const char *allow, const char *what) {
        assert(event);
        assert(token);
        assert(buf);
        assert(what);

        size_t count = udev_replace_chars(buf, allow);
        if (count > 0)
                log_event_trace(event, token,
                                "Replaced %zu character(s) from %s, results to \"%s\"",
                                count, what, buf);
}

static int udev_rule_apply_token_to_event(
                UdevRuleToken *token,
                sd_device *dev,
                UdevEvent *event) {

        int r;

        assert(token);
        assert(dev);
        assert(event);

        /* This returns the following values:
         * 0 on the current token does not match the event,
         * 1 on the current token matches the event, and
         * negative errno on some critical errors. */

        switch (token->type) {
        case TK_M_ACTION: {
                sd_device_action_t a;

                r = sd_device_get_action(dev, &a);
                if (r < 0)
                        return log_event_error_errno(event, token, r, "Failed to get uevent action type: %m");

                return token_match_string(event, token, device_action_to_string(a), /* log_result= */ true);
        }
        case TK_M_DEVPATH: {
                const char *val;

                r = sd_device_get_devpath(dev, &val);
                if (r < 0)
                        return log_event_error_errno(event, token, r, "Failed to get devpath: %m");

                return token_match_string(event, token, val, /* log_result= */ true);
        }
        case TK_M_KERNEL:
        case TK_M_PARENTS_KERNEL: {
                const char *val;

                r = sd_device_get_sysname(dev, &val);
                if (r < 0)
                        return log_event_error_errno(event, token, r, "Failed to get sysname: %m");

                return token_match_string(event, token, val, /* log_result= */ true);
        }
        case TK_M_DEVLINK:
                FOREACH_DEVICE_DEVLINK(dev, val)
                        if (token_match_string(event, token, strempty(startswith(val, "/dev/")), /* log_result= */ false) == (token->op == OP_MATCH))
                                return log_event_result(event, token, token->op == OP_MATCH);
                return log_event_result(event, token, token->op == OP_NOMATCH);

        case TK_M_NAME:
                return token_match_string(event, token, event->name, /* log_result= */ true);

        case TK_M_ENV: {
                const char *val = NULL;

                (void) device_get_property_value_with_fallback(dev, token->data, event->worker ? event->worker->properties : NULL, &val);

                return token_match_string(event, token, val, /* log_result= */ true);
        }
        case TK_M_CONST: {
                const char *val, *k = token->data;

                if (streq(k, "arch"))
                        val = architecture_to_string(uname_architecture());
                else if (streq(k, "virt"))
                        val = virtualization_to_string(detect_virtualization());
                else if (streq(k, "cvm"))
                        val = confidential_virtualization_to_string(detect_confidential_virtualization());
                else
                        assert_not_reached();
                return token_match_string(event, token, val, /* log_result= */ true);
        }
        case TK_M_TAG:
        case TK_M_PARENTS_TAG:
                FOREACH_DEVICE_CURRENT_TAG(dev, val)
                        if (token_match_string(event, token, val, /* log_result= */ false) == (token->op == OP_MATCH))
                                return log_event_result(event, token, token->op == OP_MATCH);
                return log_event_result(event, token, token->op == OP_NOMATCH);

        case TK_M_SUBSYSTEM:
        case TK_M_PARENTS_SUBSYSTEM: {
                const char *val;

                r = sd_device_get_subsystem(dev, &val);
                if (r == -ENOENT)
                        val = NULL;
                else if (r < 0)
                        return log_event_error_errno(event, token, r, "Failed to get subsystem: %m");

                return token_match_string(event, token, val, /* log_result= */ true);
        }
        case TK_M_DRIVER:
        case TK_M_PARENTS_DRIVER: {
                const char *val;

                r = sd_device_get_driver(dev, &val);
                if (r == -ENOENT)
                        val = NULL;
                else if (r < 0)
                        return log_event_error_errno(event, token, r, "Failed to get driver: %m");

                return token_match_string(event, token, val, /* log_result= */ true);
        }
        case TK_M_ATTR:
        case TK_M_PARENTS_ATTR:
                return token_match_attr(token, dev, event);

        case TK_M_SYSCTL: {
                _cleanup_free_ char *value = NULL;
                char buf[UDEV_PATH_SIZE];

                if (!apply_format_attr(event, token, buf, sizeof(buf), "sysctl entry name"))
                        return false;

                r = sysctl_read(sysctl_normalize(buf), &value);
                if (r < 0 && r != -ENOENT)
                        return log_event_error_errno(event, token, r, "Failed to read sysctl \"%s\": %m", buf);

                return token_match_string(event, token, strstrip(value), /* log_result= */ true);
        }
        case TK_M_TEST: {
                mode_t mode = PTR_TO_MODE(token->data);
                char buf[UDEV_PATH_SIZE];
                struct stat statbuf;
                bool match;

                if (!apply_format_value(event, token, buf, sizeof(buf), "file name"))
                        return false;

                if (!path_is_absolute(buf) &&
                    udev_resolve_subsys_kernel(buf, buf, sizeof(buf), false) < 0) {
                        char tmp[UDEV_PATH_SIZE];
                        const char *val;

                        r = sd_device_get_syspath(dev, &val);
                        if (r < 0)
                                return log_event_error_errno(event, token, r, "Failed to get syspath: %m");

                        bool truncated;
                        strscpy_full(tmp, sizeof(tmp), buf, &truncated);
                        assert(!truncated);
                        strscpyl_full(buf, sizeof(buf), &truncated, val, "/", tmp, NULL);
                        if (truncated)
                                return log_event_result(event, token, false);
                }

                r = attr_subst_subdir(buf);
                if (r == -ENOENT)
                        return log_event_result(event, token, token->op == OP_NOMATCH);
                if (r < 0)
                        return log_event_error_errno(event, token, r, "Failed to test for the existence of \"%s\": %m", buf);

                if (stat(buf, &statbuf) < 0) {
                        if (errno != ENOENT)
                                log_event_warning_errno(event, token, errno, "Failed to stat \"%s\", ignoring: %m", buf);
                        return log_event_result(event, token, token->op == OP_NOMATCH);
                }

                if (mode == MODE_INVALID)
                        return log_event_result(event, token, token->op == OP_MATCH);

                match = (statbuf.st_mode & mode) > 0;
                return log_event_result(event, token, token->op == (match ? OP_MATCH : OP_NOMATCH));
        }
        case TK_M_PROGRAM: {
                char buf[UDEV_LINE_SIZE], result[UDEV_LINE_SIZE];

                event->program_result = mfree(event->program_result);

                if (!apply_format_value(event, token, buf, sizeof(buf), "command"))
                        return false;

                log_event_debug(event, token, "Running command \"%s\"", buf);

                r = udev_event_spawn(event, /* accept_failure= */ true, buf, result, sizeof(result), NULL);
                if (r != 0) {
                        if (r < 0)
                                log_event_warning_errno(event, token, r, "Failed to execute \"%s\": %m", buf);
                        else /* returned value is positive when program fails */
                                log_event_debug(event, token, "Command \"%s\" returned %d (error)", buf, r);
                        return log_event_result(event, token, token->op == OP_NOMATCH);
                }

                delete_trailing_chars(result, "\n");
                udev_replace_chars_and_log(event, token, result, UDEV_ALLOWED_CHARS_INPUT, "command output");

                event->program_result = strdup(result);
                return log_event_result(event, token, token->op == OP_MATCH);
        }
        case TK_M_IMPORT_FILE: {
                _cleanup_fclose_ FILE *f = NULL;
                char buf[UDEV_PATH_SIZE];

                if (!apply_format_value(event, token, buf, sizeof(buf), "file name to be imported"))
                        return false;

                log_event_debug(event, token, "Importing properties from \"%s\"", buf);

                f = fopen(buf, "re");
                if (!f) {
                        if (errno != ENOENT)
                                return log_event_error_errno(event, token, errno, "Failed to open \"%s\": %m", buf);
                        return log_event_result(event, token, token->op == OP_NOMATCH);
                }

                for (;;) {
                        _cleanup_free_ char *line = NULL;
                        char *key, *value;

                        r = read_line(f, LONG_LINE_MAX, &line);
                        if (r < 0) {
                                log_event_debug_errno(event, token, r, "Failed to read \"%s\", ignoring: %m", buf);
                                return log_event_result(event, token, token->op == OP_NOMATCH);
                        }
                        if (r == 0)
                                return log_event_result(event, token, token->op == OP_MATCH);

                        r = get_property_from_string(line, &key, &value);
                        if (r < 0) {
                                log_event_debug_errno(event, token, r,
                                                      "Failed to parse key and value from \"%s\", ignoring: %m",
                                                      line);
                                continue;
                        }
                        if (r == 0)
                                continue;

                        r = device_add_property(dev, key, value);
                        if (r < 0)
                                return log_event_error_errno(event, token, r,
                                                             "Failed to add property %s=%s: %m",
                                                             key, value);
                        log_event_trace(event, token, "Imported property \"%s=%s\".", key, value);
                }

                assert_not_reached();
        }
        case TK_M_IMPORT_PROGRAM: {
                _cleanup_strv_free_ char **lines = NULL;
                char buf[UDEV_LINE_SIZE], result[UDEV_LINE_SIZE];
                bool truncated;

                if (!apply_format_value(event, token, buf, sizeof(buf), "command"))
                        return false;

                log_event_debug(event, token, "Importing properties from results of \"%s\"", buf);

                r = udev_event_spawn(event, /* accept_failure= */ true, buf, result, sizeof result, &truncated);
                if (r != 0) {
                        if (r < 0)
                                log_event_warning_errno(event, token, r, "Failed to execute \"%s\", ignoring: %m", buf);
                        else /* returned value is positive when program fails */
                                log_event_debug(event, token, "Command \"%s\" returned %d (error), ignoring", buf, r);
                        return log_event_result(event, token, token->op == OP_NOMATCH);
                }

                if (truncated) {
                        log_event_debug(event, token, "Result of \"%s\" is too long and truncated, ignoring the last line of the result.", buf);

                        /* Drop the last line. */
                        bool found = false;
                        for (char *p = PTR_SUB1(buf + strlen(buf), buf); p; p = PTR_SUB1(p, buf))
                                if (strchr(NEWLINE, *p)) {
                                        *p = '\0';
                                        found = true;
                                        break;
                                }
                        if (!found)
                                buf[0] = '\0';
                }

                r = strv_split_newlines_full(&lines, result, EXTRACT_RETAIN_ESCAPE);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_event_warning_errno(event, token, r,
                                                "Failed to extract lines from result of command \"%s\", ignoring: %m", buf);
                        return log_event_result(event, token, false);
                }

                STRV_FOREACH(line, lines) {
                        char *key, *value;

                        r = get_property_from_string(*line, &key, &value);
                        if (r < 0) {
                                log_event_debug_errno(event, token, r,
                                                      "Failed to parse key and value from \"%s\", ignoring: %m",
                                                      *line);
                                continue;
                        }
                        if (r == 0)
                                continue;

                        r = device_add_property(dev, key, value);
                        if (r < 0)
                                return log_event_error_errno(event, token, r,
                                                             "Failed to add property %s=%s: %m",
                                                             key, value);
                        log_event_trace(event, token, "Imported property \"%s=%s\".", key, value);
                }

                return log_event_result(event, token, token->op == OP_MATCH);
        }
        case TK_M_IMPORT_BUILTIN: {
                UdevBuiltinCommand cmd = PTR_TO_UDEV_BUILTIN_CMD(token->data);
                assert(cmd >= 0 && cmd < _UDEV_BUILTIN_MAX);
                unsigned mask = 1U << (int) cmd;
                char buf[UDEV_LINE_SIZE];

                if (udev_builtin_run_once(cmd)) {
                        /* check if we ran already */
                        if (event->builtin_run & mask) {
                                log_event_debug(event, token, "Builtin command \"%s\" has already run, skipping.",
                                                udev_builtin_name(cmd));
                                /* return the result from earlier run */
                                return log_event_result(event, token, token->op == (event->builtin_ret & mask ? OP_NOMATCH : OP_MATCH));
                        }
                        /* mark as ran */
                        event->builtin_run |= mask;
                }

                if (!apply_format_value(event, token, buf, sizeof(buf), "builtin command"))
                        return false;

                log_event_debug(event, token, "Importing properties from results of builtin command \"%s\".", buf);

                r = udev_builtin_run(event, cmd, buf);
                if (r < 0) {
                        /* remember failure */
                        log_event_debug_errno(event, token, r, "Failed to run builtin \"%s\": %m", buf);
                        event->builtin_ret |= mask;
                }
                return log_event_result(event, token, token->op == (r >= 0 ? OP_MATCH : OP_NOMATCH));
        }
        case TK_M_IMPORT_DB: {
                const char *val;

                if (!event->dev_db_clone)
                        return log_event_result(event, token, token->op == OP_NOMATCH);
                r = sd_device_get_property_value(event->dev_db_clone, token->value, &val);
                if (r == -ENOENT)
                        return log_event_result(event, token, token->op == OP_NOMATCH);
                if (r < 0)
                        return log_event_error_errno(event, token, r,
                                                     "Failed to get property \"%s\" from database: %m",
                                                     token->value);

                r = device_add_property(dev, token->value, val);
                if (r < 0)
                        return log_event_error_errno(event, token, r, "Failed to add property \"%s=%s\": %m",
                                                     token->value, val);
                log_event_trace(event, token, "Imported property \"%s=%s\".", token->value, val);

                return log_event_result(event, token, token->op == OP_MATCH);
        }
        case TK_M_IMPORT_CMDLINE: {
                _cleanup_free_ char *value = NULL;

                r = proc_cmdline_get_key(token->value, PROC_CMDLINE_VALUE_OPTIONAL, &value);
                if (r < 0)
                        return log_event_error_errno(event, token, r,
                                                     "Failed to read \"%s\" option from /proc/cmdline: %m",
                                                     token->value);
                if (r == 0)
                        return log_event_result(event, token, token->op == OP_NOMATCH);

                const char *val = value ?: "1";
                r = device_add_property(dev, token->value, val);
                if (r < 0)
                        return log_event_error_errno(event, token, r, "Failed to add property \"%s=%s\": %m",
                                                     token->value, val);
                log_event_trace(event, token, "Imported property \"%s=%s\".", token->value, val);

                return log_event_result(event, token, token->op == OP_MATCH);
        }
        case TK_M_IMPORT_PARENT: {
                char buf[UDEV_PATH_SIZE];

                if (!apply_format_value(event, token, buf, sizeof(buf), "property name"))
                        return false;

                sd_device *parent;
                r = sd_device_get_parent(dev, &parent);
                if (ERRNO_IS_NEG_DEVICE_ABSENT(r))
                        return log_event_result(event, token, token->op == OP_NOMATCH);
                if (r < 0)
                        return log_event_error_errno(event, token, r, "Failed to get parent device: %m");

                bool have = false;
                FOREACH_DEVICE_PROPERTY(parent, key, val) {
                        if (fnmatch(buf, key, 0) != 0)
                                continue;

                        r = device_add_property(dev, key, val);
                        if (r < 0)
                                return log_event_error_errno(event, token, r, "Failed to add property \"%s=%s\": %m", key, val);
                        log_event_trace(event, token, "Imported property \"%s=%s\".", key, val);
                        have = true;
                }

                return log_event_result(event, token, token->op == (have ? OP_MATCH : OP_NOMATCH));
        }
        case TK_M_RESULT:
                return token_match_string(event, token, event->program_result, /* log_result= */ true);

        case TK_A_OPTIONS_DUMP: {
                sd_json_format_flags_t flags = PTR_TO_UINT(token->data);

                log_event_info(event, token, "Dumping current state:");

                _cleanup_(memstream_done) MemStream m = {};
                FILE *f = memstream_init(&m);
                if (!f)
                        return log_oom();

                (void) dump_event(event, flags, f);

                _cleanup_free_ char *buf = NULL;
                r = memstream_finalize(&m, &buf, NULL);
                if (r < 0)
                        log_event_warning_errno(event, token, r, "Failed to finalize memory stream, ignoring: %m");
                else
                        log_device_info(dev, "%s", buf);

                log_event_info(event, token, "DONE");
                return true;
        }
        case TK_A_OPTIONS_STRING_ESCAPE_NONE:
                event->esc = ESCAPE_NONE;
                return log_event_done(event, token);

        case TK_A_OPTIONS_STRING_ESCAPE_REPLACE:
                event->esc = ESCAPE_REPLACE;
                return log_event_done(event, token);

        case TK_A_OPTIONS_DB_PERSIST:
                device_set_db_persist(dev);
                return log_event_done(event, token);

        case TK_A_OPTIONS_INOTIFY_WATCH:
                if (event->inotify_watch_final)
                        return log_event_final_set(event, token);

                if (token->op == OP_ASSIGN_FINAL)
                        event->inotify_watch_final = true;

                event->inotify_watch = token->data;
                return log_event_done(event, token);

        case TK_A_OPTIONS_DEVLINK_PRIORITY:
                device_set_devlink_priority(dev, PTR_TO_INT(token->data));
                return log_event_done(event, token);

        case TK_A_OPTIONS_LOG_LEVEL: {
                int level = PTR_TO_INT(token->data);

                if (level < 0)
                        level = event->default_log_level;

                if (event->event_mode == EVENT_UDEV_WORKER)
                        log_set_max_level(level);
                else {
                        _cleanup_free_ char *level_str = NULL;
                        (void) log_level_to_string_alloc(level, &level_str);
                        log_event_debug(event, token, "Running in test mode, skipping changing maximum log level to %s.", strna(level_str));
                }

                if (level == LOG_DEBUG && !event->log_level_was_debug) {
                        /* The log level becomes LOG_DEBUG at first time. Let's log basic information. */
                        if (event->event_mode == EVENT_UDEV_WORKER)
                                log_device_uevent(dev, "The log level is changed to 'debug' while processing device");
                        event->log_level_was_debug = true;
                }

                return log_event_done(event, token);
        }
        case TK_A_OWNER: {
                char owner[UDEV_NAME_SIZE];

                if (event->owner_final)
                        return log_event_final_set(event, token);

                if (token->op == OP_ASSIGN_FINAL)
                        event->owner_final = true;

                if (!apply_format_value(event, token, owner, sizeof(owner), "user name"))
                        return true;

                _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
                r = userdb_by_name(owner, /* match= */ NULL,
                                   USERDB_SUPPRESS_SHADOW | USERDB_PARSE_NUMERIC | USERDB_SYNTHESIZE_NUMERIC,
                                   &ur);
                if (r < 0)
                        log_event_error_errno(event, token, r,
                                              "Failed to resolve user \"%s\", ignoring: %s",
                                              owner, STRERROR_USER(r));
                else {
                        if (!uid_is_system(ur->uid))
                                log_udev_event_syntax(event, token, LOG_WARNING,
                                                      SD_MESSAGE_SYSTEM_ACCOUNT_REQUIRED_STR,
                                                      "User %s configured to own a device node is not a system user. "
                                                      "Support for device node ownership by non-system accounts is deprecated and will be removed in the future.",
                                                      owner);

                        event->uid = ur->uid;
                        log_event_debug(event, token, "Set owner: %s("UID_FMT")", owner, event->uid);
                }
                return true;
        }
        case TK_A_GROUP: {
                char group[UDEV_NAME_SIZE];

                if (event->group_final)
                        return log_event_final_set(event, token);

                if (token->op == OP_ASSIGN_FINAL)
                        event->group_final = true;

                if (!apply_format_value(event, token, group, sizeof(group), "group name"))
                        return true;

                _cleanup_(group_record_unrefp) GroupRecord *gr = NULL;
                r = groupdb_by_name(group, /* match= */ NULL,
                                    USERDB_SUPPRESS_SHADOW | USERDB_PARSE_NUMERIC | USERDB_SYNTHESIZE_NUMERIC,
                                    &gr);
                if (r < 0)
                        log_event_error_errno(event, token, r,
                                              "Failed to resolve group \"%s\", ignoring: %s",
                                              group, STRERROR_GROUP(r));
                else {
                        if (!gid_is_system(gr->gid))
                                log_udev_event_syntax(event, token, LOG_WARNING,
                                                      SD_MESSAGE_SYSTEM_ACCOUNT_REQUIRED_STR,
                                                      "Group %s configured to own a device node is not a system group. "
                                                      "Support for device node ownership by non-system accounts is deprecated and will be removed in the future.",
                                                      group);

                        event->gid = gr->gid;
                        log_event_debug(event, token, "Set group: %s("GID_FMT")", group, event->gid);
                }
                return true;
        }
        case TK_A_MODE: {
                char mode_str[UDEV_NAME_SIZE];

                if (event->mode_final)
                        return log_event_final_set(event, token);

                if (token->op == OP_ASSIGN_FINAL)
                        event->mode_final = true;

                if (!apply_format_value(event, token, mode_str, sizeof(mode_str), "mode"))
                        return true;

                r = parse_mode(mode_str, &event->mode);
                if (r < 0)
                        log_event_error_errno(event, token, r, "Failed to parse mode \"%s\", ignoring: %m", mode_str);
                else
                        log_event_debug(event, token, "Set mode: %#o", event->mode);
                return true;
        }
        case TK_A_OWNER_ID:
                if (event->owner_final)
                        return log_event_final_set(event, token);

                if (token->op == OP_ASSIGN_FINAL)
                        event->owner_final = true;

                event->uid = PTR_TO_UID(ASSERT_PTR(token->data));
                log_event_debug(event, token, "Set owner ID: %u", event->uid);
                return true;

        case TK_A_GROUP_ID:
                if (event->group_final)
                        return log_event_final_set(event, token);

                if (token->op == OP_ASSIGN_FINAL)
                        event->group_final = true;

                event->gid = PTR_TO_GID(ASSERT_PTR(token->data));
                log_event_debug(event, token, "Set group ID: %u", event->gid);
                return true;

        case TK_A_MODE_ID:
                if (event->mode_final)
                        return log_event_final_set(event, token);

                if (token->op == OP_ASSIGN_FINAL)
                        event->mode_final = true;

                event->mode = PTR_TO_MODE(ASSERT_PTR(token->data));
                log_event_debug(event, token, "Set mode: %#o", event->mode);
                return true;

        case TK_A_SECLABEL: {
                _cleanup_free_ char *name = NULL, *label = NULL;
                char label_str[UDEV_LINE_SIZE] = {};

                name = strdup(token->data);
                if (!name)
                        return log_oom();

                if (!apply_format_value(event, token, label_str, sizeof(label_str), "security label"))
                        return true;

                if (!isempty(label_str))
                        label = strdup(label_str);
                else
                        label = strdup(token->value);
                if (!label)
                        return log_oom();

                if (token->op == OP_ASSIGN)
                        ordered_hashmap_clear(event->seclabel_list);

                r = ordered_hashmap_ensure_put(&event->seclabel_list, &trivial_hash_ops_free_free, name, label);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        return log_event_error_errno(event, token, r, "Failed to store security label \"%s=%s\": %m", name, label);

                log_event_debug(event, token, "Set security label: %s=%s", name, label);

                TAKE_PTR(name);
                TAKE_PTR(label);
                return true;
        }
        case TK_A_ENV: {
                const char *val, *name = token->data;
                char value_new[UDEV_NAME_SIZE], *p = value_new;
                size_t l = sizeof(value_new);

                if (isempty(token->value)) {
                        if (token->op == OP_ADD)
                                return log_event_done(event, token);

                        r = device_add_property(dev, name, NULL);
                        if (r < 0)
                                return log_event_error_errno(event, token, r, "Failed to remove property \"%s\": %m", name);
                        log_event_trace(event, token, "Removed property \"%s\".", name);
                        return true;
                }

                if (token->op == OP_ADD &&
                    device_get_property_value_with_fallback(dev, name, event->worker ? event->worker->properties : NULL, &val) >= 0) {
                        bool truncated;
                        l = strpcpyl_full(&p, l, &truncated, val, " ", NULL);
                        if (truncated) {
                                log_event_warning(event, token,
                                                  "The buffer for the property is full, refusing to append new property \"%s=%s\".",
                                                  name, token->value);
                                return true;
                        }
                }

                if (!apply_format_value(event, token, p, l, "property value"))
                        return true;

                if (event->esc == ESCAPE_REPLACE)
                        udev_replace_chars_and_log(event, token, p, /* allow= */ NULL, "property value");

                r = device_add_property(dev, name, value_new);
                if (r < 0)
                        return log_event_error_errno(event, token, r, "Failed to set property \"%s=%s\": %m", name, value_new);
                log_event_trace(event, token, "Set property \"%s=%s\".", name, value_new);
                return true;
        }
        case TK_A_TAG: {
                char buf[UDEV_PATH_SIZE];

                if (!apply_format_value(event, token, buf, sizeof(buf), "tag name"))
                        return true;

                if (token->op == OP_REMOVE) {
                        device_remove_tag(dev, buf);
                        log_event_trace(event, token, "Removed tag \"%s\".", buf);
                        return true;
                }

                assert(IN_SET(token->op, OP_ASSIGN, OP_ADD));

                if (token->op == OP_ASSIGN)
                        device_cleanup_tags(dev);

                r = device_add_tag(dev, buf, /* both= */ true);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        log_event_warning_errno(event, token, r, "Failed to %s tag \"%s\", ignoring: %m",
                                                token->op == OP_ASSIGN ? "set" : "add", buf);
                else
                        log_event_trace(event, token, "%s tag \"%s\".", token->op == OP_ASSIGN ? "Set" : "Added", buf);
                return true;
        }
        case TK_A_NAME: {
                char buf[UDEV_PATH_SIZE];

                if (event->name_final)
                        return log_event_final_set(event, token);

                if (token->op == OP_ASSIGN_FINAL)
                        event->name_final = true;

                if (sd_device_get_ifindex(dev, NULL) < 0) {
                        log_event_warning(event, token, "Only network interfaces can be renamed, ignoring.");
                        return true;
                }

                if (!apply_format_value(event, token, buf, sizeof(buf), "network interface name"))
                        return true;

                if (IN_SET(event->esc, ESCAPE_UNSET, ESCAPE_REPLACE))
                        udev_replace_ifname(event, token, buf);

                r = free_and_strdup_warn(&event->name, buf);
                if (r < 0)
                        return r;

                log_event_debug(event, token, "Set network interface name: %s", event->name);
                return true;
        }
        case TK_A_DEVLINK: {
                char buf[UDEV_PATH_SIZE];

                if (event->devlink_final)
                        return log_event_final_set(event, token);

                if (sd_device_get_devnum(dev, NULL) < 0) {
                        log_event_debug(event, token, "Device does not have device node, ignoring to manage device node symlink.");
                        return true;
                }

                if (token->op == OP_ASSIGN_FINAL)
                        event->devlink_final = true;

                if (IN_SET(token->op, OP_ASSIGN, OP_ASSIGN_FINAL))
                        device_cleanup_devlinks(dev);

                if (!apply_format_full(event, token, token->value, buf, sizeof(buf),
                                       /* replace_whitespace= */ event->esc != ESCAPE_NONE,
                                       "symbolic link path"))
                        return true;

                /* By default or string_escape=none, allow multiple symlinks separated by spaces. */
                if (event->esc == ESCAPE_UNSET)
                        udev_replace_chars_and_log(event, token, buf, /* allow= */ "/ ", "device node symlink");
                else if (event->esc == ESCAPE_REPLACE)
                        udev_replace_chars_and_log(event, token, buf, /* allow= */ "/", "device node symlink");

                for (const char *p = buf;;) {
                        _cleanup_free_ char *path = NULL;

                        r = extract_first_word(&p, &path, NULL, EXTRACT_RETAIN_ESCAPE);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0) {
                                log_warning_errno(r, "Failed to extract first path in device node symlinks, ignoring: %m");
                                return true;
                        }
                        if (r == 0)
                                return true;

                        if (token->op == OP_REMOVE) {
                                r = device_remove_devlink(dev, path);
                                if (r == -ENOMEM)
                                        return log_oom();
                                if (r < 0)
                                        log_event_warning_errno(event, token, r, "Failed to remove device node symlink \"%s\", ignoring: %m", path);
                                else if (r > 0)
                                        log_event_debug(event, token, "Removed device node symlink \"%s\"", path);
                        } else {
                                r = device_add_devlink(dev, path);
                                if (r == -ENOMEM)
                                        return log_oom();
                                if (r < 0)
                                        log_event_warning_errno(event, token, r, "Failed to add device node symlink \"%s\", ignoring: %m", path);
                                else if (r > 0)
                                        log_event_debug(event, token, "Added device node symlink \"%s\".", path);
                        }
                }
                assert_not_reached();
        }
        case TK_A_ATTR: {
                char buf[UDEV_PATH_SIZE], value[UDEV_NAME_SIZE];
                const char *key = token->data;

                /* First, try to resolve "[<SUBSYSTEM>/<KERNEL>]<attribute>" format. */
                r = udev_resolve_subsys_kernel(key, buf, sizeof(buf), false);
                if (r == -ENOMEM)
                        return log_oom();
                if (ERRNO_IS_NEG_DEVICE_ABSENT(r)) {
                        log_event_warning_errno(event, token, r, "Failed to resolve sysfs attribute \"%s\", ignoring: %m", key);
                        return true;
                }
                if (r < 0) {
                        /* If not, make the path to sysfs attribute absolute, to make '*' resolvable by attr_subst_subdir(). */
                        const char *syspath;
                        r = sd_device_get_syspath(dev, &syspath);
                        if (r < 0)
                                return log_event_error_errno(event, token, r, "Failed to get syspath: %m");

                        bool truncated;
                        strscpyl_full(buf, sizeof(buf), &truncated, syspath, "/", key, NULL);
                        if (truncated) {
                                log_event_warning(event, token,
                                                  "The path to the attribute \"%s/%s\" is too long, refusing to set the attribute.",
                                                  syspath, key);
                                return true;
                        }

                        /* Resolve '*' in the path. */
                        r = attr_subst_subdir(buf);
                        if (r < 0) {
                                log_event_error_errno(event, token, r, "Could not find file matches \"%s\", ignoring: %m", buf);
                                return true;
                        }
                }

                /* Then, make the path relative again. This also checks if the path being inside of the sysfs. */
                _cleanup_free_ char *resolved = NULL;
                _cleanup_close_ int fd = -EBADF;
                r = device_chase(dev, buf, /* flags= */ 0, &resolved, &fd);
                if (r < 0) {
                        log_event_error_errno(event, token, r, "Could not chase sysfs attribute \"%s\", ignoring: %m", buf);
                        return true;
                }

                /* Apply formatting to the value. */
                if (!apply_format_value(event, token, value, sizeof(value), "attribute value"))
                        return true;

                if (EVENT_MODE_DESTRUCTIVE(event)) {
                        log_event_debug(event, token, "Writing \"%s\" to sysfs attribute \"%s\".", value, resolved);
                        r = sd_device_set_sysattr_value(dev, resolved, value);
                        if (r < 0)
                                log_event_error_errno(event, token, r, "Failed to write \"%s\" to sysfs attribute \"%s\", ignoring: %m", value, resolved);
                        else {
                                event_cache_written_sysattr(event, resolved, value);
                                log_event_done(event, token);
                        }
                } else {
                        log_event_debug(event, token, "Running in test mode, skipping writing \"%s\" to sysfs attribute \"%s\".", value, resolved);

                        /* We assume the attribute is writable if the path points to a regular file, and cache
                         * the value to make it shown by OPTIONS="dump" or obtained by later ATTR match token. */
                        r = fd_verify_regular(fd);
                        if (r < 0 && !ERRNO_IS_NEG_PRIVILEGE(r))
                                log_event_error_errno(event, token, r, "Failed to verify sysfs attribute \"%s\" is a regular file: %m", resolved);
                        else {
                                event_cache_written_sysattr(event, resolved, value);

                                _cleanup_free_ char *copied = strdup(value);
                                if (!copied)
                                        return log_oom();

                                r = device_cache_sysattr_value(dev, resolved, copied, /* error= */ 0);
                                if (r < 0)
                                        log_event_warning_errno(event, token, r, "Failed to cache sysfs attribute \"%s\", ignoring: %m", resolved);
                                else if (r > 0) {
                                        TAKE_PTR(resolved);
                                        TAKE_PTR(copied);
                                }
                        }
                }
                return true;
        }
        case TK_A_SYSCTL: {
                char buf[UDEV_PATH_SIZE], value[UDEV_NAME_SIZE];

                if (!apply_format_attr(event, token, buf, sizeof(buf), "sysctl entry name"))
                        return true;

                if (!apply_format_value(event, token, value, sizeof(value), "sysctl value"))
                        return true;

                sysctl_normalize(buf);

                if (EVENT_MODE_DESTRUCTIVE(event)) {
                        log_event_debug(event, token, "Writing \"%s\" to sysctl entry \"%s\".", value, buf);
                        r = sysctl_write(buf, value);
                        if (r < 0)
                                log_event_error_errno(event, token, r, "Failed to write \"%s\" to sysctl entry \"%s\", ignoring: %m", value, buf);
                        else {
                                event_cache_written_sysctl(event, buf, value);
                                log_event_done(event, token);
                        }
                } else {
                        log_event_debug(event, token, "Running in test mode, skipping writing \"%s\" to sysctl entry \"%s\".", value, buf);

                        _cleanup_free_ char *path = path_join("/proc/sys/", buf);
                        if (!path)
                                return log_oom();

                        r = verify_regular_at(AT_FDCWD, path, /* follow= */ true);
                        if (r < 0 && !ERRNO_IS_NEG_PRIVILEGE(r))
                                log_event_error_errno(event, token, r, "Failed to verify sysctl entry \"%s\" is a regular file: %m", buf);
                        else
                                event_cache_written_sysctl(event, buf, value);
                }
                return true;
        }
        case TK_A_RUN_BUILTIN:
        case TK_A_RUN_PROGRAM: {
                _cleanup_free_ char *cmd = NULL;
                char buf[UDEV_LINE_SIZE];

                if (event->run_final)
                        return log_event_final_set(event, token);

                if (token->op == OP_ASSIGN_FINAL)
                        event->run_final = true;

                if (IN_SET(token->op, OP_ASSIGN, OP_ASSIGN_FINAL))
                        ordered_hashmap_clear(event->run_list);

                if (!apply_format_value(event, token, buf, sizeof(buf), "command"))
                        return true;

                cmd = strdup(buf);
                if (!cmd)
                        return log_oom();

                r = ordered_hashmap_ensure_put(&event->run_list, &trivial_hash_ops_free, cmd, token->data);
                if (r < 0)
                        return log_event_error_errno(event, token, r, "Failed to store command \"%s\": %m", cmd);

                log_event_debug(event, token, "Set command: %s", cmd);
                TAKE_PTR(cmd);
                return true;
        }
        case TK_A_OPTIONS_STATIC_NODE:
                /* do nothing for events. */
                return true;

        default:
                assert_not_reached();
        }

        assert_not_reached();
}

static int udev_rule_apply_parent_token_to_event(UdevRuleToken *head_token, UdevEvent *event) {
        int r;

        assert(head_token);
        assert(token_is_for_parents(head_token));
        assert(event);

        UdevRuleLine *line = head_token->rule_line;
        if (event->trace) {
                _cleanup_free_ char *joined = NULL;

                LIST_FOREACH(tokens, token, head_token)
                        if (token_is_for_parents(token))
                                (void) strextend_with_separator(&joined, ", ", token->token_str);
                        else
                                break;

                log_event_line(event, line, "Checking conditions for parent devices (including self): %s", strna(joined));
        }

        event->dev_parent = ASSERT_PTR(event->dev);

        for (;;) {
                LIST_FOREACH(tokens, token, head_token) {
                        if (!token_is_for_parents(token)) {
                                r = 1; /* avoid false maybe-uninitialized warning */
                                break; /* All parent tokens match. */
                        }

                        r = udev_rule_apply_token_to_event(token, event->dev_parent, event);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;
                }
                if (r > 0) {
                        if (event->trace) {
                                const char *s = NULL;
                                (void) sd_device_get_syspath(event->dev_parent, &s);
                                log_event_line(event, line, "Parent device \"%s\" passed all parent conditions.", strna(s));
                        }
                        return true;
                }

                if (sd_device_get_parent(event->dev_parent, &event->dev_parent) < 0) {
                        event->dev_parent = NULL;
                        log_event_line(event, line, "No parent device passed parent conditions.");
                        return false;
                }
        }
}

static int udev_rule_apply_line_to_event(
                UdevRuleLine *line,
                UdevEvent *event,
                UdevRuleLine **next_line) {

        UdevRuleLineType mask = LINE_HAS_GOTO | LINE_UPDATE_SOMETHING;
        bool parents_done = false;
        sd_device_action_t action;
        int r;

        assert(line);
        assert(event);
        assert(next_line);

        r = sd_device_get_action(event->dev, &action);
        if (r < 0)
                return r;

        if (action != SD_DEVICE_REMOVE) {
                if (sd_device_get_devnum(event->dev, NULL) >= 0)
                        mask |= LINE_HAS_DEVLINK;

                if (sd_device_get_ifindex(event->dev, NULL) >= 0)
                        mask |= LINE_HAS_NAME;
        }

        if ((line->type & mask) == 0)
                return 0;

        event->esc = ESCAPE_UNSET;

        DEVICE_TRACE_POINT(rules_apply_line, event->dev, line->rule_file->filename, line->line_number);

        LIST_FOREACH(tokens, token, line->tokens) {
                if (token_is_for_parents(token)) {
                        if (parents_done)
                                continue;

                        r = udev_rule_apply_parent_token_to_event(token, event);
                        if (r <= 0)
                                return r;

                        parents_done = true;
                        continue;
                }

                r = udev_rule_apply_token_to_event(token, event->dev, event);
                if (r <= 0)
                        return r;
        }

        if (line->goto_line) {
                log_event_line(event, line, "GOTO=%s", strna(line->goto_label));
                *next_line = line->goto_line; /* update next_line only when the line has GOTO token. */
        }

        return 0;
}

int udev_rules_apply_to_event(UdevRules *rules, UdevEvent *event) {
        int r;

        assert(rules);
        assert(event);

        LIST_FOREACH(rule_files, file, rules->rule_files)
                LIST_FOREACH_WITH_NEXT(rule_lines, line, next_line, file->rule_lines) {
                        r = udev_rule_apply_line_to_event(line, event, &next_line);
                        if (r < 0)
                                return r;
                }

        return 0;
}

static int udev_rule_line_apply_static_dev_perms(UdevRuleLine *rule_line) {
        _cleanup_strv_free_ char **tags = NULL;
        uid_t uid = UID_INVALID;
        gid_t gid = GID_INVALID;
        mode_t mode = MODE_INVALID;
        int r;

        assert(rule_line);

        if (!FLAGS_SET(rule_line->type, LINE_HAS_STATIC_NODE))
                return 0;

        LIST_FOREACH(tokens, token, rule_line->tokens)
                if (token->type == TK_A_OWNER_ID)
                        uid = PTR_TO_UID(token->data);
                else if (token->type == TK_A_GROUP_ID)
                        gid = PTR_TO_GID(token->data);
                else if (token->type == TK_A_MODE_ID)
                        mode = PTR_TO_MODE(token->data);
                else if (token->type == TK_A_TAG) {
                        r = strv_extend(&tags, token->value);
                        if (r < 0)
                                return log_oom();
                } else if (token->type == TK_A_OPTIONS_STATIC_NODE) {
                        r = static_node_apply_permissions(token->value, mode, uid, gid, tags);
                        if (r < 0)
                                return r;
                }

        return 0;
}

int udev_rules_apply_static_dev_perms(UdevRules *rules) {
        int r;

        assert(rules);

        LIST_FOREACH(rule_files, file, rules->rule_files)
                LIST_FOREACH(rule_lines, line, file->rule_lines) {
                        r = udev_rule_line_apply_static_dev_perms(line);
                        if (r < 0)
                                return r;
                }

        return 0;
}

static const char* const resolve_name_timing_table[_RESOLVE_NAME_TIMING_MAX] = {
        [RESOLVE_NAME_NEVER] = "never",
        [RESOLVE_NAME_LATE]  = "late",
        [RESOLVE_NAME_EARLY] = "early",
};

DEFINE_STRING_TABLE_LOOKUP(resolve_name_timing, ResolveNameTiming);
