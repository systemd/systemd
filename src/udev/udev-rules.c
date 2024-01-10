/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <ctype.h>

#include "alloc-util.h"
#include "architecture.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "confidential-virt.h"
#include "constants.h"
#include "device-private.h"
#include "device-util.h"
#include "dirent-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "glob-util.h"
#include "list.h"
#include "mkdir.h"
#include "netif-naming-scheme.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "strv.h"
#include "strxcpyx.h"
#include "sysctl-util.h"
#include "syslog-util.h"
#include "udev-builtin.h"
#include "udev-event.h"
#include "udev-format.h"
#include "udev-node.h"
#include "udev-rules.h"
#include "udev-spawn.h"
#include "udev-trace.h"
#include "udev-util.h"
#include "user-util.h"
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
        _MATCH_TYPE_INVALID = -EINVAL,
} UdevRuleMatchType;

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
        UdevRuleSubstituteType attr_subst_type:7;
        bool attr_match_remove_trailing_whitespace:1;
        const char *value;
        void *data;

        UdevRuleLine *rule_line;
        LIST_FIELDS(UdevRuleToken, tokens);
};

struct UdevRuleLine {
        char *line;
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

/*** Logging helpers ***/

#define log_udev_rule_internal(device, file, line_nr, level, error, fmt, ...) \
        ({                                                              \
                int _lv = (level);                                      \
                sd_device *_dev = (device);                             \
                UdevRuleFile *_f = (file);                              \
                const char *_n = _f ? _f->filename : NULL;              \
                                                                        \
                if (!_dev && _f)                                        \
                        _f->issues |= (1U << _lv);                      \
                                                                        \
                log_device_full_errno_zerook(                           \
                                _dev, _lv, error, "%s:%u " fmt,         \
                                strna(_n), line_nr,                     \
                                ##__VA_ARGS__);                         \
        })

/* Mainly used when applying tokens to the event device. */
#define log_event_full_errno_zerook(device, token, ...)                 \
        ({                                                              \
                UdevRuleToken *_t = (token);                            \
                UdevRuleLine *_l = _t ? _t->rule_line : NULL;           \
                                                                        \
                log_udev_rule_internal(                                 \
                                device,                                 \
                                _l ? _l->rule_file : NULL,              \
                                _l ? _l->line_number : 0,               \
                                __VA_ARGS__);                           \
        })

#define log_event_full_errno(device, token, level, error, ...)          \
        ({                                                              \
                int _error = (error);                                   \
                ASSERT_NON_ZERO(_error);                                \
                log_event_full_errno_zerook(                            \
                        device, token, level, _error, ##__VA_ARGS__);   \
        })

#define log_event_full(device, token, level, ...)   (void) log_event_full_errno_zerook(device, token, level, 0, __VA_ARGS__)

#define log_event_debug(device, token, ...)   log_event_full(device, token, LOG_DEBUG, __VA_ARGS__)
#define log_event_info(device, token, ...)    log_event_full(device, token, LOG_INFO, __VA_ARGS__)
#define log_event_notice(device, token, ...)  log_event_full(device, token, LOG_NOTICE, __VA_ARGS__)
#define log_event_warning(device, token, ...) log_event_full(device, token, LOG_WARNING, __VA_ARGS__)
#define log_event_error(device, token, ...)   log_event_full(device, token, LOG_ERR, __VA_ARGS__)

#define log_event_debug_errno(device, token, error, ...)   log_event_full_errno(device, token, LOG_DEBUG, error, __VA_ARGS__)
#define log_event_info_errno(device, token, error, ...)    log_event_full_errno(device, token, LOG_INFO, error, __VA_ARGS__)
#define log_event_notice_errno(device, token, error, ...)  log_event_full_errno(device, token, LOG_NOTICE, error, __VA_ARGS__)
#define log_event_warning_errno(device, token, error, ...) log_event_full_errno(device, token, LOG_WARNING, error, __VA_ARGS__)
#define log_event_error_errno(device, token, error, ...)   log_event_full_errno(device, token, LOG_ERR, error, __VA_ARGS__)

/* Mainly used when parsing .rules files. */
#define log_file_full_errno_zerook(...) \
        log_udev_rule_internal(NULL, __VA_ARGS__)

#define log_file_error(file, line_nr, ...)                              \
        log_file_full_errno_zerook(file, line_nr, LOG_ERR, 0, __VA_ARGS__)

#define log_line_full_errno_zerook(line, ...)                           \
        ({                                                              \
                UdevRuleLine *_l = (line);                              \
                log_file_full_errno_zerook(                             \
                                _l ? _l->rule_file : NULL,              \
                                _l ? _l->line_number : 0,               \
                                __VA_ARGS__);                           \
        })

#define log_line_full_errno(line, level, error, ...)                    \
        ({                                                              \
                int _error = (error);                                   \
                ASSERT_NON_ZERO(_error);                                \
                log_line_full_errno_zerook(                             \
                        line, level, _error, ##__VA_ARGS__);            \
        })

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

#define log_line_invalid_attr_format(line, key, attr, offset, hint)   \
        log_line_error_errno(line, SYNTHETIC_ERRNO(EINVAL),           \
                             "Invalid attribute \"%s\" for %s (char %zu: %s), ignoring.", \
                             attr, key, offset, hint)
#define log_line_invalid_value(line, key, value, offset, hint)        \
        log_line_error_errno(line, SYNTHETIC_ERRNO(EINVAL),             \
                             "Invalid value \"%s\" for %s (char %zu: %s), ignoring.", \
                             value, key, offset, hint)

static void log_unknown_owner(sd_device *dev, UdevRuleLine *line, int error, const char *entity, const char *name) {
        assert(line);
        ASSERT_NON_ZERO(error);

        if (IN_SET(abs(error), ENOENT, ESRCH))
                log_udev_rule_internal(dev, line->rule_file, line->line_number, LOG_ERR, error,
                                       "Unknown %s '%s', ignoring.", entity, name);
        else
                log_udev_rule_internal(dev, line->rule_file, line->line_number, LOG_ERR, error,
                                       "Failed to resolve %s '%s', ignoring: %m", entity, name);
}

static void log_event_truncated(
                sd_device *dev,
                UdevRuleToken *token,
                const char *what,
                const char *format,
                const char *key,
                bool is_match) {

        if (is_match)
                log_event_debug(dev, token,
                                "The %s is truncated while substituting into '%s', "
                                "assuming the %s key does not match.",
                                what, format, key);
        else
                log_event_warning(dev, token,
                                  "The %s is truncated while substituting into '%s', "
                                  "refusing to apply the %s key.",
                                  what, format, key);
}

/*** Other functions ***/

static UdevRuleToken *udev_rule_token_free(UdevRuleToken *token) {
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

static UdevRuleLine *udev_rule_line_free(UdevRuleLine *rule_line) {
        if (!rule_line)
                return NULL;

        udev_rule_line_clear_tokens(rule_line);

        if (rule_line->rule_file)
                LIST_REMOVE(rule_lines, rule_line->rule_file->rule_lines, rule_line);

        free(rule_line->line);
        return mfree(rule_line);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(UdevRuleLine*, udev_rule_line_free);

static UdevRuleFile *udev_rule_file_free(UdevRuleFile *rule_file) {
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

UdevRules *udev_rules_free(UdevRules *rules) {
        if (!rules)
                return NULL;

        LIST_FOREACH(rule_files, i, rules->rule_files)
                udev_rule_file_free(i);

        hashmap_free_free_key(rules->known_users);
        hashmap_free_free_key(rules->known_groups);
        hashmap_free(rules->stats_by_path);
        return mfree(rules);
}

static int rule_resolve_user(UdevRuleLine *rule_line, const char *name, uid_t *ret) {
        Hashmap **known_users = &LINE_GET_RULES(rule_line)->known_users;
        _cleanup_free_ char *n = NULL;
        uid_t uid;
        void *val;
        int r;

        assert(name);
        assert(ret);

        val = hashmap_get(*known_users, name);
        if (val) {
                *ret = PTR_TO_UID(val);
                return 0;
        }

        r = get_user_creds(&name, &uid, NULL, NULL, NULL, USER_CREDS_ALLOW_MISSING);
        if (r < 0) {
                log_unknown_owner(NULL, rule_line, r, "user", name);
                *ret = UID_INVALID;
                return 0;
        }

        n = strdup(name);
        if (!n)
                return -ENOMEM;

        r = hashmap_ensure_put(known_users, &string_hash_ops, n, UID_TO_PTR(uid));
        if (r < 0)
                return r;

        TAKE_PTR(n);
        *ret = uid;
        return 0;
}

static int rule_resolve_group(UdevRuleLine *rule_line, const char *name, gid_t *ret) {
        Hashmap **known_groups = &LINE_GET_RULES(rule_line)->known_groups;
        _cleanup_free_ char *n = NULL;
        gid_t gid;
        void *val;
        int r;

        assert(name);
        assert(ret);

        val = hashmap_get(*known_groups, name);
        if (val) {
                *ret = PTR_TO_GID(val);
                return 0;
        }

        r = get_group_creds(&name, &gid, USER_CREDS_ALLOW_MISSING);
        if (r < 0) {
                log_unknown_owner(NULL, rule_line, r, "group", name);
                *ret = GID_INVALID;
                return 0;
        }

        n = strdup(name);
        if (!n)
                return -ENOMEM;

        r = hashmap_ensure_put(known_groups, &string_hash_ops, n, GID_TO_PTR(gid));
        if (r < 0)
                return r;

        TAKE_PTR(n);
        *ret = gid;
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

static int rule_line_add_token(UdevRuleLine *rule_line, UdevRuleTokenType type, UdevRuleOperatorType op, char *value, void *data) {
        _cleanup_(udev_rule_token_freep) UdevRuleToken *token = NULL;
        UdevRuleMatchType match_type = _MATCH_TYPE_INVALID;
        UdevRuleSubstituteType subst_type = _SUBST_TYPE_INVALID;
        bool remove_trailing_whitespace = false;
        size_t len;

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
                assert(value);
                assert(data);

                len = strlen(value);
                if (len > 0 && !isspace(value[len - 1]))
                        remove_trailing_whitespace = true;

                subst_type = rule_get_substitution_type(data);
        }

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
                .attr_match_remove_trailing_whitespace = remove_trailing_whitespace,
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

static int parse_token(UdevRuleLine *rule_line, const char *key, char *attr, UdevRuleOperatorType op, char *value) {
        ResolveNameTiming resolve_name_timing = LINE_GET_RULES(rule_line)->resolve_name_timing;
        bool is_match = IN_SET(op, OP_MATCH, OP_NOMATCH);
        int r;

        assert(key);
        assert(value);

        if (streq(key, "ACTION")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);

                r = rule_line_add_token(rule_line, TK_M_ACTION, op, value, NULL);
        } else if (streq(key, "DEVPATH")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);

                r = rule_line_add_token(rule_line, TK_M_DEVPATH, op, value, NULL);
        } else if (streq(key, "KERNEL")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);

                r = rule_line_add_token(rule_line, TK_M_KERNEL, op, value, NULL);
        } else if (streq(key, "SYMLINK")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match) {
                        check_value_format_and_warn(rule_line, key, value, false);
                        r = rule_line_add_token(rule_line, TK_A_DEVLINK, op, value, NULL);
                } else
                        r = rule_line_add_token(rule_line, TK_M_DEVLINK, op, value, NULL);
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

                        r = rule_line_add_token(rule_line, TK_A_NAME, op, value, NULL);
                } else
                        r = rule_line_add_token(rule_line, TK_M_NAME, op, value, NULL);
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
                        if (STR_IN_SET(attr,
                                       "ACTION", "DEVLINKS", "DEVNAME", "DEVPATH", "DEVTYPE", "DRIVER",
                                       "IFINDEX", "MAJOR", "MINOR", "SEQNUM", "SUBSYSTEM", "TAGS"))
                                return log_line_error_errno(rule_line, SYNTHETIC_ERRNO(EINVAL),
                                                            "Invalid ENV attribute. '%s' cannot be set.", attr);

                        check_value_format_and_warn(rule_line, key, value, false);

                        r = rule_line_add_token(rule_line, TK_A_ENV, op, value, attr);
                } else
                        r = rule_line_add_token(rule_line, TK_M_ENV, op, value, attr);
        } else if (streq(key, "CONST")) {
                if (isempty(attr) || !STR_IN_SET(attr, "arch", "virt"))
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);
                r = rule_line_add_token(rule_line, TK_M_CONST, op, value, attr);
        } else if (streq(key, "TAG")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (op == OP_ASSIGN_FINAL) {
                        log_line_warning(rule_line, "%s key takes '==', '!=', '=', or '+=' operator, assuming '='.", key);
                        op = OP_ASSIGN;
                }

                if (!is_match) {
                        check_value_format_and_warn(rule_line, key, value, true);

                        r = rule_line_add_token(rule_line, TK_A_TAG, op, value, NULL);
                } else
                        r = rule_line_add_token(rule_line, TK_M_TAG, op, value, NULL);
        } else if (streq(key, "SUBSYSTEM")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);

                if (STR_IN_SET(value, "bus", "class"))
                        log_line_warning(rule_line, "\"%s\" must be specified as \"subsystem\".", value);

                r = rule_line_add_token(rule_line, TK_M_SUBSYSTEM, op, value, NULL);
        } else if (streq(key, "DRIVER")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);

                r = rule_line_add_token(rule_line, TK_M_DRIVER, op, value, NULL);
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
                        r = rule_line_add_token(rule_line, TK_A_ATTR, op, value, attr);
                } else
                        r = rule_line_add_token(rule_line, TK_M_ATTR, op, value, attr);
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
                        r = rule_line_add_token(rule_line, TK_A_SYSCTL, op, value, attr);
                } else
                        r = rule_line_add_token(rule_line, TK_M_SYSCTL, op, value, attr);
        } else if (streq(key, "KERNELS")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);

                r = rule_line_add_token(rule_line, TK_M_PARENTS_KERNEL, op, value, NULL);
        } else if (streq(key, "SUBSYSTEMS")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);

                r = rule_line_add_token(rule_line, TK_M_PARENTS_SUBSYSTEM, op, value, NULL);
        } else if (streq(key, "DRIVERS")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);

                r = rule_line_add_token(rule_line, TK_M_PARENTS_DRIVER, op, value, NULL);
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

                r = rule_line_add_token(rule_line, TK_M_PARENTS_ATTR, op, value, attr);
        } else if (streq(key, "TAGS")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);

                r = rule_line_add_token(rule_line, TK_M_PARENTS_TAG, op, value, NULL);
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

                r = rule_line_add_token(rule_line, TK_M_TEST, op, value, MODE_TO_PTR(mode));
        } else if (streq(key, "PROGRAM")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                check_value_format_and_warn(rule_line, key, value, true);
                if (op == OP_REMOVE)
                        return log_line_invalid_op(rule_line, key);
                if (!is_match)
                        op = OP_MATCH;

                r = rule_line_add_token(rule_line, TK_M_PROGRAM, op, value, NULL);
        } else if (streq(key, "IMPORT")) {
                if (isempty(attr))
                        return log_line_invalid_attr(rule_line, key);
                check_value_format_and_warn(rule_line, key, value, true);
                if (op == OP_REMOVE)
                        return log_line_invalid_op(rule_line, key);
                if (!is_match)
                        op = OP_MATCH;

                if (streq(attr, "file"))
                        r = rule_line_add_token(rule_line, TK_M_IMPORT_FILE, op, value, NULL);
                else if (streq(attr, "program")) {
                        UdevBuiltinCommand cmd;

                        cmd = udev_builtin_lookup(value);
                        if (cmd >= 0) {
                                log_line_debug(rule_line, "Found builtin command '%s' for %s, replacing attribute.", value, key);
                                r = rule_line_add_token(rule_line, TK_M_IMPORT_BUILTIN, op, value, UDEV_BUILTIN_CMD_TO_PTR(cmd));
                        } else
                                r = rule_line_add_token(rule_line, TK_M_IMPORT_PROGRAM, op, value, NULL);
                } else if (streq(attr, "builtin")) {
                        UdevBuiltinCommand cmd;

                        cmd = udev_builtin_lookup(value);
                        if (cmd < 0)
                                return log_line_error_errno(rule_line, SYNTHETIC_ERRNO(EINVAL),
                                                            "Unknown builtin command: %s", value);
                        r = rule_line_add_token(rule_line, TK_M_IMPORT_BUILTIN, op, value, UDEV_BUILTIN_CMD_TO_PTR(cmd));
                } else if (streq(attr, "db"))
                        r = rule_line_add_token(rule_line, TK_M_IMPORT_DB, op, value, NULL);
                else if (streq(attr, "cmdline"))
                        r = rule_line_add_token(rule_line, TK_M_IMPORT_CMDLINE, op, value, NULL);
                else if (streq(attr, "parent"))
                        r = rule_line_add_token(rule_line, TK_M_IMPORT_PARENT, op, value, NULL);
                else
                        return log_line_invalid_attr(rule_line, key);
        } else if (streq(key, "RESULT")) {
                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (!is_match)
                        return log_line_invalid_op(rule_line, key);

                r = rule_line_add_token(rule_line, TK_M_RESULT, op, value, NULL);
        } else if (streq(key, "OPTIONS")) {
                char *tmp;

                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (is_match || op == OP_REMOVE)
                        return log_line_invalid_op(rule_line, key);
                if (op == OP_ADD)
                        op = OP_ASSIGN;

                if (streq(value, "string_escape=none"))
                        r = rule_line_add_token(rule_line, TK_A_OPTIONS_STRING_ESCAPE_NONE, op, NULL, NULL);
                else if (streq(value, "string_escape=replace"))
                        r = rule_line_add_token(rule_line, TK_A_OPTIONS_STRING_ESCAPE_REPLACE, op, NULL, NULL);
                else if (streq(value, "db_persist"))
                        r = rule_line_add_token(rule_line, TK_A_OPTIONS_DB_PERSIST, op, NULL, NULL);
                else if (streq(value, "watch"))
                        r = rule_line_add_token(rule_line, TK_A_OPTIONS_INOTIFY_WATCH, op, NULL, INT_TO_PTR(1));
                else if (streq(value, "nowatch"))
                        r = rule_line_add_token(rule_line, TK_A_OPTIONS_INOTIFY_WATCH, op, NULL, INT_TO_PTR(0));
                else if ((tmp = startswith(value, "static_node=")))
                        r = rule_line_add_token(rule_line, TK_A_OPTIONS_STATIC_NODE, op, tmp, NULL);
                else if ((tmp = startswith(value, "link_priority="))) {
                        int prio;

                        r = safe_atoi(tmp, &prio);
                        if (r < 0)
                                return log_line_error_errno(rule_line, r, "Failed to parse link priority '%s': %m", tmp);
                        r = rule_line_add_token(rule_line, TK_A_OPTIONS_DEVLINK_PRIORITY, op, NULL, INT_TO_PTR(prio));
                } else if ((tmp = startswith(value, "log_level="))) {
                        int level;

                        if (streq(tmp, "reset"))
                                level = -1;
                        else {
                                level = log_level_from_string(tmp);
                                if (level < 0)
                                        return log_line_error_errno(rule_line, level, "Failed to parse log level '%s': %m", tmp);
                        }
                        r = rule_line_add_token(rule_line, TK_A_OPTIONS_LOG_LEVEL, op, NULL, INT_TO_PTR(level));
                } else {
                        log_line_warning(rule_line, "Invalid value for OPTIONS key, ignoring: '%s'", value);
                        return 0;
                }
        } else if (streq(key, "OWNER")) {
                uid_t uid;

                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (is_match || op == OP_REMOVE)
                        return log_line_invalid_op(rule_line, key);
                if (op == OP_ADD) {
                        log_line_warning(rule_line, "%s key takes '=' or ':=' operator, assuming '='.", key);
                        op = OP_ASSIGN;
                }

                if (parse_uid(value, &uid) >= 0)
                        r = rule_line_add_token(rule_line, TK_A_OWNER_ID, op, NULL, UID_TO_PTR(uid));
                else if (resolve_name_timing == RESOLVE_NAME_EARLY &&
                           rule_get_substitution_type(value) == SUBST_TYPE_PLAIN) {
                        r = rule_resolve_user(rule_line, value, &uid);
                        if (r < 0)
                                return log_line_error_errno(rule_line, r, "Failed to resolve user name '%s': %m", value);

                        r = rule_line_add_token(rule_line, TK_A_OWNER_ID, op, NULL, UID_TO_PTR(uid));
                } else if (resolve_name_timing != RESOLVE_NAME_NEVER) {
                        check_value_format_and_warn(rule_line, key, value, true);
                        r = rule_line_add_token(rule_line, TK_A_OWNER, op, value, NULL);
                } else {
                        log_line_debug(rule_line, "User name resolution is disabled, ignoring %s=\"%s\".", key, value);
                        return 0;
                }
        } else if (streq(key, "GROUP")) {
                gid_t gid;

                if (attr)
                        return log_line_invalid_attr(rule_line, key);
                if (is_match || op == OP_REMOVE)
                        return log_line_invalid_op(rule_line, key);
                if (op == OP_ADD) {
                        log_line_warning(rule_line, "%s key takes '=' or ':=' operator, assuming '='.", key);
                        op = OP_ASSIGN;
                }

                if (parse_gid(value, &gid) >= 0)
                        r = rule_line_add_token(rule_line, TK_A_GROUP_ID, op, NULL, GID_TO_PTR(gid));
                else if (resolve_name_timing == RESOLVE_NAME_EARLY &&
                           rule_get_substitution_type(value) == SUBST_TYPE_PLAIN) {
                        r = rule_resolve_group(rule_line, value, &gid);
                        if (r < 0)
                                return log_line_error_errno(rule_line, r, "Failed to resolve group name '%s': %m", value);

                        r = rule_line_add_token(rule_line, TK_A_GROUP_ID, op, NULL, GID_TO_PTR(gid));
                } else if (resolve_name_timing != RESOLVE_NAME_NEVER) {
                        check_value_format_and_warn(rule_line, key, value, true);
                        r = rule_line_add_token(rule_line, TK_A_GROUP, op, value, NULL);
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
                        r = rule_line_add_token(rule_line, TK_A_MODE_ID, op, NULL, MODE_TO_PTR(mode));
                else {
                        check_value_format_and_warn(rule_line, key, value, true);
                        r = rule_line_add_token(rule_line, TK_A_MODE, op, value, NULL);
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

                r = rule_line_add_token(rule_line, TK_A_SECLABEL, op, value, attr);
        } else if (streq(key, "RUN")) {
                if (is_match || op == OP_REMOVE)
                        return log_line_invalid_op(rule_line, key);
                check_value_format_and_warn(rule_line, key, value, true);
                if (!attr || streq(attr, "program"))
                        r = rule_line_add_token(rule_line, TK_A_RUN_PROGRAM, op, value, NULL);
                else if (streq(attr, "builtin")) {
                        UdevBuiltinCommand cmd;

                        cmd = udev_builtin_lookup(value);
                        if (cmd < 0)
                                return log_line_error_errno(rule_line, SYNTHETIC_ERRNO(EINVAL),
                                                             "Unknown builtin command '%s', ignoring.", value);
                        r = rule_line_add_token(rule_line, TK_A_RUN_BUILTIN, op, value, UDEV_BUILTIN_CMD_TO_PTR(cmd));
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

int udev_rule_parse_value(char *str, char **ret_value, char **ret_endpos) {
        char *i, *j;
        bool is_escaped;

        /* value must be double quotated */
        is_escaped = str[0] == 'e';
        str += is_escaped;
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
        return 0;
}

static int parse_line(char **line, char **ret_key, char **ret_attr, UdevRuleOperatorType *ret_op, char **ret_value) {
        char *key_begin, *key_end, *attr, *tmp;
        UdevRuleOperatorType op;
        int r;

        assert(line);
        assert(*line);
        assert(ret_key);
        assert(ret_op);
        assert(ret_value);

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
        r = udev_rule_parse_value(tmp, ret_value, line);
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

static int rule_add_line(UdevRuleFile *rule_file, const char *line_str, unsigned line_nr, bool extra_checks) {
        _cleanup_(udev_rule_line_freep) UdevRuleLine *rule_line = NULL;
        _cleanup_free_ char *line = NULL;
        char *p;
        int r;

        assert(rule_file);
        assert(line_str);

        if (isempty(line_str))
                return 0;

        line = strdup(line_str);
        if (!line)
                return log_oom();

        rule_line = new(UdevRuleLine, 1);
        if (!rule_line)
                return log_oom();

        *rule_line = (UdevRuleLine) {
                .line = TAKE_PTR(line),
                .line_number = line_nr,
                .rule_file = rule_file,
        };

        LIST_APPEND(rule_lines, rule_file->rule_lines, rule_line);

        for (p = rule_line->line; !isempty(p); ) {
                char *key, *attr, *value;
                UdevRuleOperatorType op;

                if (extra_checks)
                        check_token_delimiters(rule_line, p);

                r = parse_line(&p, &key, &attr, &op, &value);
                if (r < 0)
                        return log_line_error_errno(rule_line, r, "Invalid key/value pair, ignoring.");
                if (r == 0)
                        break;

                r = parse_token(rule_line, key, attr, op, value);
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
               a->attr_match_remove_trailing_whitespace == b->attr_match_remove_trailing_whitespace &&
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
              a->attr_match_remove_trailing_whitespace == b->attr_match_remove_trailing_whitespace &&
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

int udev_rules_parse_file(UdevRules *rules, const char *filename, bool extra_checks, UdevRuleFile **ret) {
        _cleanup_(udev_rule_file_freep) UdevRuleFile *rule_file = NULL;
        _cleanup_free_ char *continuation = NULL, *name = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        bool ignore_line = false;
        unsigned line_nr = 0;
        struct stat st;
        int r;

        assert(rules);
        assert(filename);

        f = fopen(filename, "re");
        if (!f) {
                if (extra_checks)
                        return -errno;

                if (errno == ENOENT)
                        return 0;

                return log_warning_errno(errno, "Failed to open %s, ignoring: %m", filename);
        }

        if (fstat(fileno(f), &st) < 0)
                return log_warning_errno(errno, "Failed to stat %s, ignoring: %m", filename);

        if (null_or_empty(&st)) {
                log_debug("Skipping empty file: %s", filename);
                if (ret)
                        *ret = NULL;
                return 0;
        }

        r = hashmap_put_stats_by_path(&rules->stats_by_path, filename, &st);
        if (r < 0)
                return log_warning_errno(errno, "Failed to save stat for %s, ignoring: %m", filename);

        (void) fd_warn_permissions(filename, fileno(f));

        log_debug("Reading rules file: %s", filename);

        name = strdup(filename);
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

        for (;;) {
                _cleanup_free_ char *buf = NULL;
                size_t len;
                char *line;

                r = read_line(f, UDEV_LINE_SIZE, &buf);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                line_nr++;
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
        return 1;
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

int udev_rules_load(UdevRules **ret_rules, ResolveNameTiming resolve_name_timing) {
        _cleanup_(udev_rules_freep) UdevRules *rules = NULL;
        _cleanup_strv_free_ char **files = NULL;
        int r;

        rules = udev_rules_new(resolve_name_timing);
        if (!rules)
                return -ENOMEM;

        r = conf_files_list_strv(&files, ".rules", NULL, 0, RULES_DIRS);
        if (r < 0)
                return log_debug_errno(r, "Failed to enumerate rules files: %m");

        STRV_FOREACH(f, files) {
                r = udev_rules_parse_file(rules, *f, /* extra_checks = */ false, NULL);
                if (r < 0)
                        log_debug_errno(r, "Failed to read rules file %s, ignoring: %m", *f);
        }

        *ret_rules = TAKE_PTR(rules);
        return 0;
}

bool udev_rules_should_reload(UdevRules *rules) {
        _cleanup_hashmap_free_ Hashmap *stats_by_path = NULL;
        int r;

        if (!rules)
                return true;

        r = config_get_stats_by_path(".rules", NULL, 0, RULES_DIRS, /* check_dropins = */ false, &stats_by_path);
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

static bool token_match_string(UdevRuleToken *token, const char *str) {
        const char *value;
        bool match = false;

        assert(token);
        assert(token->value);
        assert(token->type < _TK_M_MAX);

        str = strempty(str);
        value = token->value;

        switch (token->match_type) {
        case MATCH_TYPE_EMPTY:
                match = isempty(str);
                break;
        case MATCH_TYPE_SUBSYSTEM:
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
                        if (streq(i, str)) {
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
                        if ((fnmatch(i, str, 0) == 0)) {
                                match = true;
                                break;
                        }
                break;
        default:
                assert_not_reached();
        }

        return token->op == (match ? OP_MATCH : OP_NOMATCH);
}

static bool token_match_attr(UdevRuleToken *token, sd_device *dev, UdevEvent *event) {
        char nbuf[UDEV_NAME_SIZE], vbuf[UDEV_NAME_SIZE];
        const char *name, *value;
        bool truncated;

        assert(token);
        assert(IN_SET(token->type, TK_M_ATTR, TK_M_PARENTS_ATTR));
        assert(dev);
        assert(event);

        name = token->data;

        switch (token->attr_subst_type) {
        case SUBST_TYPE_FORMAT:
                (void) udev_event_apply_format(event, name, nbuf, sizeof(nbuf), false, &truncated);
                if (truncated) {
                        log_event_truncated(dev, token, "sysfs attribute name", name,
                                            token->type == TK_M_ATTR ? "ATTR" : "ATTRS", /* is_match = */ true);
                        return false;
                }

                name = nbuf;
                _fallthrough_;
        case SUBST_TYPE_PLAIN:
                if (sd_device_get_sysattr_value(dev, name, &value) < 0)
                        return false;
                break;
        case SUBST_TYPE_SUBSYS:
                if (udev_resolve_subsys_kernel(name, vbuf, sizeof(vbuf), true) < 0)
                        return false;
                value = vbuf;
                break;
        default:
                assert_not_reached();
        }

        /* remove trailing whitespace, if not asked to match for it */
        if (token->attr_match_remove_trailing_whitespace) {
                if (value != vbuf) {
                        strscpy(vbuf, sizeof(vbuf), value);
                        value = vbuf;
                }

                delete_trailing_chars(vbuf, NULL);
        }

        return token_match_string(token, value);
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

static int import_parent_into_properties(sd_device *dev, const char *filter) {
        sd_device *parent;
        int r;

        assert(dev);
        assert(filter);

        r = sd_device_get_parent(dev, &parent);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        FOREACH_DEVICE_PROPERTY(parent, key, val) {
                if (fnmatch(filter, key, 0) != 0)
                        continue;
                r = device_add_property(dev, key, val);
                if (r < 0)
                        return r;
        }

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

static size_t udev_replace_ifname(char *str) {
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
                        return log_event_error_errno(dev, token, r, "Failed to get uevent action type: %m");

                return token_match_string(token, device_action_to_string(a));
        }
        case TK_M_DEVPATH: {
                const char *val;

                r = sd_device_get_devpath(dev, &val);
                if (r < 0)
                        return log_event_error_errno(dev, token, r, "Failed to get devpath: %m");

                return token_match_string(token, val);
        }
        case TK_M_KERNEL:
        case TK_M_PARENTS_KERNEL: {
                const char *val;

                r = sd_device_get_sysname(dev, &val);
                if (r < 0)
                        return log_event_error_errno(dev, token, r, "Failed to get sysname: %m");

                return token_match_string(token, val);
        }
        case TK_M_DEVLINK:
                FOREACH_DEVICE_DEVLINK(dev, val)
                        if (token_match_string(token, strempty(startswith(val, "/dev/"))) == (token->op == OP_MATCH))
                                return token->op == OP_MATCH;
                return token->op == OP_NOMATCH;
        case TK_M_NAME:
                return token_match_string(token, event->name);
        case TK_M_ENV: {
                const char *val = NULL;

                (void) device_get_property_value_with_fallback(dev, token->data, event->worker ? event->worker->properties : NULL, &val);

                return token_match_string(token, val);
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
                return token_match_string(token, val);
        }
        case TK_M_TAG:
        case TK_M_PARENTS_TAG:
                FOREACH_DEVICE_CURRENT_TAG(dev, val)
                        if (token_match_string(token, val) == (token->op == OP_MATCH))
                                return token->op == OP_MATCH;
                return token->op == OP_NOMATCH;
        case TK_M_SUBSYSTEM:
        case TK_M_PARENTS_SUBSYSTEM: {
                const char *val;

                r = sd_device_get_subsystem(dev, &val);
                if (r == -ENOENT)
                        val = NULL;
                else if (r < 0)
                        return log_event_error_errno(dev, token, r, "Failed to get subsystem: %m");

                return token_match_string(token, val);
        }
        case TK_M_DRIVER:
        case TK_M_PARENTS_DRIVER: {
                const char *val;

                r = sd_device_get_driver(dev, &val);
                if (r == -ENOENT)
                        val = NULL;
                else if (r < 0)
                        return log_event_error_errno(dev, token, r, "Failed to get driver: %m");

                return token_match_string(token, val);
        }
        case TK_M_ATTR:
        case TK_M_PARENTS_ATTR:
                return token_match_attr(token, dev, event);
        case TK_M_SYSCTL: {
                _cleanup_free_ char *value = NULL;
                char buf[UDEV_PATH_SIZE];
                bool truncated;

                (void) udev_event_apply_format(event, token->data, buf, sizeof(buf), false, &truncated);
                if (truncated) {
                        log_event_truncated(dev, token, "sysctl entry name", token->data, "SYSCTL", /* is_match = */ true);
                        return false;
                }

                r = sysctl_read(sysctl_normalize(buf), &value);
                if (r < 0 && r != -ENOENT)
                        return log_event_error_errno(dev, token, r, "Failed to read sysctl '%s': %m", buf);

                return token_match_string(token, strstrip(value));
        }
        case TK_M_TEST: {
                mode_t mode = PTR_TO_MODE(token->data);
                char buf[UDEV_PATH_SIZE];
                struct stat statbuf;
                bool match, truncated;

                (void) udev_event_apply_format(event, token->value, buf, sizeof(buf), false, &truncated);
                if (truncated) {
                        log_event_truncated(dev, token, "file name", token->value, "TEST", /* is_match = */ true);
                        return false;
                }

                if (!path_is_absolute(buf) &&
                    udev_resolve_subsys_kernel(buf, buf, sizeof(buf), false) < 0) {
                        char tmp[UDEV_PATH_SIZE];
                        const char *val;

                        r = sd_device_get_syspath(dev, &val);
                        if (r < 0)
                                return log_event_error_errno(dev, token, r, "Failed to get syspath: %m");

                        strscpy_full(tmp, sizeof(tmp), buf, &truncated);
                        assert(!truncated);
                        strscpyl_full(buf, sizeof(buf), &truncated, val, "/", tmp, NULL);
                        if (truncated)
                                return false;
                }

                r = attr_subst_subdir(buf);
                if (r == -ENOENT)
                        return token->op == OP_NOMATCH;
                if (r < 0)
                        return log_event_error_errno(dev, token, r, "Failed to test for the existence of '%s': %m", buf);

                if (stat(buf, &statbuf) < 0)
                        return token->op == OP_NOMATCH;

                if (mode == MODE_INVALID)
                        return token->op == OP_MATCH;

                match = (statbuf.st_mode & mode) > 0;
                return token->op == (match ? OP_MATCH : OP_NOMATCH);
        }
        case TK_M_PROGRAM: {
                char buf[UDEV_LINE_SIZE], result[UDEV_LINE_SIZE];
                bool truncated;
                size_t count;

                event->program_result = mfree(event->program_result);
                (void) udev_event_apply_format(event, token->value, buf, sizeof(buf), false, &truncated);
                if (truncated) {
                        log_event_truncated(dev, token, "command", token->value, "PROGRAM", /* is_match = */ true);
                        return false;
                }

                log_event_debug(dev, token, "Running PROGRAM '%s'", buf);

                r = udev_event_spawn(event, /* accept_failure = */ true, buf, result, sizeof(result), NULL);
                if (r != 0) {
                        if (r < 0)
                                log_event_warning_errno(dev, token, r, "Failed to execute \"%s\": %m", buf);
                        else /* returned value is positive when program fails */
                                log_event_debug(dev, token, "Command \"%s\" returned %d (error)", buf, r);
                        return token->op == OP_NOMATCH;
                }

                delete_trailing_chars(result, "\n");
                count = udev_replace_chars(result, UDEV_ALLOWED_CHARS_INPUT);
                if (count > 0)
                        log_event_debug(dev, token,
                                        "Replaced %zu character(s) in result of \"%s\"",
                                        count, buf);

                event->program_result = strdup(result);
                return token->op == OP_MATCH;
        }
        case TK_M_IMPORT_FILE: {
                _cleanup_fclose_ FILE *f = NULL;
                char buf[UDEV_PATH_SIZE];
                bool truncated;

                (void) udev_event_apply_format(event, token->value, buf, sizeof(buf), false, &truncated);
                if (truncated) {
                        log_event_truncated(dev, token, "file name to be imported", token->value, "IMPORT", /* is_match = */ true);
                        return false;
                }

                log_event_debug(dev, token, "Importing properties from '%s'", buf);

                f = fopen(buf, "re");
                if (!f) {
                        if (errno != ENOENT)
                                return log_event_error_errno(dev, token, errno, "Failed to open '%s': %m", buf);
                        return token->op == OP_NOMATCH;
                }

                for (;;) {
                        _cleanup_free_ char *line = NULL;
                        char *key, *value;

                        r = read_line(f, LONG_LINE_MAX, &line);
                        if (r < 0) {
                                log_event_debug_errno(dev, token, r, "Failed to read '%s', ignoring: %m", buf);
                                return token->op == OP_NOMATCH;
                        }
                        if (r == 0)
                                break;

                        r = get_property_from_string(line, &key, &value);
                        if (r < 0) {
                                log_event_debug_errno(dev, token, r,
                                                      "Failed to parse key and value from '%s', ignoring: %m",
                                                      line);
                                continue;
                        }
                        if (r == 0)
                                continue;

                        r = device_add_property(dev, key, value);
                        if (r < 0)
                                return log_event_error_errno(dev, token, r,
                                                             "Failed to add property %s=%s: %m",
                                                             key, value);
                }

                return token->op == OP_MATCH;
        }
        case TK_M_IMPORT_PROGRAM: {
                _cleanup_strv_free_ char **lines = NULL;
                char buf[UDEV_LINE_SIZE], result[UDEV_LINE_SIZE];
                bool truncated;

                (void) udev_event_apply_format(event, token->value, buf, sizeof(buf), false, &truncated);
                if (truncated) {
                        log_event_truncated(dev, token, "command", token->value, "IMPORT", /* is_match = */ true);
                        return false;
                }

                log_event_debug(dev, token, "Importing properties from results of '%s'", buf);

                r = udev_event_spawn(event, /* accept_failure = */ true, buf, result, sizeof result, &truncated);
                if (r != 0) {
                        if (r < 0)
                                log_event_warning_errno(dev, token, r, "Failed to execute '%s', ignoring: %m", buf);
                        else /* returned value is positive when program fails */
                                log_event_debug(dev, token, "Command \"%s\" returned %d (error), ignoring", buf, r);
                        return token->op == OP_NOMATCH;
                }

                if (truncated) {
                        bool found = false;

                        /* Drop the last line. */
                        for (char *p = PTR_SUB1(buf + strlen(buf), buf); p; p = PTR_SUB1(p, buf))
                                if (strchr(NEWLINE, *p)) {
                                        *p = '\0';
                                        found = true;
                                } else if (found)
                                        break;
                }

                r = strv_split_newlines_full(&lines, result, EXTRACT_RETAIN_ESCAPE);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_event_warning_errno(dev, token, r,
                                                "Failed to extract lines from result of command \"%s\", ignoring: %m", buf);
                        return false;
                }

                STRV_FOREACH(line, lines) {
                        char *key, *value;

                        r = get_property_from_string(*line, &key, &value);
                        if (r < 0) {
                                log_event_debug_errno(dev, token, r,
                                                      "Failed to parse key and value from '%s', ignoring: %m",
                                                      *line);
                                continue;
                        }
                        if (r == 0)
                                continue;

                        r = device_add_property(dev, key, value);
                        if (r < 0)
                                return log_event_error_errno(dev, token, r,
                                                             "Failed to add property %s=%s: %m",
                                                             key, value);
                }

                return token->op == OP_MATCH;
        }
        case TK_M_IMPORT_BUILTIN: {
                UdevBuiltinCommand cmd = PTR_TO_UDEV_BUILTIN_CMD(token->data);
                assert(cmd >= 0 && cmd < _UDEV_BUILTIN_MAX);
                unsigned mask = 1U << (int) cmd;
                char buf[UDEV_LINE_SIZE];
                bool truncated;

                if (udev_builtin_run_once(cmd)) {
                        /* check if we ran already */
                        if (event->builtin_run & mask) {
                                log_event_debug(dev, token, "Skipping builtin '%s' in IMPORT key",
                                                udev_builtin_name(cmd));
                                /* return the result from earlier run */
                                return token->op == (event->builtin_ret & mask ? OP_NOMATCH : OP_MATCH);
                        }
                        /* mark as ran */
                        event->builtin_run |= mask;
                }

                (void) udev_event_apply_format(event, token->value, buf, sizeof(buf), false, &truncated);
                if (truncated) {
                        log_event_truncated(dev, token, "builtin command", token->value, "IMPORT", /* is_match = */ true);
                        return false;
                }

                log_event_debug(dev, token, "Importing properties from results of builtin command '%s'", buf);

                r = udev_builtin_run(event, cmd, buf, false);
                if (r < 0) {
                        /* remember failure */
                        log_event_debug_errno(dev, token, r, "Failed to run builtin '%s': %m", buf);
                        event->builtin_ret |= mask;
                }
                return token->op == (r >= 0 ? OP_MATCH : OP_NOMATCH);
        }
        case TK_M_IMPORT_DB: {
                const char *val;

                if (!event->dev_db_clone)
                        return token->op == OP_NOMATCH;
                r = sd_device_get_property_value(event->dev_db_clone, token->value, &val);
                if (r == -ENOENT)
                        return token->op == OP_NOMATCH;
                if (r < 0)
                        return log_event_error_errno(dev, token, r,
                                                     "Failed to get property '%s' from database: %m",
                                                     token->value);

                r = device_add_property(dev, token->value, val);
                if (r < 0)
                        return log_event_error_errno(dev, token, r, "Failed to add property '%s=%s': %m",
                                                     token->value, val);
                return token->op == OP_MATCH;
        }
        case TK_M_IMPORT_CMDLINE: {
                _cleanup_free_ char *value = NULL;

                r = proc_cmdline_get_key(token->value, PROC_CMDLINE_VALUE_OPTIONAL|PROC_CMDLINE_IGNORE_EFI_OPTIONS, &value);
                if (r < 0)
                        return log_event_error_errno(dev, token, r,
                                                     "Failed to read '%s' option from /proc/cmdline: %m",
                                                     token->value);
                if (r == 0)
                        return token->op == OP_NOMATCH;

                r = device_add_property(dev, token->value, value ?: "1");
                if (r < 0)
                        return log_event_error_errno(dev, token, r, "Failed to add property '%s=%s': %m",
                                                     token->value, value ?: "1");
                return token->op == OP_MATCH;
        }
        case TK_M_IMPORT_PARENT: {
                char buf[UDEV_PATH_SIZE];
                bool truncated;

                (void) udev_event_apply_format(event, token->value, buf, sizeof(buf), false, &truncated);
                if (truncated) {
                        log_event_truncated(dev, token, "property name", token->value, "IMPORT", /* is_match = */ true);
                        return false;
                }

                r = import_parent_into_properties(dev, buf);
                if (r < 0)
                        return log_event_error_errno(dev, token, r,
                                                     "Failed to import properties '%s' from parent: %m",
                                                     buf);
                return token->op == (r > 0 ? OP_MATCH : OP_NOMATCH);
        }
        case TK_M_RESULT:
                return token_match_string(token, event->program_result);
        case TK_A_OPTIONS_STRING_ESCAPE_NONE:
                event->esc = ESCAPE_NONE;
                break;
        case TK_A_OPTIONS_STRING_ESCAPE_REPLACE:
                event->esc = ESCAPE_REPLACE;
                break;
        case TK_A_OPTIONS_DB_PERSIST:
                device_set_db_persist(dev);
                break;
        case TK_A_OPTIONS_INOTIFY_WATCH:
                if (event->inotify_watch_final)
                        break;
                if (token->op == OP_ASSIGN_FINAL)
                        event->inotify_watch_final = true;

                event->inotify_watch = token->data;
                break;
        case TK_A_OPTIONS_DEVLINK_PRIORITY:
                device_set_devlink_priority(dev, PTR_TO_INT(token->data));
                break;
        case TK_A_OPTIONS_LOG_LEVEL: {
                int level = PTR_TO_INT(token->data);

                if (level < 0)
                        level = event->default_log_level;

                log_set_max_level(level);

                if (level == LOG_DEBUG && !event->log_level_was_debug) {
                        /* The log level becomes LOG_DEBUG at first time. Let's log basic information. */
                        log_device_uevent(dev, "The log level is changed to 'debug' while processing device");
                        event->log_level_was_debug = true;
                }

                break;
        }
        case TK_A_OWNER: {
                char owner[UDEV_NAME_SIZE];
                const char *ow = owner;
                bool truncated;

                if (event->owner_final)
                        break;
                if (token->op == OP_ASSIGN_FINAL)
                        event->owner_final = true;

                (void) udev_event_apply_format(event, token->value, owner, sizeof(owner), false, &truncated);
                if (truncated) {
                        log_event_truncated(dev, token, "user name", token->value, "OWNER", /* is_match = */ false);
                        break;
                }

                r = get_user_creds(&ow, &event->uid, NULL, NULL, NULL, USER_CREDS_ALLOW_MISSING);
                if (r < 0)
                        log_unknown_owner(dev, token->rule_line, r, "user", owner);
                else
                        log_event_debug(dev, token, "OWNER %s(%u)", owner, event->uid);
                break;
        }
        case TK_A_GROUP: {
                char group[UDEV_NAME_SIZE];
                const char *gr = group;
                bool truncated;

                if (event->group_final)
                        break;
                if (token->op == OP_ASSIGN_FINAL)
                        event->group_final = true;

                (void) udev_event_apply_format(event, token->value, group, sizeof(group), false, &truncated);
                if (truncated) {
                        log_event_truncated(dev, token, "group name", token->value, "GROUP", /* is_match = */ false);
                        break;
                }

                r = get_group_creds(&gr, &event->gid, USER_CREDS_ALLOW_MISSING);
                if (r < 0)
                        log_unknown_owner(dev, token->rule_line, r, "group", group);
                else
                        log_event_debug(dev, token, "GROUP %s(%u)", group, event->gid);
                break;
        }
        case TK_A_MODE: {
                char mode_str[UDEV_NAME_SIZE];
                bool truncated;

                if (event->mode_final)
                        break;
                if (token->op == OP_ASSIGN_FINAL)
                        event->mode_final = true;

                (void) udev_event_apply_format(event, token->value, mode_str, sizeof(mode_str), false, &truncated);
                if (truncated) {
                        log_event_truncated(dev, token, "mode", token->value, "MODE", /* is_match = */ false);
                        break;
                }

                r = parse_mode(mode_str, &event->mode);
                if (r < 0)
                        log_event_error_errno(dev, token, r, "Failed to parse mode '%s', ignoring: %m", mode_str);
                else
                        log_event_debug(dev, token, "MODE %#o", event->mode);
                break;
        }
        case TK_A_OWNER_ID:
                if (event->owner_final)
                        break;
                if (token->op == OP_ASSIGN_FINAL)
                        event->owner_final = true;
                if (!token->data)
                        break;
                event->uid = PTR_TO_UID(token->data);
                log_event_debug(dev, token, "OWNER %u", event->uid);
                break;
        case TK_A_GROUP_ID:
                if (event->group_final)
                        break;
                if (token->op == OP_ASSIGN_FINAL)
                        event->group_final = true;
                if (!token->data)
                        break;
                event->gid = PTR_TO_GID(token->data);
                log_event_debug(dev, token, "GROUP %u", event->gid);
                break;
        case TK_A_MODE_ID:
                if (event->mode_final)
                        break;
                if (token->op == OP_ASSIGN_FINAL)
                        event->mode_final = true;
                if (!token->data)
                        break;
                event->mode = PTR_TO_MODE(token->data);
                log_event_debug(dev, token, "MODE %#o", event->mode);
                break;
        case TK_A_SECLABEL: {
                _cleanup_free_ char *name = NULL, *label = NULL;
                char label_str[UDEV_LINE_SIZE] = {};
                bool truncated;

                name = strdup(token->data);
                if (!name)
                        return log_oom();

                (void) udev_event_apply_format(event, token->value, label_str, sizeof(label_str), false, &truncated);
                if (truncated) {
                        log_event_truncated(dev, token, "security label", token->value, "SECLABEL", /* is_match = */ false);
                        break;
                }

                if (!isempty(label_str))
                        label = strdup(label_str);
                else
                        label = strdup(token->value);
                if (!label)
                        return log_oom();

                if (token->op == OP_ASSIGN)
                        ordered_hashmap_clear_free_free(event->seclabel_list);

                r = ordered_hashmap_ensure_put(&event->seclabel_list, NULL, name, label);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        return log_event_error_errno(dev, token, r, "Failed to store SECLABEL{%s}='%s': %m", name, label);

                log_event_debug(dev, token, "SECLABEL{%s}='%s'", name, label);

                TAKE_PTR(name);
                TAKE_PTR(label);
                break;
        }
        case TK_A_ENV: {
                const char *val, *name = token->data;
                char value_new[UDEV_NAME_SIZE], *p = value_new;
                size_t count, l = sizeof(value_new);
                bool truncated;

                if (isempty(token->value)) {
                        if (token->op == OP_ADD)
                                break;
                        r = device_add_property(dev, name, NULL);
                        if (r < 0)
                                return log_event_error_errno(dev, token, r, "Failed to remove property '%s': %m", name);
                        break;
                }

                if (token->op == OP_ADD &&
                    device_get_property_value_with_fallback(dev, name, event->worker ? event->worker->properties : NULL, &val) >= 0) {
                        l = strpcpyl_full(&p, l, &truncated, val, " ", NULL);
                        if (truncated) {
                                log_event_warning(dev, token,
                                                  "The buffer for the property '%s' is full, "
                                                  "refusing to append the new value '%s'.", name, token->value);
                                break;
                        }
                }

                (void) udev_event_apply_format(event, token->value, p, l, false, &truncated);
                if (truncated) {
                        _cleanup_free_ char *key_with_name = strjoin("ENV{", name, "}");
                        log_event_truncated(dev, token, "property value", token->value,
                                            key_with_name ?: "ENV", /* is_match = */ false);
                        break;
                }

                if (event->esc == ESCAPE_REPLACE) {
                        count = udev_replace_chars(p, NULL);
                        if (count > 0)
                                log_event_debug(dev, token,
                                                "Replaced %zu slash(es) from result of ENV{%s}%s=\"%s\"",
                                                count, name, token->op == OP_ADD ? "+" : "", token->value);
                }

                r = device_add_property(dev, name, value_new);
                if (r < 0)
                        return log_event_error_errno(dev, token, r, "Failed to add property '%s=%s': %m", name, value_new);
                break;
        }
        case TK_A_TAG: {
                char buf[UDEV_PATH_SIZE];
                bool truncated;

                (void) udev_event_apply_format(event, token->value, buf, sizeof(buf), false, &truncated);
                if (truncated) {
                        log_event_truncated(dev, token, "tag name", token->value, "TAG", /* is_match = */ false);
                        break;
                }

                if (token->op == OP_ASSIGN)
                        device_cleanup_tags(dev);

                if (token->op == OP_REMOVE)
                        device_remove_tag(dev, buf);
                else {
                        r = device_add_tag(dev, buf, true);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0)
                                log_event_warning_errno(dev, token, r, "Failed to add tag '%s', ignoring: %m", buf);
                }
                break;
        }
        case TK_A_NAME: {
                char buf[UDEV_PATH_SIZE];
                bool truncated;
                size_t count;

                if (event->name_final)
                        break;
                if (token->op == OP_ASSIGN_FINAL)
                        event->name_final = true;

                if (sd_device_get_ifindex(dev, NULL) < 0) {
                        log_event_error(dev, token,
                                        "Only network interfaces can be renamed, ignoring NAME=\"%s\".",
                                        token->value);
                        break;
                }

                (void) udev_event_apply_format(event, token->value, buf, sizeof(buf), false, &truncated);
                if (truncated) {
                        log_event_truncated(dev, token, "network interface name", token->value, "NAME", /* is_match = */ false);
                        break;
                }

                if (IN_SET(event->esc, ESCAPE_UNSET, ESCAPE_REPLACE)) {
                        if (naming_scheme_has(NAMING_REPLACE_STRICTLY))
                                count = udev_replace_ifname(buf);
                        else
                                count = udev_replace_chars(buf, "/");
                        if (count > 0)
                                log_event_debug(dev, token,
                                                "Replaced %zu character(s) from result of NAME=\"%s\"",
                                                count, token->value);
                }
                r = free_and_strdup_warn(&event->name, buf);
                if (r < 0)
                        return r;

                log_event_debug(dev, token, "NAME '%s'", event->name);
                break;
        }
        case TK_A_DEVLINK: {
                char buf[UDEV_PATH_SIZE];
                bool truncated;
                size_t count;

                if (event->devlink_final)
                        break;
                if (sd_device_get_devnum(dev, NULL) < 0)
                        break;
                if (token->op == OP_ASSIGN_FINAL)
                        event->devlink_final = true;
                if (IN_SET(token->op, OP_ASSIGN, OP_ASSIGN_FINAL))
                        device_cleanup_devlinks(dev);

                (void) udev_event_apply_format(event, token->value, buf, sizeof(buf),
                                               /* replace_whitespace = */ event->esc != ESCAPE_NONE, &truncated);
                if (truncated) {
                        log_event_truncated(dev, token, "symbolic link path", token->value, "SYMLINK", /* is_match = */ false);
                        break;
                }

                /* By default or string_escape=none, allow multiple symlinks separated by spaces. */
                if (event->esc == ESCAPE_UNSET)
                        count = udev_replace_chars(buf, /* allow = */ "/ ");
                else if (event->esc == ESCAPE_REPLACE)
                        count = udev_replace_chars(buf, /* allow = */ "/");
                else
                        count = 0;
                if (count > 0)
                        log_event_debug(dev, token,
                                        "Replaced %zu character(s) from result of SYMLINK=\"%s\"",
                                        count, token->value);

                for (const char *p = buf;;) {
                        _cleanup_free_ char *path = NULL;

                        r = extract_first_word(&p, &path, NULL, EXTRACT_RETAIN_ESCAPE);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0) {
                                log_warning_errno(r, "Failed to extract first path in SYMLINK=, ignoring: %m");
                                break;
                        }
                        if (r == 0)
                                break;

                        if (token->op == OP_REMOVE) {
                                r = device_remove_devlink(dev, path);
                                if (r == -ENOMEM)
                                        return log_oom();
                                if (r < 0)
                                        log_event_warning_errno(dev, token, r, "Failed to remove devlink '%s', ignoring: %m", path);
                                else if (r > 0)
                                        log_event_debug(dev, token, "Dropped SYMLINK '%s'", path);
                        } else {
                                r = device_add_devlink(dev, path);
                                if (r == -ENOMEM)
                                        return log_oom();
                                if (r < 0)
                                        log_event_warning_errno(dev, token, r, "Failed to add devlink '%s', ignoring: %m", path);
                                else if (r > 0)
                                        log_event_debug(dev, token, "Added SYMLINK '%s'", path);
                        }
                }
                break;
        }
        case TK_A_ATTR: {
                char buf[UDEV_PATH_SIZE], value[UDEV_NAME_SIZE];
                const char *val, *key_name = token->data;
                bool truncated;

                if (udev_resolve_subsys_kernel(key_name, buf, sizeof(buf), false) < 0 &&
                    sd_device_get_syspath(dev, &val) >= 0) {
                        strscpyl_full(buf, sizeof(buf), &truncated, val, "/", key_name, NULL);
                        if (truncated) {
                                log_event_warning(dev, token,
                                                  "The path to the attribute '%s/%s' is too long, refusing to set the attribute.",
                                                  val, key_name);
                                break;
                        }
                }

                r = attr_subst_subdir(buf);
                if (r < 0) {
                        log_event_error_errno(dev, token, r, "Could not find file matches '%s', ignoring: %m", buf);
                        break;
                }
                (void) udev_event_apply_format(event, token->value, value, sizeof(value), false, &truncated);
                if (truncated) {
                        log_event_truncated(dev, token, "attribute value", token->value, "ATTR", /* is_match = */ false);
                        break;
                }

                log_event_debug(dev, token, "ATTR '%s' writing '%s'", buf, value);
                r = write_string_file(buf, value,
                                      WRITE_STRING_FILE_VERIFY_ON_FAILURE |
                                      WRITE_STRING_FILE_DISABLE_BUFFER |
                                      WRITE_STRING_FILE_AVOID_NEWLINE |
                                      WRITE_STRING_FILE_VERIFY_IGNORE_NEWLINE);
                if (r < 0)
                        log_event_error_errno(dev, token, r, "Failed to write ATTR{%s}, ignoring: %m", buf);
                break;
        }
        case TK_A_SYSCTL: {
                char buf[UDEV_PATH_SIZE], value[UDEV_NAME_SIZE];
                bool truncated;

                (void) udev_event_apply_format(event, token->data, buf, sizeof(buf), false, &truncated);
                if (truncated) {
                        log_event_truncated(dev, token, "sysctl entry name", token->data, "SYSCTL", /* is_match = */ false);
                        break;
                }

                (void) udev_event_apply_format(event, token->value, value, sizeof(value), false, &truncated);
                if (truncated) {
                        _cleanup_free_ char *key_with_name = strjoin("SYSCTL{", buf, "}");
                        log_event_truncated(dev, token, "sysctl value", token->value,
                                            key_with_name ?: "SYSCTL", /* is_match = */ false);
                        break;
                }

                sysctl_normalize(buf);
                log_event_debug(dev, token, "SYSCTL '%s' writing '%s'", buf, value);
                r = sysctl_write(buf, value);
                if (r < 0)
                        log_event_error_errno(dev, token, r, "Failed to write SYSCTL{%s}='%s', ignoring: %m", buf, value);
                break;
        }
        case TK_A_RUN_BUILTIN:
        case TK_A_RUN_PROGRAM: {
                _cleanup_free_ char *cmd = NULL;
                char buf[UDEV_LINE_SIZE];
                bool truncated;

                if (event->run_final)
                        break;
                if (token->op == OP_ASSIGN_FINAL)
                        event->run_final = true;

                if (IN_SET(token->op, OP_ASSIGN, OP_ASSIGN_FINAL))
                        ordered_hashmap_clear_free_key(event->run_list);

                (void) udev_event_apply_format(event, token->value, buf, sizeof(buf), false, &truncated);
                if (truncated) {
                        log_event_truncated(dev, token, "command", token->value,
                                            token->type == TK_A_RUN_BUILTIN ? "RUN{builtin}" : "RUN{program}",
                                            /* is_match = */ false);
                        break;
                }

                cmd = strdup(buf);
                if (!cmd)
                        return log_oom();

                r = ordered_hashmap_ensure_put(&event->run_list, NULL, cmd, token->data);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        return log_event_error_errno(dev, token, r, "Failed to store command '%s': %m", cmd);

                TAKE_PTR(cmd);

                log_event_debug(dev, token, "RUN '%s'", token->value);
                break;
        }
        case TK_A_OPTIONS_STATIC_NODE:
                /* do nothing for events. */
                break;
        default:
                assert_not_reached();
        }

        return true;
}

static bool token_is_for_parents(UdevRuleToken *token) {
        return token->type >= TK_M_PARENTS_KERNEL && token->type <= TK_M_PARENTS_TAG;
}

static int udev_rule_apply_parent_token_to_event(UdevRuleToken *head_token, UdevEvent *event) {
        int r;

        assert(head_token);
        assert(event);

        event->dev_parent = ASSERT_PTR(event->dev);

        for (;;) {
                LIST_FOREACH(tokens, token, head_token) {
                        if (!token_is_for_parents(token))
                                return true; /* All parent tokens match. */

                        r = udev_rule_apply_token_to_event(token, event->dev_parent, event);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;
                }
                if (r > 0)
                        /* All parent tokens match, and no more token (except for GOTO) in the line. */
                        return true;

                if (sd_device_get_parent(event->dev_parent, &event->dev_parent) < 0) {
                        event->dev_parent = NULL;
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

        if (line->goto_line)
                *next_line = line->goto_line; /* update next_line only when the line has GOTO token. */

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
