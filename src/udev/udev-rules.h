/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

#include "device-util.h"
#include "hashmap.h"
#include "list.h"
#include "time-util.h"
#include "udev-util.h"

typedef struct UdevRules UdevRules;
typedef struct UdevRuleFile UdevRuleFile;
typedef struct UdevRuleLine UdevRuleLine;
typedef struct UdevRuleToken UdevRuleToken;
typedef struct UdevEvent UdevEvent;

typedef enum {
        OP_MATCH,        /* == */
        OP_NOMATCH,      /* != */
        OP_ADD,          /* += */
        OP_REMOVE,       /* -= */
        OP_ASSIGN,       /* = */
        OP_ASSIGN_FINAL, /* := */
        _OP_TYPE_MAX,
        _OP_TYPE_INVALID = -1
} UdevRuleOperatorType;

typedef enum {
        MATCH_TYPE_EMPTY,     /* empty string */
        MATCH_TYPE_PLAIN,     /* no special characters */
        MATCH_TYPE_GLOB,      /* shell globs ?,*,[] */
        MATCH_TYPE_SUBSYSTEM, /* "subsystem", "bus", or "class" */
        _MATCH_TYPE_MAX,
        _MATCH_TYPE_INVALID = -1
} UdevRuleMatchType;

typedef enum {
        SUBST_TYPE_PLAIN,  /* no substitution */
        SUBST_TYPE_FORMAT, /* % or $ */
        SUBST_TYPE_SUBSYS, /* "[<SUBSYSTEM>/<KERNEL>]<attribute>" format */
        _SUBST_TYPE_MAX,
        _SUBST_TYPE_INVALID = -1
} UdevRuleSubstituteType;

typedef enum {
        ESCAPE_UNSET,
        ESCAPE_NONE,    /* OPTIONS="string_escape=none" */
        ESCAPE_REPLACE, /* OPTIONS="string_escape=replace" */
        _ESCAPE_TYPE_MAX,
        _ESCAPE_TYPE_INVALID = -1
} UdevRuleEscapeType;

typedef enum {
        /* lvalues which take match or nomatch operator */
        TK_M_ACTION,                        /* string, device_get_action() */
        TK_M_DEVPATH,                       /* path, sd_device_get_devpath() */
        TK_M_KERNEL,                        /* string, sd_device_get_sysname() */
        TK_M_DEVLINK,                       /* strv, sd_device_get_devlink_first(), sd_device_get_devlink_next() */
        TK_M_NAME,                          /* string, name of network interface */
        TK_M_ENV,                           /* string, device property, takes key through attribute */
        TK_M_TAG,                           /* strv, sd_device_get_tag_first(), sd_device_get_tag_next() */
        TK_M_SUBSYSTEM,                     /* string, sd_device_get_subsystem() */
        TK_M_DRIVER,                        /* string, sd_device_get_driver() */
        TK_M_ATTR,                          /* string, takes filename through attribute, sd_device_get_sysattr_value(), util_resolve_subsys_kernel(), etc. */
        TK_M_SYSCTL,                        /* string, takes kernel parameter through attribute */

        /* matches parent paramters */
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
        _TK_TYPE_INVALID = -1,
} UdevRuleTokenType;

typedef enum {
        LINE_HAS_NAME         = 1 << 0, /* has NAME= */
        LINE_HAS_DEVLINK      = 1 << 1, /* has SYMLINK=, OWNER=, GROUP= or MODE= */
        LINE_HAS_STATIC_NODE  = 1 << 2, /* has OPTIONS=static_node */
        LINE_HAS_GOTO         = 1 << 3, /* has GOTO= */
        LINE_HAS_LABEL        = 1 << 4, /* has LABEL= */
        LINE_UPDATE_SOMETHING = 1 << 5, /* has other TK_A_* or TK_M_IMPORT tokens */
} UdevRuleLineType;

struct UdevRuleToken {
        UdevRuleTokenType type:8;
        UdevRuleOperatorType op:8;
        UdevRuleMatchType match_type:8;
        UdevRuleSubstituteType attr_subst_type:7;
        bool attr_match_remove_trailing_whitespace:1;
        const char *value;
        void *data;
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
        UdevRuleToken *current_token;
        LIST_HEAD(UdevRuleToken, tokens);
        LIST_FIELDS(UdevRuleLine, rule_lines);
};

struct UdevRuleFile {
        char *filename;
        UdevRuleLine *current_line;
        LIST_HEAD(UdevRuleLine, rule_lines);
        LIST_FIELDS(UdevRuleFile, rule_files);
};

struct UdevRules {
        usec_t dirs_ts_usec;
        ResolveNameTiming resolve_name_timing;
        Hashmap *known_users;
        Hashmap *known_groups;
        UdevRuleFile *current_file;
        LIST_HEAD(UdevRuleFile, rule_files);
};

int udev_rules_new(UdevRules **ret_rules, ResolveNameTiming resolve_name_timing);
UdevRules *udev_rules_free(UdevRules *rules);
DEFINE_TRIVIAL_CLEANUP_FUNC(UdevRules*, udev_rules_free);

bool udev_rules_check_timestamp(UdevRules *rules);
int udev_rules_apply_to_event(UdevRules *rules, UdevEvent *event,
                              usec_t timeout_usec,
                              Hashmap *properties_list);
int udev_rules_apply_static_dev_perms(UdevRules *rules);
