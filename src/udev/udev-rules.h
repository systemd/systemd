/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "alloc-util.h"
#include "hashmap.h"
#include "time-util.h"

#define UDEV_NAME_SIZE   512
#define UDEV_PATH_SIZE  1024
#define UDEV_LINE_SIZE 16384

typedef struct UdevRuleFile UdevRuleFile;
typedef struct UdevRules UdevRules;
typedef struct UdevEvent UdevEvent;

typedef enum {
        ESCAPE_UNSET,
        ESCAPE_NONE,    /* OPTIONS="string_escape=none" */
        ESCAPE_REPLACE, /* OPTIONS="string_escape=replace" */
        _ESCAPE_TYPE_MAX,
        _ESCAPE_TYPE_INVALID = -EINVAL,
} UdevRuleEscapeType;

typedef enum ResolveNameTiming {
        RESOLVE_NAME_NEVER,
        RESOLVE_NAME_LATE,
        RESOLVE_NAME_EARLY,
        _RESOLVE_NAME_TIMING_MAX,
        _RESOLVE_NAME_TIMING_INVALID = -EINVAL,
} ResolveNameTiming;

int udev_rule_parse_value(char *str, char **ret_value, char **ret_endpos);
int udev_rules_parse_file(UdevRules *rules, const char *filename, bool extra_checks, UdevRuleFile **ret);
unsigned udev_rule_file_get_issues(UdevRuleFile *rule_file);
UdevRules* udev_rules_new(ResolveNameTiming resolve_name_timing);
int udev_rules_load(UdevRules **ret_rules, ResolveNameTiming resolve_name_timing);
UdevRules *udev_rules_free(UdevRules *rules);
DEFINE_TRIVIAL_CLEANUP_FUNC(UdevRules*, udev_rules_free);
#define udev_rules_free_and_replace(a, b) free_and_replace_full(a, b, udev_rules_free)

bool udev_rules_should_reload(UdevRules *rules);
int udev_rules_apply_to_event(UdevRules *rules, UdevEvent *event);
int udev_rules_apply_static_dev_perms(UdevRules *rules);

ResolveNameTiming resolve_name_timing_from_string(const char *s) _pure_;
const char *resolve_name_timing_to_string(ResolveNameTiming i) _const_;
