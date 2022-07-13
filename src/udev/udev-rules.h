/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "alloc-util.h"
#include "hashmap.h"
#include "time-util.h"
#include "udev-util.h"

typedef struct UdevRules UdevRules;
typedef struct UdevEvent UdevEvent;

typedef enum {
        ESCAPE_UNSET,
        ESCAPE_NONE,    /* OPTIONS="string_escape=none" */
        ESCAPE_REPLACE, /* OPTIONS="string_escape=replace" */
        _ESCAPE_TYPE_MAX,
        _ESCAPE_TYPE_INVALID = -EINVAL,
} UdevRuleEscapeType;

int udev_rules_parse_file(UdevRules *rules, const char *filename);
UdevRules* udev_rules_new(ResolveNameTiming resolve_name_timing);
int udev_rules_load(UdevRules **ret_rules, ResolveNameTiming resolve_name_timing);
UdevRules *udev_rules_free(UdevRules *rules);
DEFINE_TRIVIAL_CLEANUP_FUNC(UdevRules*, udev_rules_free);
#define udev_rules_free_and_replace(a, b) free_and_replace_full(a, b, udev_rules_free)

bool udev_rules_should_reload(UdevRules *rules);
int udev_rules_apply_to_event(UdevRules *rules, UdevEvent *event,
                              usec_t timeout_usec,
                              int timeout_signal,
                              Hashmap *properties_list);
int udev_rules_apply_static_dev_perms(UdevRules *rules);
