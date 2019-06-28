/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

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
        _ESCAPE_TYPE_INVALID = -1
} UdevRuleEscapeType;

int udev_rules_new(UdevRules **ret_rules, ResolveNameTiming resolve_name_timing);
UdevRules *udev_rules_free(UdevRules *rules);
DEFINE_TRIVIAL_CLEANUP_FUNC(UdevRules*, udev_rules_free);

bool udev_rules_check_timestamp(UdevRules *rules);
int udev_rules_apply_to_event(UdevRules *rules, UdevEvent *event,
                              usec_t timeout_usec,
                              Hashmap *properties_list);
int udev_rules_apply_static_dev_perms(UdevRules *rules);
