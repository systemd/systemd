/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "os-util.h"

typedef enum TargetClass {
        /* These should try to match ImageClass from src/basic/os-util.h */
        TARGET_MACHINE  = IMAGE_MACHINE,
        TARGET_PORTABLE = IMAGE_PORTABLE,
        TARGET_SYSEXT   = IMAGE_SYSEXT,
        TARGET_CONFEXT  = IMAGE_CONFEXT,
        _TARGET_CLASS_IS_IMAGE_CLASS_MAX,

        /* sysupdate-specific classes */
        TARGET_HOST = _TARGET_CLASS_IS_IMAGE_CLASS_MAX,
        TARGET_COMPONENT,

        _TARGET_CLASS_MAX,
        _TARGET_CLASS_INVALID = -EINVAL,
} TargetClass;

/* Let's ensure when the number of classes is updated things are updated here too */
assert_cc((int) _IMAGE_CLASS_MAX == (int) _TARGET_CLASS_IS_IMAGE_CLASS_MAX);

DECLARE_STRING_TABLE_LOOKUP(target_class, TargetClass);

typedef struct TargetIdentifier {
        TargetClass class;
        char *name;
} TargetIdentifier;

void target_identifier_done(TargetIdentifier *t);
