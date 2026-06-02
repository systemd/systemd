/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "macro.h"
#include "string-table.h"
#include "sysupdate-target.h"

static const char* const target_class_table[_TARGET_CLASS_MAX] = {
        [TARGET_MACHINE]   = "machine",
        [TARGET_PORTABLE]  = "portable",
        [TARGET_SYSEXT]    = "sysext",
        [TARGET_CONFEXT]   = "confext",
        [TARGET_COMPONENT] = "component",
        [TARGET_HOST]      = "host",
};

DEFINE_STRING_TABLE_LOOKUP(target_class, TargetClass);

int target_identifier_new(TargetClass class, const char *name, TargetIdentifier **ret) {
        _cleanup_(target_identifier_freep) TargetIdentifier *t = NULL;

        assert(name);
        assert(ret);

        t = new(TargetIdentifier, 1);
        if (!t)
                return -ENOMEM;

        *t = (TargetIdentifier) {
                .class = class,
                .name = strdup(name),
        };

        if (!t->name)
                return -ENOMEM;

        *ret = TAKE_PTR(t);
        return 0;
}

void target_identifier_done(TargetIdentifier *t) {
        assert(t);

        t->class = _TARGET_CLASS_INVALID;
        t->name = mfree(t->name);
}

TargetIdentifier *target_identifier_free(TargetIdentifier *t) {
        if (!t)
                return NULL;

        target_identifier_done(t);
        return mfree(t);
}
