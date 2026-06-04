/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-table.h"
#include "sysupdate.h"
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

void target_identifier_done(TargetIdentifier *t) {
        assert(t);

        t->class = _TARGET_CLASS_INVALID;
        t->name = mfree(t->name);
}
