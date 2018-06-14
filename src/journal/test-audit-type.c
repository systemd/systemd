/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdio.h>
#include <linux/audit.h>

#include "audit-type.h"

static void print_audit_label(int i) {
        const char *name;

        name = audit_type_name_alloca(i);
        /* This is a separate function only because of alloca */
        printf("%i → %s → %s\n", i, audit_type_to_string(i), name);
}

static void test_audit_type(void) {
        int i;

        for (i = 0; i <= AUDIT_KERNEL; i++)
                print_audit_label(i);
}

int main(int argc, char **argv) {
        test_audit_type();
}
