/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdio.h>

#include "selinux-overhaul-permissions.h"

int main(int argc, char **argv) {

        size_t i;
        int ret = 0;

        for (i = 0; i < sizeof mac_selinux_overhaul_pidone_permissions / sizeof *mac_selinux_overhaul_pidone_permissions; ++i) {
                if (mac_selinux_overhaul_pidone_permissions[i] == NULL || strcmp(mac_selinux_overhaul_pidone_permissions[i], "") == 0) {
                        fprintf(stderr, "lookup table mac_selinux_overhaul_pidone_permissions is not initialized at position %zu\n", i);
                        ret = 1;
                }
        }

        for (i = 0; i < sizeof mac_selinux_overhaul_unit_permissions / sizeof *mac_selinux_overhaul_unit_permissions; ++i) {
                if (mac_selinux_overhaul_unit_permissions[i] == NULL || strcmp(mac_selinux_overhaul_unit_permissions[i], "") == 0) {
                        fprintf(stderr, "lookup table mac_selinux_overhaul_unit_permissions is not initialized at position %zu\n", i);
                        ret = 1;
                }
        }

        return ret;
}
