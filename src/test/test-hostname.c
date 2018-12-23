/* SPDX-License-Identifier: LGPL-2.1+ */

#include "hostname-setup.h"
#include "util.h"

int main(int argc, char *argv[]) {
        int r;

        r = hostname_setup();
        if (r < 0)
                log_error_errno(r, "hostname: %m");

        return 0;
}
