/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "string-util.h"
#include "varlink-systemd.h"
#include "version.h"

int varlink_set_info_systemd(sd_varlink_server *server) {
        _cleanup_free_ char *product = NULL;

        product = strjoin("systemd (", program_invocation_short_name, ")");
        if (!product)
                return -ENOMEM;

        return sd_varlink_server_set_info(
                        server,
                        "The systemd Project",
                        product,
                        PROJECT_VERSION_FULL " (" GIT_VERSION ")",
                        "https://systemd.io/");
}
