/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "id128-print.h"
#include "log.h"
#include "pretty-print.h"
#include "terminal-util.h"

int id128_pretty_print_sample(const char *name, sd_id128_t id) {
       _cleanup_free_ char *man_link = NULL, *mod_link = NULL;
        const char *on, *off;
        unsigned i;

        on = ansi_highlight();
        off = ansi_normal();

        if (terminal_urlify("man:systemd-id128(1)", "systemd-id128(1)", &man_link) < 0)
                return log_oom();

        if (terminal_urlify("https://docs.python.org/3/library/uuid.html", "uuid", &mod_link) < 0)
                return log_oom();

        printf("As string:\n"
               "%s" SD_ID128_FORMAT_STR "%s\n\n"
               "As UUID:\n"
               "%s" SD_ID128_UUID_FORMAT_STR "%s\n\n"
               "As %s macro:\n"
               "%s#define %s SD_ID128_MAKE(",
               on, SD_ID128_FORMAT_VAL(id), off,
               on, SD_ID128_FORMAT_VAL(id), off,
               man_link,
               on, name);
        for (i = 0; i < 16; i++)
                printf("%02x%s", id.bytes[i], i != 15 ? "," : "");
        printf(")%s\n\n", off);

        printf("As Python constant:\n"
               ">>> import %s\n"
               ">>> %s%s = uuid.UUID('" SD_ID128_FORMAT_STR "')%s\n",
               mod_link,
               on, name, SD_ID128_FORMAT_VAL(id), off);

        return 0;
}


int id128_pretty_print(sd_id128_t id, Id128PrettyPrintMode mode) {
        assert(mode >= 0);
        assert(mode < _ID128_PRETTY_PRINT_MODE_MAX);

        if (mode == ID128_PRINT_ID128) {
                printf(SD_ID128_FORMAT_STR "\n",
                       SD_ID128_FORMAT_VAL(id));
                return 0;
        } else if (mode == ID128_PRINT_UUID) {
                printf(SD_ID128_UUID_FORMAT_STR "\n",
                       SD_ID128_FORMAT_VAL(id));
                return 0;
        } else
                return id128_pretty_print_sample("XYZ", id);
}

int id128_print_new(Id128PrettyPrintMode mode) {
        sd_id128_t id;
        int r;

        r = sd_id128_randomize(&id);
        if (r < 0)
                return log_error_errno(r, "Failed to generate ID: %m");

        return id128_pretty_print(id, mode);
}
