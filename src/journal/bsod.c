#include <stdio.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "log.h"
#include "main-func.h"
#include "sd-id128.h"
#include "sd-journal.h"
#include "terminal-util.h"

static char* first_emerg_boot_message(void) {
        sd_journal *j;
        const void *d;
        size_t l;
        char boot_id_string[33];
        sd_id128_t boot_id;
        char boot_id_filter[42];
        int r;
        _cleanup_free_ char *message = NULL;

        r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
        if (r < 0) {
                log_warning_errno(r, "Failed to open journal: %m");
                return NULL;
        }

        r = sd_id128_get_boot(&boot_id);
        if (r < 0) {
                log_warning_errno(r, "Failed to get boot ID, ignoring : %m");
                goto clean_journal;
        }
        sd_id128_to_string(boot_id, boot_id_string);

        snprintf(boot_id_filter, sizeof(boot_id_filter), "_BOOT_ID=%s", boot_id_string);
        r = sd_journal_add_match(j, boot_id_filter, 0);
        if (r < 0) {
                log_warning_errno(r, "Failed to add boot ID filter: %m");
                goto clean_journal;
        }

        r = sd_journal_add_match(j, "_UID=0", 0);
        if (r < 0) {
                log_warning_errno(r, "Failed to add User ID filter: %m");
                goto clean_journal;
        }

        r = sd_journal_add_match(j, "PRIORITY=5", 0);
        if (r < 0) {
                log_warning_errno(r, "Failed to add Emergency filter: %m");
                goto clean_journal;
        }

        SD_JOURNAL_FOREACH(j) {
                r = sd_journal_get_data(j, "MESSAGE", &d, &l);
                if (r < 0) {
                        log_warning_errno(r, "Failed to read journal message: %m");
                        continue;
                }
                message = strndup((char *) d, l);
                break;
        }

clean_journal:
        sd_journal_close(j);
        return message;
}

static int run(int argc, char *argv[]) {
        _cleanup_close_ int fd = -EBADF;
        char * message = first_emerg_boot_message();

        fd = open_terminal("/dev/console", O_WRONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                log_warning_errno(fd, "Failed to open console, ignoring: %m");
        else
                dprintf(fd, ANSI_HIGHLIGHT_RED "%s" ANSI_NORMAL "\n", message);
        return 0;
}

DEFINE_MAIN_FUNCTION(run);
