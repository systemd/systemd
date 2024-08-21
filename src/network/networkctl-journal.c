/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "journal-internal.h"
#include "logs-show.h"
#include "networkctl.h"
#include "networkctl-journal.h"
#include "terminal-util.h"

static OutputFlags get_output_flags(void) {
        return
                arg_all * OUTPUT_SHOW_ALL |
                (arg_full || !on_tty() || pager_have()) * OUTPUT_FULL_WIDTH |
                colors_enabled() * OUTPUT_COLOR;
}

int show_logs(int ifindex, const char *ifname) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        int r;

        assert(ifindex == 0 || ifname);

        if (arg_lines == 0)
                return 0;

        r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY | SD_JOURNAL_ASSUME_IMMUTABLE);
        if (r < 0)
                return log_error_errno(r, "Failed to open journal: %m");

        r = add_match_this_boot(j, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to add boot matches: %m");

        if (ifindex > 0) {
                (void) (
                       (r = journal_add_matchf(j, "_KERNEL_DEVICE=n%i", ifindex)) || /* kernel */
                       (r = sd_journal_add_disjunction(j)) ||
                       (r = journal_add_match_pair(j, "INTERFACE", ifname)) || /* networkd */
                       (r = sd_journal_add_disjunction(j)) ||
                       (r = journal_add_match_pair(j, "DEVICE", ifname)) /* udevd */
                );
                if (r < 0)
                        return log_error_errno(r, "Failed to add link matches: %m");
        } else {
                r = add_matches_for_unit(j, "systemd-networkd.service");
                if (r < 0)
                        return log_error_errno(r, "Failed to add unit matches: %m");

                r = add_matches_for_unit(j, "systemd-networkd-wait-online.service");
                if (r < 0)
                        return log_error_errno(r, "Failed to add unit matches: %m");
        }

        return show_journal(
                        stdout,
                        j,
                        OUTPUT_SHORT,
                        0,
                        0,
                        arg_lines,
                        get_output_flags() | OUTPUT_BEGIN_NEWLINE,
                        NULL);
}
