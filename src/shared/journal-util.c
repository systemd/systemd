/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "acl-util.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "journal-internal.h"
#include "journal-util.h"
#include "log.h"
#include "strv.h"
#include "user-util.h"

static int access_check_var_log_journal(sd_journal *j, bool want_other_users) {
        int r;

        assert(j);

        /* If we are root, we should have access, don't warn. */
        if (getuid() == 0)
                return 0;

        /* If we are in the 'systemd-journal' group, we should have
         * access too. */
        r = in_group("systemd-journal");
        if (r < 0)
                return log_error_errno(r, "Failed to check if we are in the 'systemd-journal' group: %m");
        if (r > 0)
                return 0;

#if HAVE_ACL
        _cleanup_strv_free_ char **g = NULL;
        const char* dir;

        if (laccess("/run/log/journal", F_OK) >= 0)
                dir = "/run/log/journal";
        else
                dir = "/var/log/journal";

        /* If we are in any of the groups listed in the journal ACLs,
         * then all is good, too. Let's enumerate all groups from the
         * default ACL of the directory, which generally should allow
         * access to most journal files too. */
        r = acl_search_groups(dir, &g);
        if (r < 0)
                return log_error_errno(r, "Failed to search journal ACL: %m");
        if (r > 0)
                return 0;

        /* Print a pretty list, if there were ACLs set. */
        if (!strv_isempty(g)) {
                _cleanup_free_ char *s = NULL;

                /* There are groups in the ACL, let's list them */
                r = strv_extend(&g, "systemd-journal");
                if (r < 0)
                        return log_oom();

                strv_sort(g);
                strv_uniq(g);

                s = strv_join(g, "', '");
                if (!s)
                        return log_oom();

                log_notice("Hint: You are currently not seeing messages from %s.\n"
                           "      Users in groups '%s' can see all messages.\n"
                           "      Pass -q to turn off this notice.",
                           want_other_users ? "other users and the system" : "the system",
                           s);
                return 1;
        }
#endif

        /* If no ACLs were found, print a short version of the message. */
        log_notice("Hint: You are currently not seeing messages from %s.\n"
                   "      Users in the 'systemd-journal' group can see all messages. Pass -q to\n"
                   "      turn off this notice.",
                   want_other_users ? "other users and the system" : "the system");

        return 1;
}

int journal_access_blocked(sd_journal *j) {
        return hashmap_contains(j->errors, INT_TO_PTR(-EACCES));
}

int journal_access_check_and_warn(sd_journal *j, bool quiet, bool want_other_users) {
        void *code;
        char *path;
        int r = 0;

        assert(j);

        if (hashmap_isempty(j->errors)) {
                if (ordered_hashmap_isempty(j->files) && !quiet)
                        log_notice("No journal files were found.");

                return 0;
        }

        if (journal_access_blocked(j)) {
                if (!quiet)
                        (void) access_check_var_log_journal(j, want_other_users);

                if (ordered_hashmap_isempty(j->files))
                        r = log_error_errno(EACCES, "No journal files were opened due to insufficient permissions.");
        }

        HASHMAP_FOREACH_KEY(path, code, j->errors) {
                int err;

                err = abs(PTR_TO_INT(code));

                switch (err) {
                case EACCES:
                        continue;

                case ENODATA:
                        log_warning_errno(err, "Journal file %s is truncated, ignoring file.", path);
                        break;

                case EPROTONOSUPPORT:
                        log_warning_errno(err, "Journal file %1$s uses an unsupported feature, ignoring file.\n"
                                               "Use SYSTEMD_LOG_LEVEL=debug journalctl --file=%1$s to see the details.",
                                               path);
                        break;

                case EBADMSG:
                        log_warning_errno(err, "Journal file %s corrupted, ignoring file.", path);
                        break;

                case ETOOMANYREFS:
                        log_warning_errno(err, "Too many journal files (limit is at %u) in scope, ignoring file '%s'.", JOURNAL_FILES_MAX, path);
                        break;

                default:
                        log_warning_errno(err, "An error was encountered while opening journal file or directory %s, ignoring file: %m", path);
                        break;
                }
        }

        return r;
}

int journal_open_machine(sd_journal **ret, const char *machine, int flags) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_close_ int machine_fd = -EBADF;
        int fd, r;

        assert(ret);
        assert(machine);

        if (geteuid() != 0)
                /* The file descriptor returned by OpenMachineRootDirectory() will be owned by users/groups of
                 * the container, thus we need root privileges to override them. */
                return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Using the --machine= switch requires root privileges.");

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to open system bus: %m");

        r = bus_call_method(bus, bus_machine_mgr, "OpenMachineRootDirectory", &error, &reply, "s", machine);
        if (r < 0)
                return log_error_errno(r, "Failed to open root directory of machine '%s': %s",
                                       machine, bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "h", &fd);
        if (r < 0)
                return bus_log_parse_error(r);

        machine_fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (machine_fd < 0)
                return log_error_errno(errno, "Failed to duplicate file descriptor: %m");

        r = sd_journal_open_directory_fd(&j, machine_fd, SD_JOURNAL_OS_ROOT | SD_JOURNAL_TAKE_DIRECTORY_FD | flags);
        if (r < 0)
                return log_error_errno(r, "Failed to open journal in machine '%s': %m", machine);

        TAKE_FD(machine_fd);
        *ret = TAKE_PTR(j);
        return 0;
}
