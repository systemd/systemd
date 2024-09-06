/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink.h"

#include "errno-util.h"
#include "journal-internal.h"
#include "journal-vacuum.h"
#include "journalctl.h"
#include "journalctl-util.h"
#include "journalctl-varlink.h"
#include "varlink-util.h"

static int varlink_connect_journal(sd_varlink **ret) {
        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *vl = NULL;
        const char *address;
        int r;

        assert(ret);

        address = arg_namespace ?
                  strjoina("/run/systemd/journal.", arg_namespace, "/io.systemd.journal") :
                  "/run/systemd/journal/io.systemd.journal";

        r = sd_varlink_connect_address(&vl, address);
        if (r < 0)
                return r;

        (void) sd_varlink_set_description(vl, "journal");
        (void) sd_varlink_set_relative_timeout(vl, USEC_INFINITY);

        *ret = TAKE_PTR(vl);
        return 0;
}

int action_flush_to_var(void) {
        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *link = NULL;
        int r;

        assert(arg_action == ACTION_FLUSH);

        if (arg_machine || arg_namespace)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "--flush is not supported in conjunction with %s.",
                                       arg_machine ? "--machine=" : "--namespace=");

        if (access("/run/systemd/journal/flushed", F_OK) >= 0)
                return 0; /* Already flushed, no need to contact journald */
        if (errno != ENOENT)
                return log_error_errno(errno, "Unable to check for existence of /run/systemd/journal/flushed: %m");

        r = varlink_connect_journal(&link);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to Varlink socket: %m");

        return varlink_call_and_log(link, "io.systemd.Journal.FlushToVar", /* parameters= */ NULL, /* ret_parameters= */ NULL);
}

int action_relinquish_var(void) {
        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *link = NULL;
        int r;

        assert(arg_action == ACTION_RELINQUISH_VAR);

        if (arg_machine || arg_namespace)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "--(smart-)relinquish-var is not supported in conjunction with %s.",
                                       arg_machine ? "--machine=" : "--namespace=");

        r = varlink_connect_journal(&link);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to Varlink socket: %m");

        return varlink_call_and_log(link, "io.systemd.Journal.RelinquishVar", /* parameters= */ NULL, /* ret_parameters= */ NULL);
}

int action_rotate(void) {
        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *link = NULL;
        int r;

        assert(IN_SET(arg_action, ACTION_ROTATE, ACTION_ROTATE_AND_VACUUM));

        if (arg_machine)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "--rotate is not supported in conjunction with --machine=.");

        r = varlink_connect_journal(&link);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to Varlink socket: %m");

        return varlink_call_and_log(link, "io.systemd.Journal.Rotate", /* parameters= */ NULL, /* ret_parameters= */ NULL);
}

int action_vacuum(void) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        Directory *d;
        int r, ret = 0;

        assert(IN_SET(arg_action, ACTION_VACUUM, ACTION_ROTATE_AND_VACUUM));

        r = acquire_journal(&j);
        if (r < 0)
                return r;

        HASHMAP_FOREACH(d, j->directories_by_path) {
                r = journal_directory_vacuum(d->path, arg_vacuum_size, arg_vacuum_n_files, arg_vacuum_time, NULL, !arg_quiet);
                if (r < 0)
                        RET_GATHER(ret, log_error_errno(r, "Failed to vacuum %s: %m", d->path));
        }

        return ret;
}

int action_rotate_and_vacuum(void) {
        int r;

        assert(arg_action == ACTION_ROTATE_AND_VACUUM);

        r = action_rotate();
        if (r < 0)
                return r;

        return action_vacuum();
}

int action_sync(void) {
        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *link = NULL;
        int r;

        assert(arg_action == ACTION_SYNC);

        if (arg_machine)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "--sync is not supported in conjunction with --machine=.");

        r = varlink_connect_journal(&link);
        if (ERRNO_IS_NEG_DISCONNECT(r) && arg_namespace)
                /* If the namespaced sd-journald instance was shut down due to inactivity, it should already
                 * be synchronized */
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to connect to Varlink socket: %m");

        return varlink_call_and_log(link, "io.systemd.Journal.Synchronize", /* parameters= */ NULL, /* ret_parameters= */ NULL);
}
