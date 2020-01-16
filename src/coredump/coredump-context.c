#include "coredump.h"
#include "parse-util.h"
#include "special.h"
#include "string-util.h"
#include "unit-name.h"
#include "user-util.h"

static const char * const meta_field_names[_META_MAX] = {
        [META_PID]               = "COREDUMP_PID=",
        [META_SIGNAL]            = "COREDUMP_SIGNAL=",
        [META_TIMESTAMP]         = "COREDUMP_TIMESTAMP=",
        [META_RLIMIT]            = "COREDUMP_RLIMIT=",
        [META_HOSTNAME]          = "COREDUMP_HOSTNAME=",
        [META_COMM]              = "COREDUMP_COMM=",
        [META_UID]               = "COREDUMP_UID=",
        [META_GID]               = "COREDUMP_GID=",
        [META_EXE]               = "COREDUMP_EXE=",
        [META_UNIT]              = "COREDUMP_UNIT=",
        [META_NS_PID]            = "COREDUMP_NS_PID=",
};

int coredump_save_context(Context *context, const struct iovec_wrapper *iovw) {
        unsigned n, i, count = 0;
        int r;

        assert(context);
        assert(iovw);

        /* The context does not allocate any memory on its own */

        for (n = 0; n < iovw->count; n++) {
                struct iovec *iovec = iovw->iovec + n;

                /* Note that these strings are NUL terminated, because we made sure that a
                 * trailing NUL byte is in the buffer, though not included in the iov_len
                 * count (see process_socket() and gather_pid_metadata_*()) */
                assert(((char*) iovec->iov_base)[iovec->iov_len] == 0);

                for (i = 0; i < _META_MAX; i++) {
                        char *p;

                        p = startswith(iovec->iov_base, meta_field_names[i]);
                        if (p) {
                                context->meta[i] = p;
                                count++;
                                break;
                        }
                }
        }

        /* Check for the presence of pid and nspid */
        if (!context->meta[META_PID])
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Failed to find the PID of crashing process");

        r = parse_pid(context->meta[META_PID], &context->pid);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PID \"%s\": %m", context->meta[META_PID]);

        /* If nspid is missing or invalid, we ignore it and still process the dump from the host */
        if (context->meta[META_NS_PID]) {
                r = parse_pid(context->meta[META_NS_PID], &context->ns_pid);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse NS PID \"%s\", ignoring: %m",
                                          context->meta[META_NS_PID]);
                else
                        context->exec_in_namespace = context->ns_pid != context->pid;
        }

        /* Cache uid and gid */
        if (context->meta[META_UID]) {
                r = parse_uid(context->meta[META_UID], &context->uid);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse UID: %m");
        }

        if (context->meta[META_GID]) {
                r = parse_gid(context->meta[META_GID], &context->gid);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse GID: %m");
        }

        if (streq(context->meta[META_PID], "1"))
                context->is_pid1 = true;

        else if (context->meta[META_UNIT]) {
                const char *unit = context->meta[META_UNIT];

                if (streq_ptr(unit, SPECIAL_INIT_SCOPE))
                        context->is_pid1 = true;

                else if (streq_ptr(unit, SPECIAL_JOURNALD_SERVICE))
                        context->is_journald = true;

                else {
                        _cleanup_free_ char *t = NULL;
                        (void) unit_name_template(unit, &t);
                        context->is_coredumpd = streq_ptr(t, SPECIAL_COREDUMPD_SERVICE);
                }
        }

        return 0;
}
