#include "coredump.h"
#include "parse-util.h"
#include "special.h"
#include "string-util.h"
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
};

int coredump_save_context(Context *context, const struct iovec_wrapper *iovw) {
        unsigned n, i, count = 0;
        const char *unit;
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

        unit = context->meta[META_UNIT];
        context->is_pid1 = streq(context->meta[META_PID], "1") || streq_ptr(unit, SPECIAL_INIT_SCOPE);
        context->is_journald = streq_ptr(unit, SPECIAL_JOURNALD_SERVICE);

        return 0;
}
