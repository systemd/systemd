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
        [META_COMM]              = "COREDUMP_COMM=",
        [META_UID]               = "COREDUMP_UID=",
        [META_GID]               = "COREDUMP_GID=",
        [META_EXE]               = "COREDUMP_EXE=",
        [META_UNIT]              = "COREDUMP_UNIT=",
        [META_NS_PID]            = "COREDUMP_NS_PID=",
        [META_HOSTNAME]          = "COREDUMP_HOSTNAME=",
};

static void load_context_meta(const struct iovec_wrapper *iovw, Context *context) {
        unsigned int i, j;

        for (j = 0; j < iovw->count; j++) {
                struct iovec *iovec = iovw->iovec + j;

                /* Note that these strings are NUL terminated, because we made sure that a
                 * trailing NUL byte is in the buffer, though not included in the iov_len
                 * count (see process_socket() and gather_pid_metadata_*()) */
                assert(((char*) iovec->iov_base)[iovec->iov_len] == 0);

                for (i = 0; i < _META_MAX; i++) {
                        char *p;

                        p = startswith(iovec->iov_base, meta_field_names[i]);
                        if (p) {
                                context->meta[i] = p;
                                break;
                        }
                }
        }
}

int coredump_context_save(const struct iovec_wrapper *iovw, Context *context, bool pids_only) {
        int i, r;

        assert(context);
        assert(iovw);

        /* The context does not allocate any memory on its own */

        load_context_meta(iovw, context);

        /* Did we already parse the pid related metadata ? */
        if (!context->pid) {
                /* Check for the presence of pid and nspid */
                if (!context->meta[META_PID])
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "PID of crashing process is missing !");

                r = parse_pid(context->meta[META_PID], &context->pid);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse PID \"%s\": %m", context->meta[META_PID]);

                context->is_pid1 = context->pid == 1;

                /* If nspid is missing or invalid, we ignore it and still
                 * process the dump in the host */
                if (context->meta[META_NS_PID]) {
                        r = parse_pid(context->meta[META_NS_PID], &context->ns_pid);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse NS PID \"%s\", ignoring: %m",
                                                  context->meta[META_NS_PID]);
                        else
                                context->exec_in_namespace = context->ns_pid != context->pid;
                }
        }

        if (pids_only)
                return 0;

        /* Make sure the mandatory metadata have been gathered somehow */
        for (i = 0; i < _META_MANDATORY_MAX; i++)
                if (!context->meta[i])
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Field '%s' has not been provided.",
                                               meta_field_names[i]);

        /* Cache uid and gid */
        r = parse_uid(context->meta[META_UID], &context->uid);
        if (r < 0)
                return log_error_errno(r, "Failed to parse UID: %m");

        r = parse_gid(context->meta[META_GID], &context->gid);
        if (r < 0)
                return log_error_errno(r, "Failed to parse GID: %m");

        if (!context->is_pid1 && context->meta[META_UNIT]) {
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
