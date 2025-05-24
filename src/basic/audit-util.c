/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "audit-util.h"
#include "fileio.h"
#include "parse-util.h"
#include "pidref.h"
#include "process-util.h"
#include "stat-util.h"
#include "user-util.h"
#include "virt.h"

static int audit_read_field(const PidRef *pid, const char *field, char **ret) {
        int r;

        assert(field);
        assert(ret);

        if (!pidref_is_set(pid))
                return -ESRCH;

        /* Auditing is currently not virtualized for containers. Let's hence not use the audit session ID or
         * login UID for now, it will be leaked in from the host */
        if (detect_container() > 0)
                return -ENODATA;

        const char *p = procfs_file_alloca(pid->pid, field);

        _cleanup_free_ char *s = NULL;
        bool enoent = false;
        r = read_full_virtual_file(p, &s, /* ret_size= */ NULL);
        if (r == -ENOENT) {
                if (proc_mounted() == 0)
                        return -ENOSYS;
                enoent = true;
        } else if (r < 0)
                return r;

        r = pidref_verify(pid);
        if (r < 0)
                return r;

        if (enoent) /* We got ENOENT, but /proc/ was mounted and the PID still valid? In that case it appears
                     * auditing is not supported by the kernel. */
                return -ENODATA;

        delete_trailing_chars(s, NEWLINE);

        *ret = TAKE_PTR(s);
        return 0;
}

int audit_session_from_pid(const PidRef *pid, uint32_t *ret_id) {
        _cleanup_free_ char *s = NULL;
        int r;

        r = audit_read_field(pid, "sessionid", &s);
        if (r < 0)
                return r;

        uint32_t u;
        r = safe_atou32(s, &u);
        if (r < 0)
                return r;

        if (!audit_session_is_valid(u))
                return -ENODATA;

        if (ret_id)
                *ret_id = u;

        return 0;
}

int audit_loginuid_from_pid(const PidRef *pid, uid_t *ret_uid) {
        _cleanup_free_ char *s = NULL;
        int r;

        r = audit_read_field(pid, "loginuid", &s);
        if (r < 0)
                return r;

        if (streq(s, "4294967295")) /* loginuid as 4294967295 means not part of any session. */
                return -ENODATA;

        return parse_uid(s, ret_uid);
}
