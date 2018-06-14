/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "alloc-util.h"
#include "capability-util.h"
#include "fileio.h"
#include "log.h"
#include "macro.h"
#include "parse-util.h"
#include "user-util.h"
#include "util.h"

int have_effective_cap(int value) {
        _cleanup_cap_free_ cap_t cap;
        cap_flag_value_t fv;

        cap = cap_get_proc();
        if (!cap)
                return -errno;

        if (cap_get_flag(cap, value, CAP_EFFECTIVE, &fv) < 0)
                return -errno;
        else
                return fv == CAP_SET;
}

unsigned long cap_last_cap(void) {
        static thread_local unsigned long saved;
        static thread_local bool valid = false;
        _cleanup_free_ char *content = NULL;
        unsigned long p = 0;
        int r;

        if (valid)
                return saved;

        /* available since linux-3.2 */
        r = read_one_line_file("/proc/sys/kernel/cap_last_cap", &content);
        if (r >= 0) {
                r = safe_atolu(content, &p);
                if (r >= 0) {
                        saved = p;
                        valid = true;
                        return p;
                }
        }

        /* fall back to syscall-probing for pre linux-3.2 */
        p = (unsigned long) CAP_LAST_CAP;

        if (prctl(PR_CAPBSET_READ, p) < 0) {

                /* Hmm, look downwards, until we find one that
                 * works */
                for (p--; p > 0; p --)
                        if (prctl(PR_CAPBSET_READ, p) >= 0)
                                break;

        } else {

                /* Hmm, look upwards, until we find one that doesn't
                 * work */
                for (;; p++)
                        if (prctl(PR_CAPBSET_READ, p+1) < 0)
                                break;
        }

        saved = p;
        valid = true;

        return p;
}

int capability_update_inherited_set(cap_t caps, uint64_t set) {
        unsigned long i;

        /* Add capabilities in the set to the inherited caps. Do not apply
         * them yet. */

        for (i = 0; i < cap_last_cap(); i++) {

                if (set & (UINT64_C(1) << i)) {
                        cap_value_t v;

                        v = (cap_value_t) i;

                        /* Make the capability inheritable. */
                        if (cap_set_flag(caps, CAP_INHERITABLE, 1, &v, CAP_SET) < 0)
                                return -errno;
                }
        }

        return 0;
}

int capability_ambient_set_apply(uint64_t set, bool also_inherit) {
        unsigned long i;
        _cleanup_cap_free_ cap_t caps = NULL;

        /* Add the capabilities to the ambient set. */

        if (also_inherit) {
                int r;
                caps = cap_get_proc();
                if (!caps)
                        return -errno;

                r = capability_update_inherited_set(caps, set);
                if (r < 0)
                        return -errno;

                if (cap_set_proc(caps) < 0)
                        return -errno;
        }

        for (i = 0; i < cap_last_cap(); i++) {

                if (set & (UINT64_C(1) << i)) {

                        /* Add the capability to the ambient set. */
                        if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, i, 0, 0) < 0)
                                return -errno;
                }
        }

        return 0;
}

int capability_bounding_set_drop(uint64_t keep, bool right_now) {
        _cleanup_cap_free_ cap_t before_cap = NULL, after_cap = NULL;
        cap_flag_value_t fv;
        unsigned long i;
        int r;

        /* If we are run as PID 1 we will lack CAP_SETPCAP by default
         * in the effective set (yes, the kernel drops that when
         * executing init!), so get it back temporarily so that we can
         * call PR_CAPBSET_DROP. */

        before_cap = cap_get_proc();
        if (!before_cap)
                return -errno;

        if (cap_get_flag(before_cap, CAP_SETPCAP, CAP_EFFECTIVE, &fv) < 0)
                return -errno;

        if (fv != CAP_SET) {
                _cleanup_cap_free_ cap_t temp_cap = NULL;
                static const cap_value_t v = CAP_SETPCAP;

                temp_cap = cap_dup(before_cap);
                if (!temp_cap)
                        return -errno;

                if (cap_set_flag(temp_cap, CAP_EFFECTIVE, 1, &v, CAP_SET) < 0)
                        return -errno;

                if (cap_set_proc(temp_cap) < 0)
                        log_debug_errno(errno, "Can't acquire effective CAP_SETPCAP bit, ignoring: %m");

                /* If we didn't manage to acquire the CAP_SETPCAP bit, we continue anyway, after all this just means
                 * we'll fail later, when we actually intend to drop some capabilities. */
        }

        after_cap = cap_dup(before_cap);
        if (!after_cap)
                return -errno;

        for (i = 0; i <= cap_last_cap(); i++) {
                cap_value_t v;

                if ((keep & (UINT64_C(1) << i)))
                        continue;

                /* Drop it from the bounding set */
                if (prctl(PR_CAPBSET_DROP, i) < 0) {
                        r = -errno;

                        /* If dropping the capability failed, let's see if we didn't have it in the first place. If so,
                         * continue anyway, as dropping a capability we didn't have in the first place doesn't really
                         * matter anyway. */
                        if (prctl(PR_CAPBSET_READ, i) != 0)
                                goto finish;
                }
                v = (cap_value_t) i;

                /* Also drop it from the inheritable set, so
                 * that anything we exec() loses the
                 * capability for good. */
                if (cap_set_flag(after_cap, CAP_INHERITABLE, 1, &v, CAP_CLEAR) < 0) {
                        r = -errno;
                        goto finish;
                }

                /* If we shall apply this right now drop it
                 * also from our own capability sets. */
                if (right_now) {
                        if (cap_set_flag(after_cap, CAP_PERMITTED, 1, &v, CAP_CLEAR) < 0 ||
                            cap_set_flag(after_cap, CAP_EFFECTIVE, 1, &v, CAP_CLEAR) < 0) {
                                r = -errno;
                                goto finish;
                        }
                }
        }

        r = 0;

finish:
        if (cap_set_proc(after_cap) < 0) {
                /* If there are no actual changes anyway then let's ignore this error. */
                if (cap_compare(before_cap, after_cap) != 0)
                        r = -errno;
        }

        return r;
}

static int drop_from_file(const char *fn, uint64_t keep) {
        _cleanup_free_ char *p = NULL;
        uint64_t current, after;
        uint32_t hi, lo;
        int r, k;

        r = read_one_line_file(fn, &p);
        if (r < 0)
                return r;

        assert_cc(sizeof(hi) == sizeof(unsigned));
        assert_cc(sizeof(lo) == sizeof(unsigned));

        k = sscanf(p, "%u %u", &lo, &hi);
        if (k != 2)
                return -EIO;

        current = (uint64_t) lo | ((uint64_t) hi << 32ULL);
        after = current & keep;

        if (current == after)
                return 0;

        lo = (unsigned) (after & 0xFFFFFFFFULL);
        hi = (unsigned) ((after >> 32ULL) & 0xFFFFFFFFULL);

        return write_string_filef(fn, WRITE_STRING_FILE_CREATE, "%u %u", lo, hi);
}

int capability_bounding_set_drop_usermode(uint64_t keep) {
        int r;

        r = drop_from_file("/proc/sys/kernel/usermodehelper/inheritable", keep);
        if (r < 0)
                return r;

        r = drop_from_file("/proc/sys/kernel/usermodehelper/bset", keep);
        if (r < 0)
                return r;

        return r;
}

int drop_privileges(uid_t uid, gid_t gid, uint64_t keep_capabilities) {
        _cleanup_cap_free_ cap_t d = NULL;
        unsigned i, j = 0;
        int r;

        /* Unfortunately we cannot leave privilege dropping to PID 1
         * here, since we want to run as user but want to keep some
         * capabilities. Since file capabilities have been introduced
         * this cannot be done across exec() anymore, unless our
         * binary has the capability configured in the file system,
         * which we want to avoid. */

        if (setresgid(gid, gid, gid) < 0)
                return log_error_errno(errno, "Failed to change group ID: %m");

        r = maybe_setgroups(0, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to drop auxiliary groups list: %m");

        /* Ensure we keep the permitted caps across the setresuid() */
        if (prctl(PR_SET_KEEPCAPS, 1) < 0)
                return log_error_errno(errno, "Failed to enable keep capabilities flag: %m");

        if (setresuid(uid, uid, uid) < 0)
                return log_error_errno(errno, "Failed to change user ID: %m");

        if (prctl(PR_SET_KEEPCAPS, 0) < 0)
                return log_error_errno(errno, "Failed to disable keep capabilities flag: %m");

        /* Drop all caps from the bounding set, except the ones we want */
        r = capability_bounding_set_drop(keep_capabilities, true);
        if (r < 0)
                return log_error_errno(r, "Failed to drop capabilities: %m");

        /* Now upgrade the permitted caps we still kept to effective caps */
        d = cap_init();
        if (!d)
                return log_oom();

        if (keep_capabilities) {
                cap_value_t bits[u64log2(keep_capabilities) + 1];

                for (i = 0; i < ELEMENTSOF(bits); i++)
                        if (keep_capabilities & (1ULL << i))
                                bits[j++] = i;

                /* use enough bits */
                assert(i == 64 || (keep_capabilities >> i) == 0);
                /* don't use too many bits */
                assert(keep_capabilities & (1ULL << (i - 1)));

                if (cap_set_flag(d, CAP_EFFECTIVE, j, bits, CAP_SET) < 0 ||
                    cap_set_flag(d, CAP_PERMITTED, j, bits, CAP_SET) < 0)
                        return log_error_errno(errno, "Failed to enable capabilities bits: %m");

                if (cap_set_proc(d) < 0)
                        return log_error_errno(errno, "Failed to increase capabilities: %m");
        }

        return 0;
}

int drop_capability(cap_value_t cv) {
        _cleanup_cap_free_ cap_t tmp_cap = NULL;

        tmp_cap = cap_get_proc();
        if (!tmp_cap)
                return -errno;

        if ((cap_set_flag(tmp_cap, CAP_INHERITABLE, 1, &cv, CAP_CLEAR) < 0) ||
            (cap_set_flag(tmp_cap, CAP_PERMITTED, 1, &cv, CAP_CLEAR) < 0) ||
            (cap_set_flag(tmp_cap, CAP_EFFECTIVE, 1, &cv, CAP_CLEAR) < 0))
                return -errno;

        if (cap_set_proc(tmp_cap) < 0)
                return -errno;

        return 0;
}

bool ambient_capabilities_supported(void) {
        static int cache = -1;

        if (cache >= 0)
                return cache;

        /* If PR_CAP_AMBIENT returns something valid, or an unexpected error code we assume that ambient caps are
         * available. */

        cache = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_KILL, 0, 0) >= 0 ||
                !IN_SET(errno, EINVAL, EOPNOTSUPP, ENOSYS);

        return cache;
}
