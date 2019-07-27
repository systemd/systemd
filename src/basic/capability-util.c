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
#include "cap-list.h"
#include "fileio.h"
#include "log.h"
#include "macro.h"
#include "missing_prctl.h"
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

                        if (p > 63) /* Safety for the future: if one day the kernel learns more than 64 caps,
                                     * then we are in trouble (since we, as much userspace and kernel space
                                     * store capability masks in uint64_t types). Let's hence protect
                                     * ourselves against that and always cap at 63 for now. */
                                p = 63;

                        saved = p;
                        valid = true;
                        return p;
                }
        }

        /* fall back to syscall-probing for pre linux-3.2 */
        p = MIN((unsigned long) CAP_LAST_CAP, 63U);

        if (prctl(PR_CAPBSET_READ, p) < 0) {

                /* Hmm, look downwards, until we find one that works */
                for (p--; p > 0; p --)
                        if (prctl(PR_CAPBSET_READ, p) >= 0)
                                break;

        } else {

                /* Hmm, look upwards, until we find one that doesn't work */
                for (; p < 63; p++)
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

        for (i = 0; i <= cap_last_cap(); i++) {

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
        _cleanup_cap_free_ cap_t caps = NULL;
        unsigned long i;
        int r;

        /* Add the capabilities to the ambient set. */

        if (also_inherit) {
                caps = cap_get_proc();
                if (!caps)
                        return -errno;

                r = capability_update_inherited_set(caps, set);
                if (r < 0)
                        return -errno;

                if (cap_set_proc(caps) < 0)
                        return -errno;
        }

        for (i = 0; i <= cap_last_cap(); i++) {

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

        k = sscanf(p, "%" PRIu32 " %" PRIu32, &lo, &hi);
        if (k != 2)
                return -EIO;

        current = (uint64_t) lo | ((uint64_t) hi << 32);
        after = current & keep;

        if (current == after)
                return 0;

        lo = after & UINT32_C(0xFFFFFFFF);
        hi = (after >> 32) & UINT32_C(0xFFFFFFFF);

        return write_string_filef(fn, 0, "%" PRIu32 " %" PRIu32, lo, hi);
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
        int r;

        /* Unfortunately we cannot leave privilege dropping to PID 1 here, since we want to run as user but
         * want to keep some capabilities. Since file capabilities have been introduced this cannot be done
         * across exec() anymore, unless our binary has the capability configured in the file system, which
         * we want to avoid. */

        if (setresgid(gid, gid, gid) < 0)
                return log_error_errno(errno, "Failed to change group ID: %m");

        r = maybe_setgroups(0, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to drop auxiliary groups list: %m");

        /* Ensure we keep the permitted caps across the setresuid(). Note that we do this even if we actually
         * don't want to keep any capabilities, since we want to be able to drop them from the bounding set
         * too, and we can only do that if we have capabilities. */
        if (prctl(PR_SET_KEEPCAPS, 1) < 0)
                return log_error_errno(errno, "Failed to enable keep capabilities flag: %m");

        if (setresuid(uid, uid, uid) < 0)
                return log_error_errno(errno, "Failed to change user ID: %m");

        if (prctl(PR_SET_KEEPCAPS, 0) < 0)
                return log_error_errno(errno, "Failed to disable keep capabilities flag: %m");

        /* Drop all caps from the bounding set (as well as the inheritable/permitted/effective sets), except
         * the ones we want to keep */
        r = capability_bounding_set_drop(keep_capabilities, true);
        if (r < 0)
                return log_error_errno(r, "Failed to drop capabilities: %m");

        /* Now upgrade the permitted caps we still kept to effective caps */
        if (keep_capabilities != 0) {
                cap_value_t bits[u64log2(keep_capabilities) + 1];
                _cleanup_cap_free_ cap_t d = NULL;
                unsigned i, j = 0;

                d = cap_init();
                if (!d)
                        return log_oom();

                for (i = 0; i < ELEMENTSOF(bits); i++)
                        if (keep_capabilities & (1ULL << i))
                                bits[j++] = i;

                /* use enough bits */
                assert(i == 64 || (keep_capabilities >> i) == 0);
                /* don't use too many bits */
                assert(keep_capabilities & (UINT64_C(1) << (i - 1)));

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

bool capability_quintet_mangle(CapabilityQuintet *q) {
        unsigned long i;
        uint64_t combined, drop = 0;
        bool ambient_supported;

        assert(q);

        combined = q->effective | q->bounding | q->inheritable | q->permitted;

        ambient_supported = q->ambient != (uint64_t) -1;
        if (ambient_supported)
                combined |= q->ambient;

        for (i = 0; i <= cap_last_cap(); i++) {
                unsigned long bit = UINT64_C(1) << i;
                if (!FLAGS_SET(combined, bit))
                        continue;

                if (prctl(PR_CAPBSET_READ, i) > 0)
                        continue;

                drop |= bit;

                log_debug("Not in the current bounding set: %s", capability_to_name(i));
        }

        q->effective &= ~drop;
        q->bounding &= ~drop;
        q->inheritable &= ~drop;
        q->permitted &= ~drop;

        if (ambient_supported)
                q->ambient &= ~drop;

        return drop != 0; /* Let the caller know we changed something */
}

int capability_quintet_enforce(const CapabilityQuintet *q) {
        _cleanup_cap_free_ cap_t c = NULL, modified = NULL;
        int r;

        if (q->ambient != (uint64_t) -1) {
                unsigned long i;
                bool changed = false;

                c = cap_get_proc();
                if (!c)
                        return -errno;

                /* In order to raise the ambient caps set we first need to raise the matching inheritable + permitted
                 * cap */
                for (i = 0; i <= cap_last_cap(); i++) {
                        uint64_t m = UINT64_C(1) << i;
                        cap_value_t cv = (cap_value_t) i;
                        cap_flag_value_t old_value_inheritable, old_value_permitted;

                        if ((q->ambient & m) == 0)
                                continue;

                        if (cap_get_flag(c, cv, CAP_INHERITABLE, &old_value_inheritable) < 0)
                                return -errno;
                        if (cap_get_flag(c, cv, CAP_PERMITTED, &old_value_permitted) < 0)
                                return -errno;

                        if (old_value_inheritable == CAP_SET && old_value_permitted == CAP_SET)
                                continue;

                        if (cap_set_flag(c, CAP_INHERITABLE, 1, &cv, CAP_SET) < 0)
                                return -errno;
                        if (cap_set_flag(c, CAP_PERMITTED, 1, &cv, CAP_SET) < 0)
                                return -errno;

                        changed = true;
                }

                if (changed)
                        if (cap_set_proc(c) < 0)
                                return -errno;

                r = capability_ambient_set_apply(q->ambient, false);
                if (r < 0)
                        return r;
        }

        if (q->inheritable != (uint64_t) -1 || q->permitted != (uint64_t) -1 || q->effective != (uint64_t) -1) {
                bool changed = false;
                unsigned long i;

                if (!c) {
                        c = cap_get_proc();
                        if (!c)
                                return -errno;
                }

                for (i = 0; i <= cap_last_cap(); i++) {
                        uint64_t m = UINT64_C(1) << i;
                        cap_value_t cv = (cap_value_t) i;

                        if (q->inheritable != (uint64_t) -1) {
                                cap_flag_value_t old_value, new_value;

                                if (cap_get_flag(c, cv, CAP_INHERITABLE, &old_value) < 0) {
                                        if (errno == EINVAL) /* If the kernel knows more caps than this
                                                              * version of libcap, then this will return
                                                              * EINVAL. In that case, simply ignore it,
                                                              * pretend it doesn't exist. */
                                                continue;

                                        return -errno;
                                }

                                new_value = (q->inheritable & m) ? CAP_SET : CAP_CLEAR;

                                if (old_value != new_value) {
                                        changed = true;

                                        if (cap_set_flag(c, CAP_INHERITABLE, 1, &cv, new_value) < 0)
                                                return -errno;
                                }
                        }

                        if (q->permitted != (uint64_t) -1) {
                                cap_flag_value_t old_value, new_value;

                                if (cap_get_flag(c, cv, CAP_PERMITTED, &old_value) < 0) {
                                        if (errno == EINVAL)
                                                continue;

                                        return -errno;
                                }

                                new_value = (q->permitted & m) ? CAP_SET : CAP_CLEAR;

                                if (old_value != new_value) {
                                        changed = true;

                                        if (cap_set_flag(c, CAP_PERMITTED, 1, &cv, new_value) < 0)
                                                return -errno;
                                }
                        }

                        if (q->effective != (uint64_t) -1) {
                                cap_flag_value_t old_value, new_value;

                                if (cap_get_flag(c, cv, CAP_EFFECTIVE, &old_value) < 0) {
                                        if (errno == EINVAL)
                                                continue;

                                        return -errno;
                                }

                                new_value = (q->effective & m) ? CAP_SET : CAP_CLEAR;

                                if (old_value != new_value) {
                                        changed = true;

                                        if (cap_set_flag(c, CAP_EFFECTIVE, 1, &cv, new_value) < 0)
                                                return -errno;
                                }
                        }
                }

                if (changed) {
                        /* In order to change the bounding caps, we need to keep CAP_SETPCAP for a bit
                         * longer. Let's add it to our list hence for now. */
                        if (q->bounding != (uint64_t) -1) {
                                cap_value_t cv = CAP_SETPCAP;

                                modified = cap_dup(c);
                                if (!modified)
                                        return -ENOMEM;

                                if (cap_set_flag(modified, CAP_PERMITTED, 1, &cv, CAP_SET) < 0)
                                        return -errno;
                                if (cap_set_flag(modified, CAP_EFFECTIVE, 1, &cv, CAP_SET) < 0)
                                        return -errno;

                                if (cap_compare(modified, c) == 0) {
                                        /* No change? then drop this nonsense again */
                                        cap_free(modified);
                                        modified = NULL;
                                }
                        }

                        /* Now, let's enforce the caps for the first time. Note that this is where we acquire
                         * caps in any of the sets we currently don't have. We have to do this before
                         * dropping the bounding caps below, since at that point we can never acquire new
                         * caps in inherited/permitted/effective anymore, but only lose them. */
                        if (cap_set_proc(modified ?: c) < 0)
                                return -errno;
                }
        }

        if (q->bounding != (uint64_t) -1) {
                r = capability_bounding_set_drop(q->bounding, false);
                if (r < 0)
                        return r;
        }

        /* If needed, let's now set the caps again, this time in the final version, which differs from what
         * we have already set only in the CAP_SETPCAP bit, which we needed for dropping the bounding
         * bits. This call only undoes bits and doesn't acquire any which means the bounding caps don't
         * matter. */
        if (modified)
                if (cap_set_proc(c) < 0)
                        return -errno;

        return 0;
}
