/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdatomic.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bitfield.h"
#include "capability-list.h"
#include "capability-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "parse-util.h"
#include "pidref.h"
#include "process-util.h"
#include "stat-util.h"
#include "user-util.h"

int capability_get(CapabilityQuintet *ret) {
        assert(ret);

        struct __user_cap_header_struct hdr = {
                .version = _LINUX_CAPABILITY_VERSION_3,
                .pid = getpid_cached(),
        };

        assert_cc(_LINUX_CAPABILITY_U32S_3 == 2);
        struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
        if (syscall(SYS_capget, &hdr, data) < 0)
                return -errno;

        *ret = (CapabilityQuintet) {
                .effective = (uint64_t) data[0].effective | ((uint64_t) data[1].effective << 32),
                .bounding = UINT64_MAX,
                .inheritable = (uint64_t) data[0].inheritable | ((uint64_t) data[1].inheritable << 32),
                .permitted = (uint64_t) data[0].permitted | ((uint64_t) data[1].permitted << 32),
                .ambient = UINT64_MAX,
        };
        return 0;
}

static int capability_apply(const CapabilityQuintet *q) {
        assert(q);

        struct __user_cap_header_struct hdr = {
                .version = _LINUX_CAPABILITY_VERSION_3,
                .pid = getpid_cached(),
        };

        struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3] = {
                {
                        .effective = (uint32_t) (q->effective & UINT32_MAX),
                        .inheritable = (uint32_t) (q->inheritable & UINT32_MAX),
                        .permitted = (uint32_t) (q->permitted & UINT32_MAX),
                },
                {
                        .effective = (uint32_t) (q->effective >> 32),
                        .inheritable = (uint32_t) (q->inheritable >> 32),
                        .permitted = (uint32_t) (q->permitted >> 32),
                },
        };
        return RET_NERRNO(syscall(SYS_capset, &hdr, data));
}

unsigned cap_last_cap(void) {
        static atomic_int saved = INT_MAX;
        int r, c;

        c = saved;
        if (c != INT_MAX)
                return c;

        /* Available since linux-3.2 */
        _cleanup_free_ char *content = NULL;
        r = read_one_line_file("/proc/sys/kernel/cap_last_cap", &content);
        if (r < 0)
                log_debug_errno(r, "Failed to read /proc/sys/kernel/cap_last_cap, ignoring: %m");
        else {
                r = safe_atoi(content, &c);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse /proc/sys/kernel/cap_last_cap, ignoring: %m");
                else {
                        if (c > CAP_LIMIT) /* Safety for the future: if one day the kernel learns more than
                                            * 64 caps, then we are in trouble (since we, as much userspace
                                            * and kernel space store capability masks in uint64_t types). We
                                            * also want to use UINT64_MAX as marker for "unset". Hence let's
                                            * hence protect ourselves against that and always cap at 62 for
                                            * now. */
                                c = CAP_LIMIT;

                        saved = c;
                        return c;
                }
        }

        /* Fall back to syscall-probing for pre linux-3.2, or where /proc/ is not mounted */
        unsigned long p = (unsigned long) MIN(CAP_LAST_CAP, CAP_LIMIT);

        if (prctl(PR_CAPBSET_READ, p) < 0) {

                /* Hmm, look downwards, until we find one that works */
                for (p--; p > 0; p--)
                        if (prctl(PR_CAPBSET_READ, p) >= 0)
                                break;

        } else {

                /* Hmm, look upwards, until we find one that doesn't work */
                for (; p < CAP_LIMIT; p++)
                        if (prctl(PR_CAPBSET_READ, p+1) < 0)
                                break;
        }

        c = (int) p;
        saved = c;
        return c;
}

int have_effective_cap(unsigned cap) {
        CapabilityQuintet q;
        int r;

        assert(cap <= CAP_LIMIT);

        r = capability_get(&q);
        if (r < 0)
                return r;

        return BIT_SET(q.effective, cap);
}

int have_inheritable_cap(unsigned cap) {
        CapabilityQuintet q;
        int r;

        assert(cap <= CAP_LIMIT);

        r = capability_get(&q);
        if (r < 0)
                return r;

        return BIT_SET(q.inheritable, cap);
}

int capability_ambient_set_apply(uint64_t set, bool also_inherit) {
        int r;

        /* Remove capabilities requested in ambient set, but not in the bounding set */
        for (unsigned i = 0; i <= cap_last_cap(); i++) {
                if (!BIT_SET(set, i))
                        continue;

                if (prctl(PR_CAPBSET_READ, (unsigned long) i) != 1) {
                        log_debug("Ambient capability %s requested but missing from bounding set, suppressing automatically.",
                                  capability_to_name(i));
                        CLEAR_BIT(set, i);
                }
        }

        /* Add the capabilities to the ambient set (an possibly also the inheritable set) */

        if (also_inherit) {
                CapabilityQuintet q;

                r = capability_get(&q);
                if (r < 0)
                        return r;

                q.inheritable = set;

                r = capability_apply(&q);
                if (r < 0)
                        return r;
        }

        for (unsigned i = 0; i <= cap_last_cap(); i++)
                if (BIT_SET(set, i)) {
                        /* Add the capability to the ambient set. */
                        if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, i, 0, 0) < 0)
                                return -errno;
                } else {
                        /* Drop the capability so we don't inherit capabilities we didn't ask for. */
                        r = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, i, 0, 0);
                        if (r < 0)
                                return -errno;
                        if (r > 0)
                                if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, i, 0, 0) < 0)
                                        return -errno;
                }

        return 0;
}

int capability_gain_cap_setpcap(void) {
        CapabilityQuintet q;
        int r;

        r = capability_get(&q);
        if (r < 0)
                return r;

        if (BIT_SET(q.effective, CAP_SETPCAP))
                return 1; /* We already have capability. */

        SET_BIT(q.effective, CAP_SETPCAP);

        r = capability_apply(&q);
        if (r < 0) {
                /* If we didn't manage to acquire the CAP_SETPCAP bit, we continue anyway, after all this
                 * just means we'll fail later, when we actually intend to drop some capabilities or try to
                 * set securebits. */
                log_debug_errno(r, "Can't acquire effective CAP_SETPCAP bit, ignoring: %m");
                return 0;
        }

        return 1; /* acquired */
}

int capability_bounding_set_drop(uint64_t keep, bool right_now) {
        int k, r;

        /* If we are run as PID 1 we will lack CAP_SETPCAP by default in the effective set (yes, the kernel
         * drops that when executing init!), so get it back temporarily so that we can call PR_CAPBSET_DROP. */

        CapabilityQuintet q;
        r = capability_get(&q);
        if (r < 0)
                return r;
        CapabilityQuintet saved = q;

        r = capability_gain_cap_setpcap();
        if (r < 0)
                return r;

        for (unsigned i = 0; i <= cap_last_cap(); i++) {
                if (BIT_SET(keep, i))
                        continue;

                /* Drop it from the bounding set */
                if (prctl(PR_CAPBSET_DROP, i) < 0) {
                        r = -errno;

                        /* If dropping the capability failed, let's see if we didn't have it in the first
                         * place. If so, continue anyway, as dropping a capability we didn't have in the
                         * first place doesn't really matter anyway. */
                        if (prctl(PR_CAPBSET_READ, i) != 0)
                                goto finish;
                }

                /* Also drop it from the inheritable set, so that anything we exec() loses the capability for
                 * good. */
                CLEAR_BIT(q.inheritable, i);

                /* If we shall apply this right now drop it also from our own capability sets. */
                if (right_now) {
                        CLEAR_BIT(q.effective, i);
                        CLEAR_BIT(q.permitted, i);
                }
        }

        r = 0;

finish:
        k = capability_apply(&q);
        if (k < 0)
                /* If there are no actual changes anyway then let's ignore this error. */
                if (!capability_quintet_equal(&q, &saved))
                        return k;

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

        lo = after & UINT32_MAX;
        hi = (after >> 32) & UINT32_MAX;

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

        r = maybe_setgroups(/* size= */ 0, /* list= */ NULL);
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
        r = capability_bounding_set_drop(keep_capabilities, /* right_now= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to drop capabilities: %m");

        /* Now upgrade the permitted caps we still kept to effective caps */
        if (keep_capabilities != 0) {
                CapabilityQuintet q = {
                        .effective = keep_capabilities,
                        .permitted = keep_capabilities,
                };

                r = capability_apply(&q);
                if (r < 0)
                        return log_error_errno(r, "Failed to increase capabilities: %m");
        }

        return 0;
}

static int change_capability(unsigned cap, bool b) {
        CapabilityQuintet q;
        int r;

        assert(cap <= CAP_LIMIT);

        r = capability_get(&q);
        if (r < 0)
                return r;

        if (b) {
                SET_BIT(q.effective, cap);
                SET_BIT(q.permitted, cap);
                SET_BIT(q.inheritable, cap);
        } else {
                CLEAR_BIT(q.effective, cap);
                CLEAR_BIT(q.permitted, cap);
                CLEAR_BIT(q.inheritable, cap);
        }

        return capability_apply(&q);
}

int drop_capability(unsigned cap) {
        return change_capability(cap, false);
}

int keep_capability(unsigned cap) {
        return change_capability(cap, true);
}

bool capability_quintet_mangle(CapabilityQuintet *q) {
        uint64_t combined, drop = 0;

        assert(q);

        combined = q->effective | q->bounding | q->inheritable | q->permitted | q->ambient;

        for (unsigned i = 0; i <= cap_last_cap(); i++) {
                if (!BIT_SET(combined, i))
                        continue;

                if (prctl(PR_CAPBSET_READ, (unsigned long) i) > 0)
                        continue;

                SET_BIT(drop, i);

                log_debug("Dropping capability not in the current bounding set: %s", capability_to_name(i));
        }

        q->effective &= ~drop;
        q->bounding &= ~drop;
        q->inheritable &= ~drop;
        q->permitted &= ~drop;
        q->ambient &= ~drop;

        return drop != 0; /* Let the caller know we changed something */
}

int capability_quintet_enforce(const CapabilityQuintet *q) {
        CapabilityQuintet c;
        bool modified = false;
        int r;

        if (q->ambient != CAP_MASK_UNSET ||
            q->inheritable != CAP_MASK_UNSET ||
            q->permitted != CAP_MASK_UNSET ||
            q->effective != CAP_MASK_UNSET) {
                r = capability_get(&c);
                if (r < 0)
                        return r;
        }

        if (q->ambient != CAP_MASK_UNSET) {
                /* In order to raise the ambient caps set we first need to raise the matching
                 * inheritable + permitted cap */
                if (!FLAGS_SET(c.permitted, q->ambient) ||
                    !FLAGS_SET(c.inheritable, q->ambient)) {

                        c.permitted |= q->ambient;
                        c.inheritable |= q->ambient;

                        r = capability_apply(&c);
                        if (r < 0)
                                return r;
                }

                r = capability_ambient_set_apply(q->ambient, /* also_inherit= */ false);
                if (r < 0)
                        return r;
        }

        if (q->inheritable != CAP_MASK_UNSET || q->permitted != CAP_MASK_UNSET || q->effective != CAP_MASK_UNSET) {
                if (!FLAGS_SET(c.effective, q->effective) ||
                    !FLAGS_SET(c.permitted, q->permitted) ||
                    !FLAGS_SET(c.inheritable, q->inheritable)) {

                        c.effective |= q->effective;
                        c.permitted |= q->permitted;
                        c.inheritable |= q->inheritable;

                        /* Now, let's enforce the caps for the first time. Note that this is where we acquire
                         * caps in any of the sets we currently don't have. We have to do this before
                         * dropping the bounding caps below, since at that point we can never acquire new
                         * caps in inherited/permitted/effective anymore, but only lose them.
                         *
                         * In order to change the bounding caps, we need to keep CAP_SETPCAP for a bit
                         * longer. Let's add it to our list hence for now. */
                        if (q->bounding != CAP_MASK_UNSET &&
                            (!BIT_SET(c.effective, CAP_SETPCAP) || !BIT_SET(c.permitted, CAP_SETPCAP))) {
                                CapabilityQuintet tmp = c;

                                SET_BIT(c.effective, CAP_SETPCAP);
                                SET_BIT(c.permitted, CAP_SETPCAP);

                                modified = true;

                                r = capability_apply(&tmp);
                        } else
                                r = capability_apply(&c);
                        if (r < 0)
                                return r;
                }
        }

        if (q->bounding != CAP_MASK_UNSET) {
                r = capability_bounding_set_drop(q->bounding, /* right_now= */ false);
                if (r < 0)
                        return r;
        }

        /* If needed, let's now set the caps again, this time in the final version, which differs from what
         * we have already set only in the CAP_SETPCAP bit, which we needed for dropping the bounding
         * bits. This call only undoes bits and doesn't acquire any which means the bounding caps don't
         * matter. */
        if (modified) {
                r = capability_apply(&c);
                if (r < 0)
                        return r;
        }

        return 0;
}

int capability_get_ambient(uint64_t *ret) {
        uint64_t a = 0;
        int r;

        assert(ret);

        for (unsigned i = 0; i <= cap_last_cap(); i++) {
                r = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, i, 0, 0);
                if (r < 0)
                        return -errno;
                if (r > 0)
                        SET_BIT(a, i);
        }

        *ret = a;
        return 1;
}

int pidref_get_capability(const PidRef *pidref, CapabilityQuintet *ret) {
        int r;

        if (!pidref_is_set(pidref))
                return -ESRCH;
        if (pidref_is_remote(pidref))
                return -EREMOTE;

        const char *path = procfs_file_alloca(pidref->pid, "status");
        _cleanup_fclose_ FILE *f = fopen(path, "re");
        if (!f) {
                if (errno == ENOENT && proc_mounted() == 0)
                        return -ENOSYS;

                return -errno;
        }

        CapabilityQuintet q = CAPABILITY_QUINTET_NULL;
        for (;;) {
                _cleanup_free_ char *line = NULL;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                static const struct {
                        const char *field;
                        size_t offset;
                } fields[] = {
                        { "CapBnd:", offsetof(CapabilityQuintet, bounding)    },
                        { "CapInh:", offsetof(CapabilityQuintet, inheritable) },
                        { "CapPrm:", offsetof(CapabilityQuintet, permitted)   },
                        { "CapEff:", offsetof(CapabilityQuintet, effective)   },
                        { "CapAmb:", offsetof(CapabilityQuintet, ambient)     },
                };

                FOREACH_ELEMENT(i, fields) {

                        const char *p = first_word(line, i->field);
                        if (!p)
                                continue;

                        uint64_t *v = (uint64_t*) ((uint8_t*) &q + i->offset);

                        if (*v != CAP_MASK_UNSET)
                                return -EBADMSG;

                        r = safe_atoux64(p, v);
                        if (r < 0)
                                return r;

                        if (*v == CAP_MASK_UNSET)
                                return -EBADMSG;
                }
        }

        if (!capability_quintet_is_fully_set(&q))
                return -EBADMSG;

        r = pidref_verify(pidref);
        if (r < 0)
                return r;

        if (ret)
                *ret = q;

        return 0;
}
