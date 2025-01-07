/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bitfield.h"
#include "cap-list.h"
#include "capability-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "logarithm.h"
#include "macro.h"
#include "missing_prctl.h"
#include "missing_threads.h"
#include "parse-util.h"
#include "pidref.h"
#include "stat-util.h"
#include "user-util.h"

int have_effective_cap(int value) {
        _cleanup_cap_free_ cap_t cap = NULL;
        cap_flag_value_t fv = CAP_CLEAR; /* To avoid false-positive use-of-uninitialized-value error reported
                                          * by fuzzers. */

        cap = cap_get_proc();
        if (!cap)
                return -errno;

        if (cap_get_flag(cap, value, CAP_EFFECTIVE, &fv) < 0)
                return -errno;

        return fv == CAP_SET;
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

int capability_update_inherited_set(cap_t caps, uint64_t set) {
        /* Add capabilities in the set to the inherited caps, drops capabilities not in the set.
         * Do not apply them yet. */

        for (unsigned i = 0; i <= cap_last_cap(); i++) {
                cap_flag_value_t flag = set & (UINT64_C(1) << i) ? CAP_SET : CAP_CLEAR;
                cap_value_t v;

                v = (cap_value_t) i;

                if (cap_set_flag(caps, CAP_INHERITABLE, 1, &v, flag) < 0)
                        return -errno;
        }

        return 0;
}

int capability_ambient_set_apply(uint64_t set, bool also_inherit) {
        _cleanup_cap_free_ cap_t caps = NULL;
        int r;

        /* Remove capabilities requested in ambient set, but not in the bounding set */
        BIT_FOREACH(i, set) {
                assert((unsigned) i <= cap_last_cap());

                if (prctl(PR_CAPBSET_READ, (unsigned long) i) != 1) {
                        log_debug("Ambient capability %s requested but missing from bounding set, suppressing automatically.",
                                  capability_to_name(i));
                        CLEAR_BIT(set, i);
                }
        }

        /* Add the capabilities to the ambient set (an possibly also the inheritable set) */

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

        for (unsigned i = 0; i <= cap_last_cap(); i++) {
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
        }

        return 0;
}

int capability_gain_cap_setpcap(cap_t *ret_before_caps) {
        _cleanup_cap_free_ cap_t caps = NULL;
        cap_flag_value_t fv;
        caps = cap_get_proc();
        if (!caps)
                return -errno;

        if (cap_get_flag(caps, CAP_SETPCAP, CAP_EFFECTIVE, &fv) < 0)
                return -errno;

        if (fv != CAP_SET) {
                _cleanup_cap_free_ cap_t temp_cap = NULL;
                static const cap_value_t v = CAP_SETPCAP;

                temp_cap = cap_dup(caps);
                if (!temp_cap)
                        return -errno;

                if (cap_set_flag(temp_cap, CAP_EFFECTIVE, 1, &v, CAP_SET) < 0)
                        return -errno;

                if (cap_set_proc(temp_cap) < 0)
                        log_debug_errno(errno, "Can't acquire effective CAP_SETPCAP bit, ignoring: %m");

                /* If we didn't manage to acquire the CAP_SETPCAP bit, we continue anyway, after all this just means
                 * we'll fail later, when we actually intend to drop some capabilities or try to set securebits. */
        }
        if (ret_before_caps)
                /* Return the capabilities as they have been before setting CAP_SETPCAP */
                *ret_before_caps = TAKE_PTR(caps);

        return 0;
}

int capability_bounding_set_drop(uint64_t keep, bool right_now) {
        _cleanup_cap_free_ cap_t before_cap = NULL, after_cap = NULL;
        int r;

        /* If we are run as PID 1 we will lack CAP_SETPCAP by default
         * in the effective set (yes, the kernel drops that when
         * executing init!), so get it back temporarily so that we can
         * call PR_CAPBSET_DROP. */

        r = capability_gain_cap_setpcap(&before_cap);
        if (r < 0)
                return r;

        after_cap = cap_dup(before_cap);
        if (!after_cap)
                return -errno;

        for (unsigned i = 0; i <= cap_last_cap(); i++) {
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
                cap_value_t bits[log2u64(keep_capabilities) + 1];
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

static int change_capability(cap_value_t cv, cap_flag_value_t flag) {
        _cleanup_cap_free_ cap_t tmp_cap = NULL;

        tmp_cap = cap_get_proc();
        if (!tmp_cap)
                return -errno;

        if ((cap_set_flag(tmp_cap, CAP_INHERITABLE, 1, &cv, flag) < 0) ||
            (cap_set_flag(tmp_cap, CAP_PERMITTED, 1, &cv, flag) < 0) ||
            (cap_set_flag(tmp_cap, CAP_EFFECTIVE, 1, &cv, flag) < 0))
                return -errno;

        if (cap_set_proc(tmp_cap) < 0)
                return -errno;

        return 0;
}

int drop_capability(cap_value_t cv) {
        return change_capability(cv, CAP_CLEAR);
}

int keep_capability(cap_value_t cv) {
        return change_capability(cv, CAP_SET);
}

bool capability_quintet_mangle(CapabilityQuintet *q) {
        uint64_t combined, drop = 0;

        assert(q);

        combined = q->effective | q->bounding | q->inheritable | q->permitted | q->ambient;

        BIT_FOREACH(i, combined) {
                assert((unsigned) i <= cap_last_cap());

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
        _cleanup_cap_free_ cap_t c = NULL, modified = NULL;
        int r;

        if (q->ambient != CAP_MASK_UNSET) {
                bool changed = false;

                c = cap_get_proc();
                if (!c)
                        return -errno;

                /* In order to raise the ambient caps set we first need to raise the matching
                 * inheritable + permitted cap */
                for (unsigned i = 0; i <= cap_last_cap(); i++) {
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

        if (q->inheritable != CAP_MASK_UNSET || q->permitted != CAP_MASK_UNSET || q->effective != CAP_MASK_UNSET) {
                bool changed = false;

                if (!c) {
                        c = cap_get_proc();
                        if (!c)
                                return -errno;
                }

                for (unsigned i = 0; i <= cap_last_cap(); i++) {
                        uint64_t m = UINT64_C(1) << i;
                        cap_value_t cv = (cap_value_t) i;

                        if (q->inheritable != CAP_MASK_UNSET) {
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

                        if (q->permitted != CAP_MASK_UNSET) {
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

                        if (q->effective != CAP_MASK_UNSET) {
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
                        if (q->bounding != CAP_MASK_UNSET) {
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

        if (q->bounding != CAP_MASK_UNSET) {
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
