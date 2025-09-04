/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/capability.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "audit-util.h"
#include "bus-creds.h"
#include "bus-label.h"
#include "bus-message.h"
#include "capability-util.h"
#include "cgroup-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "hexdecoct.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "pidref.h"
#include "process-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "user-util.h"

enum {
        CAP_OFFSET_INHERITABLE = 0,
        CAP_OFFSET_PERMITTED = 1,
        CAP_OFFSET_EFFECTIVE = 2,
        CAP_OFFSET_BOUNDING = 3
};

void bus_creds_done(sd_bus_creds *c) {
        assert(c);

        /* For internal bus cred structures that are allocated by
         * something else */

        free(c->session);
        free(c->unit);
        free(c->user_unit);
        free(c->slice);
        free(c->user_slice);
        free(c->unescaped_description);
        free(c->supplementary_gids);
        free(c->tty);

        free(c->well_known_names); /* note that this is an strv, but
                                    * we only free the array, not the
                                    * strings the array points to. The
                                    * full strv we only free if
                                    * c->allocated is set, see
                                    * below. */

        strv_free(c->cmdline_array);

        safe_close(c->pidfd);
}

_public_ sd_bus_creds* sd_bus_creds_ref(sd_bus_creds *c) {

        if (!c)
                return NULL;

        if (c->allocated) {
                assert(c->n_ref > 0);
                c->n_ref++;
        } else {
                sd_bus_message *m;

                /* If this is an embedded creds structure, then
                 * forward ref counting to the message */
                m = container_of(c, sd_bus_message, creds);
                sd_bus_message_ref(m);
        }

        return c;
}

_public_ sd_bus_creds* sd_bus_creds_unref(sd_bus_creds *c) {

        if (!c)
                return NULL;

        if (c->allocated) {
                assert(c->n_ref > 0);
                c->n_ref--;

                if (c->n_ref == 0) {
                        free(c->comm);
                        free(c->tid_comm);
                        free(c->exe);
                        free(c->cmdline);
                        free(c->cgroup);
                        free(c->capability);
                        free(c->label);
                        free(c->unique_name);
                        free(c->cgroup_root);
                        free(c->description);

                        c->supplementary_gids = mfree(c->supplementary_gids);

                        c->well_known_names = strv_free(c->well_known_names);

                        bus_creds_done(c);

                        free(c);
                }
        } else {
                sd_bus_message *m;

                m = container_of(c, sd_bus_message, creds);
                sd_bus_message_unref(m);
        }

        return NULL;
}

_public_ uint64_t sd_bus_creds_get_mask(const sd_bus_creds *c) {
        assert_return(c, 0);

        return c->mask;
}

_public_ uint64_t sd_bus_creds_get_augmented_mask(const sd_bus_creds *c) {
        assert_return(c, 0);

        return c->augmented;
}

sd_bus_creds* bus_creds_new(void) {
        sd_bus_creds *c;

        c = new(sd_bus_creds, 1);
        if (!c)
                return NULL;

        *c = (sd_bus_creds) {
                .allocated = true,
                .n_ref = 1,
                SD_BUS_CREDS_INIT_FIELDS,
        };

        return c;
}

static int bus_creds_new_from_pidref(sd_bus_creds **ret, PidRef *pidref, uint64_t mask) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *c = NULL;
        int r;

        assert_return(mask <= _SD_BUS_CREDS_ALL, -EOPNOTSUPP);
        assert_return(ret, -EINVAL);

        c = bus_creds_new();
        if (!c)
                return -ENOMEM;

        r = bus_creds_add_more(c, mask | SD_BUS_CREDS_AUGMENT, pidref, 0);
        if (r < 0)
                return r;

        r = pidref_verify(pidref);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(c);
        return 0;
}

_public_ int sd_bus_creds_new_from_pid(sd_bus_creds **ret, pid_t pid, uint64_t mask) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r;

        assert_return(pid >= 0, -EINVAL);
        assert_return(mask <= _SD_BUS_CREDS_ALL, -EOPNOTSUPP);
        assert_return(ret, -EINVAL);

        r = pidref_set_pid(&pidref, pid);
        if (r < 0)
                return r;

        return bus_creds_new_from_pidref(ret, &pidref, mask);
}

_public_ int sd_bus_creds_new_from_pidfd(sd_bus_creds **ret, int pidfd, uint64_t mask) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r;

        assert_return(mask <= _SD_BUS_CREDS_ALL, -EOPNOTSUPP);
        assert_return(ret, -EINVAL);
        assert_return(pidfd >= 0, -EBADF);

        r = pidref_set_pidfd(&pidref, pidfd);
        if (r < 0)
                return r;

        return bus_creds_new_from_pidref(ret, &pidref, mask);
}

_public_ int sd_bus_creds_get_uid(sd_bus_creds *c, uid_t *ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_UID))
                return -ENODATA;

        *ret = c->uid;
        return 0;
}

_public_ int sd_bus_creds_get_euid(sd_bus_creds *c, uid_t *ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_EUID))
                return -ENODATA;

        *ret = c->euid;
        return 0;
}

_public_ int sd_bus_creds_get_suid(sd_bus_creds *c, uid_t *ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_SUID))
                return -ENODATA;

        *ret = c->suid;
        return 0;
}

_public_ int sd_bus_creds_get_fsuid(sd_bus_creds *c, uid_t *ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_FSUID))
                return -ENODATA;

        *ret = c->fsuid;
        return 0;
}

_public_ int sd_bus_creds_get_gid(sd_bus_creds *c, gid_t *ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_GID))
                return -ENODATA;

        *ret = c->gid;
        return 0;
}

_public_ int sd_bus_creds_get_egid(sd_bus_creds *c, gid_t *ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_EGID))
                return -ENODATA;

        *ret = c->egid;
        return 0;
}

_public_ int sd_bus_creds_get_sgid(sd_bus_creds *c, gid_t *ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_SGID))
                return -ENODATA;

        *ret = c->sgid;
        return 0;
}

_public_ int sd_bus_creds_get_fsgid(sd_bus_creds *c, gid_t *ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_FSGID))
                return -ENODATA;

        *ret = c->fsgid;
        return 0;
}

_public_ int sd_bus_creds_get_supplementary_gids(sd_bus_creds *c, const gid_t **ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_SUPPLEMENTARY_GIDS))
                return -ENODATA;

        *ret = c->supplementary_gids;
        return (int) c->n_supplementary_gids;
}

_public_ int sd_bus_creds_get_pid(sd_bus_creds *c, pid_t *ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_PID))
                return -ENODATA;

        assert(c->pid > 0);
        *ret = c->pid;
        return 0;
}

_public_ int sd_bus_creds_get_pidfd_dup(sd_bus_creds *c, int *ret) {
        _cleanup_close_ int copy = -EBADF;

        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_PIDFD))
                return -ENODATA;

        copy = fcntl(c->pidfd, F_DUPFD_CLOEXEC, 3);
        if (copy < 0)
                return -errno;

        *ret = TAKE_FD(copy);
        return 0;
}

_public_ int sd_bus_creds_get_ppid(sd_bus_creds *c, pid_t *ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_PPID))
                return -ENODATA;

        /* PID 1 has no parent process. Let's distinguish the case of
         * not knowing and not having a parent process by the returned
         * error code. */
        if (c->ppid == 0)
                return -ENXIO;

        *ret = c->ppid;
        return 0;
}

_public_ int sd_bus_creds_get_tid(sd_bus_creds *c, pid_t *ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_TID))
                return -ENODATA;

        assert(c->tid > 0);
        *ret = c->tid;
        return 0;
}

_public_ int sd_bus_creds_get_selinux_context(sd_bus_creds *c, const char **ret) {
        assert_return(c, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_SELINUX_CONTEXT))
                return -ENODATA;

        assert(c->label);
        *ret = c->label;
        return 0;
}

_public_ int sd_bus_creds_get_comm(sd_bus_creds *c, const char **ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_COMM))
                return -ENODATA;

        assert(c->comm);
        *ret = c->comm;
        return 0;
}

_public_ int sd_bus_creds_get_tid_comm(sd_bus_creds *c, const char **ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_TID_COMM))
                return -ENODATA;

        assert(c->tid_comm);
        *ret = c->tid_comm;
        return 0;
}

_public_ int sd_bus_creds_get_exe(sd_bus_creds *c, const char **ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_EXE))
                return -ENODATA;

        if (!c->exe)
                return -ENXIO;

        *ret = c->exe;
        return 0;
}

_public_ int sd_bus_creds_get_cgroup(sd_bus_creds *c, const char **ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_CGROUP))
                return -ENODATA;

        assert(c->cgroup);
        *ret = c->cgroup;
        return 0;
}

_public_ int sd_bus_creds_get_unit(sd_bus_creds *c, const char **ret) {
        int r;

        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_UNIT))
                return -ENODATA;

        assert(c->cgroup);

        if (!c->unit) {
                const char *shifted;

                r = cg_shift_path(c->cgroup, c->cgroup_root, &shifted);
                if (r < 0)
                        return r;

                r = cg_path_get_unit(shifted, (char**) &c->unit);
                if (r < 0)
                        return r;
        }

        *ret = c->unit;
        return 0;
}

_public_ int sd_bus_creds_get_user_unit(sd_bus_creds *c, const char **ret) {
        int r;

        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_USER_UNIT))
                return -ENODATA;

        assert(c->cgroup);

        if (!c->user_unit) {
                const char *shifted;

                r = cg_shift_path(c->cgroup, c->cgroup_root, &shifted);
                if (r < 0)
                        return r;

                r = cg_path_get_user_unit(shifted, (char**) &c->user_unit);
                if (r < 0)
                        return r;
        }

        *ret = c->user_unit;
        return 0;
}

_public_ int sd_bus_creds_get_slice(sd_bus_creds *c, const char **ret) {
        int r;

        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_SLICE))
                return -ENODATA;

        assert(c->cgroup);

        if (!c->slice) {
                const char *shifted;

                r = cg_shift_path(c->cgroup, c->cgroup_root, &shifted);
                if (r < 0)
                        return r;

                r = cg_path_get_slice(shifted, (char**) &c->slice);
                if (r < 0)
                        return r;
        }

        *ret = c->slice;
        return 0;
}

_public_ int sd_bus_creds_get_user_slice(sd_bus_creds *c, const char **ret) {
        int r;

        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_USER_SLICE))
                return -ENODATA;

        assert(c->cgroup);

        if (!c->user_slice) {
                const char *shifted;

                r = cg_shift_path(c->cgroup, c->cgroup_root, &shifted);
                if (r < 0)
                        return r;

                r = cg_path_get_user_slice(shifted, (char**) &c->user_slice);
                if (r < 0)
                        return r;
        }

        *ret = c->user_slice;
        return 0;
}

_public_ int sd_bus_creds_get_session(sd_bus_creds *c, const char **ret) {
        int r;

        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_SESSION))
                return -ENODATA;

        assert(c->cgroup);

        if (!c->session) {
                const char *shifted;

                r = cg_shift_path(c->cgroup, c->cgroup_root, &shifted);
                if (r < 0)
                        return r;

                r = cg_path_get_session(shifted, (char**) &c->session);
                if (r < 0)
                        return r;
        }

        *ret = c->session;
        return 0;
}

_public_ int sd_bus_creds_get_owner_uid(sd_bus_creds *c, uid_t *ret) {
        const char *shifted;
        int r;

        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_OWNER_UID))
                return -ENODATA;

        assert(c->cgroup);

        r = cg_shift_path(c->cgroup, c->cgroup_root, &shifted);
        if (r < 0)
                return r;

        return cg_path_get_owner_uid(shifted, ret);
}

_public_ int sd_bus_creds_get_cmdline(sd_bus_creds *c, char ***ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_CMDLINE))
                return -ENODATA;

        if (!c->cmdline)
                return -ENXIO;

        if (!c->cmdline_array) {
                c->cmdline_array = strv_parse_nulstr(c->cmdline, c->cmdline_size);
                if (!c->cmdline_array)
                        return -ENOMEM;
        }

        *ret = c->cmdline_array;
        return 0;
}

_public_ int sd_bus_creds_get_audit_session_id(sd_bus_creds *c, uint32_t *ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_AUDIT_SESSION_ID))
                return -ENODATA;

        if (!audit_session_is_valid(c->audit_session_id))
                return -ENXIO;

        *ret = c->audit_session_id;
        return 0;
}

_public_ int sd_bus_creds_get_audit_login_uid(sd_bus_creds *c, uid_t *ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_AUDIT_LOGIN_UID))
                return -ENODATA;

        if (!uid_is_valid(c->audit_login_uid))
                return -ENXIO;

        *ret = c->audit_login_uid;
        return 0;
}

_public_ int sd_bus_creds_get_tty(sd_bus_creds *c, const char **ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_TTY))
                return -ENODATA;

        if (!c->tty)
                return -ENXIO;

        *ret = c->tty;
        return 0;
}

_public_ int sd_bus_creds_get_unique_name(sd_bus_creds *c, const char **ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_UNIQUE_NAME))
                return -ENODATA;

        *ret = c->unique_name;
        return 0;
}

_public_ int sd_bus_creds_get_well_known_names(sd_bus_creds *c, char ***ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_WELL_KNOWN_NAMES))
                return -ENODATA;

        /* As a special hack we return the bus driver as well-known
         * names list when this is requested. */
        if (c->well_known_names_driver) {
                static const char* const wkn[] = {
                        "org.freedesktop.DBus",
                        NULL
                };

                *ret = (char**) wkn;
                return 0;
        }

        if (c->well_known_names_local) {
                static const char* const wkn[] = {
                        "org.freedesktop.DBus.Local",
                        NULL
                };

                *ret = (char**) wkn;
                return 0;
        }

        *ret = c->well_known_names;
        return 0;
}

_public_ int sd_bus_creds_get_description(sd_bus_creds *c, const char **ret) {
        assert_return(c, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_DESCRIPTION))
                return -ENODATA;

        assert(c->description);

        if (!c->unescaped_description) {
                c->unescaped_description = bus_label_unescape(c->description);
                if (!c->unescaped_description)
                        return -ENOMEM;
        }

        *ret = c->unescaped_description;
        return 0;
}

static int has_cap(sd_bus_creds *c, size_t offset, int capability) {
        size_t sz;

        assert(c);
        assert(capability >= 0);
        assert(c->capability);

        unsigned lc = cap_last_cap();

        if ((unsigned) capability > lc)
                return 0;

        /* If the last cap is 63, then there are 64 caps defined, and we need 2 entries à 32-bit hence. *
         * If the last cap is 64, then there are 65 caps defined, and we need 3 entries à 32-bit hence. */
        sz = DIV_ROUND_UP(lc+1, 32LU);

        return !!(c->capability[offset * sz + CAP_TO_INDEX((uint32_t) capability)] & CAP_TO_MASK_CORRECTED((uint32_t) capability));
}

_public_ int sd_bus_creds_has_effective_cap(sd_bus_creds *c, int capability) {
        assert_return(c, -EINVAL);
        assert_return(capability >= 0, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_EFFECTIVE_CAPS))
                return -ENODATA;

        return has_cap(c, CAP_OFFSET_EFFECTIVE, capability);
}

_public_ int sd_bus_creds_has_permitted_cap(sd_bus_creds *c, int capability) {
        assert_return(c, -EINVAL);
        assert_return(capability >= 0, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_PERMITTED_CAPS))
                return -ENODATA;

        return has_cap(c, CAP_OFFSET_PERMITTED, capability);
}

_public_ int sd_bus_creds_has_inheritable_cap(sd_bus_creds *c, int capability) {
        assert_return(c, -EINVAL);
        assert_return(capability >= 0, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_INHERITABLE_CAPS))
                return -ENODATA;

        return has_cap(c, CAP_OFFSET_INHERITABLE, capability);
}

_public_ int sd_bus_creds_has_bounding_cap(sd_bus_creds *c, int capability) {
        assert_return(c, -EINVAL);
        assert_return(capability >= 0, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_BOUNDING_CAPS))
                return -ENODATA;

        return has_cap(c, CAP_OFFSET_BOUNDING, capability);
}

static int parse_caps(sd_bus_creds *c, unsigned offset, const char *p) {
        size_t sz, max;

        assert(c);
        assert(p);

        max = DIV_ROUND_UP(cap_last_cap()+1, 32U);

        sz = strlen(p);
        if (sz % 8 != 0)
                return -EINVAL;

        sz /= 8;
        if (sz > max)
                return -EINVAL;

        if (!c->capability) {
                c->capability = new0(uint32_t, max * 4);
                if (!c->capability)
                        return -ENOMEM;
        }

        for (unsigned i = 0; i < sz; i++) {
                uint32_t v = 0;

                for (unsigned j = 0; j < 8; j++) {
                        int t;

                        t = unhexchar(*p++);
                        if (t < 0)
                                return -EINVAL;

                        v = (v << 4) | t;
                }

                c->capability[offset * max + (sz - i - 1)] = v;
        }

        return 0;
}

int bus_creds_add_more(sd_bus_creds *c, uint64_t mask, PidRef *pidref, pid_t tid) {
        _cleanup_(pidref_done) PidRef pidref_buf = PIDREF_NULL;
        uint64_t missing;
        int r;

        assert(c);
        assert(c->allocated);

        if (!(mask & SD_BUS_CREDS_AUGMENT))
                return 0;

        /* Try to retrieve PID from creds if it wasn't passed to us */
        if (pidref_is_set(pidref)) {
                if ((c->mask & SD_BUS_CREDS_PID) && c->pid != pidref->pid) /* Insist that things match if already set */
                        return -EBUSY;

                c->pid = pidref->pid;
                c->mask |= SD_BUS_CREDS_PID;
        } else if (c->mask & SD_BUS_CREDS_PIDFD) {
                r = pidref_set_pidfd(&pidref_buf, c->pidfd);
                if (r < 0)
                        return r;

                pidref = &pidref_buf;

        } else if (c->mask & SD_BUS_CREDS_PID) {
                r = pidref_set_pid(&pidref_buf, c->pid);
                if (r < 0)
                        return r;

                pidref = &pidref_buf;
        } else
                /* Without pid we cannot do much... */
                return 0;

        /* Try to retrieve TID from creds if it wasn't passed to us */
        if (tid <= 0 && (c->mask & SD_BUS_CREDS_TID))
                tid = c->tid;

        /* Calculate what we shall and can add */
        missing = mask & ~(c->mask|SD_BUS_CREDS_PID|SD_BUS_CREDS_TID|SD_BUS_CREDS_UNIQUE_NAME|SD_BUS_CREDS_WELL_KNOWN_NAMES|SD_BUS_CREDS_DESCRIPTION|SD_BUS_CREDS_AUGMENT);
        if (missing == 0)
                return 0;

        if (tid > 0) {
                c->tid = tid;
                c->mask |= SD_BUS_CREDS_TID;
        }

        if ((missing & SD_BUS_CREDS_PIDFD) && pidref->fd >= 0) {
                c->pidfd = fcntl(pidref->fd, F_DUPFD_CLOEXEC, 3);
                if (c->pidfd < 0)
                        return -errno;

                c->mask |= SD_BUS_CREDS_PIDFD;
        }

        if (missing & (SD_BUS_CREDS_PPID |
                       SD_BUS_CREDS_UID | SD_BUS_CREDS_EUID | SD_BUS_CREDS_SUID | SD_BUS_CREDS_FSUID |
                       SD_BUS_CREDS_GID | SD_BUS_CREDS_EGID | SD_BUS_CREDS_SGID | SD_BUS_CREDS_FSGID |
                       SD_BUS_CREDS_SUPPLEMENTARY_GIDS |
                       SD_BUS_CREDS_EFFECTIVE_CAPS | SD_BUS_CREDS_INHERITABLE_CAPS |
                       SD_BUS_CREDS_PERMITTED_CAPS | SD_BUS_CREDS_BOUNDING_CAPS)) {

                _cleanup_fclose_ FILE *f = NULL;
                const char *p;

                p = procfs_file_alloca(pidref->pid, "status");

                f = fopen(p, "re");
                if (!f) {
                        if (errno == ENOENT)
                                return -ESRCH;
                        if (!ERRNO_IS_PRIVILEGE(errno))
                                return -errno;
                } else {

                        for (;;) {
                                _cleanup_free_ char *line = NULL;

                                r = read_line(f, LONG_LINE_MAX, &line);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        break;

                                if (missing & SD_BUS_CREDS_PPID) {
                                        p = first_word(line, "PPid:");
                                        if (p) {
                                                /* Explicitly check for PPID 0 (which is the case for PID 1) */
                                                if (!streq(p, "0")) {
                                                        r = parse_pid(p, &c->ppid);
                                                        if (r < 0)
                                                                return r;
                                                } else
                                                        c->ppid = 0;

                                                c->mask |= SD_BUS_CREDS_PPID;
                                                continue;
                                        }
                                }

                                if (missing & (SD_BUS_CREDS_UID|SD_BUS_CREDS_EUID|SD_BUS_CREDS_SUID|SD_BUS_CREDS_FSUID)) {
                                        p = first_word(line, "Uid:");
                                        if (p) {
                                                unsigned long uid, euid, suid, fsuid;

                                                if (sscanf(p, "%lu %lu %lu %lu", &uid, &euid, &suid, &fsuid) != 4)
                                                        return -EIO;

                                                if (missing & SD_BUS_CREDS_UID)
                                                        c->uid = (uid_t) uid;
                                                if (missing & SD_BUS_CREDS_EUID)
                                                        c->euid = (uid_t) euid;
                                                if (missing & SD_BUS_CREDS_SUID)
                                                        c->suid = (uid_t) suid;
                                                if (missing & SD_BUS_CREDS_FSUID)
                                                        c->fsuid = (uid_t) fsuid;

                                                c->mask |= missing & (SD_BUS_CREDS_UID|SD_BUS_CREDS_EUID|SD_BUS_CREDS_SUID|SD_BUS_CREDS_FSUID);
                                                continue;
                                        }
                                }

                                if (missing & (SD_BUS_CREDS_GID|SD_BUS_CREDS_EGID|SD_BUS_CREDS_SGID|SD_BUS_CREDS_FSGID)) {
                                        p = first_word(line, "Gid:");
                                        if (p) {
                                                unsigned long gid, egid, sgid, fsgid;

                                                if (sscanf(p, "%lu %lu %lu %lu", &gid, &egid, &sgid, &fsgid) != 4)
                                                        return -EIO;

                                                if (missing & SD_BUS_CREDS_GID)
                                                        c->gid = (gid_t) gid;
                                                if (missing & SD_BUS_CREDS_EGID)
                                                        c->egid = (gid_t) egid;
                                                if (missing & SD_BUS_CREDS_SGID)
                                                        c->sgid = (gid_t) sgid;
                                                if (missing & SD_BUS_CREDS_FSGID)
                                                        c->fsgid = (gid_t) fsgid;

                                                c->mask |= missing & (SD_BUS_CREDS_GID|SD_BUS_CREDS_EGID|SD_BUS_CREDS_SGID|SD_BUS_CREDS_FSGID);
                                                continue;
                                        }
                                }

                                if (missing & SD_BUS_CREDS_SUPPLEMENTARY_GIDS) {
                                        p = startswith(line, "Groups:");
                                        if (p) {
                                                for (;;) {
                                                        unsigned long g;
                                                        int n = 0;

                                                        p = skip_leading_chars(p, /* bad = */ NULL);
                                                        if (*p == 0)
                                                                break;

                                                        if (sscanf(p, "%lu%n", &g, &n) != 1)
                                                                return -EIO;

                                                        if (!GREEDY_REALLOC(c->supplementary_gids, c->n_supplementary_gids+1))
                                                                return -ENOMEM;

                                                        c->supplementary_gids[c->n_supplementary_gids++] = (gid_t) g;
                                                        p += n;
                                                }

                                                c->mask |= SD_BUS_CREDS_SUPPLEMENTARY_GIDS;
                                                continue;
                                        }
                                }

                                if (missing & SD_BUS_CREDS_EFFECTIVE_CAPS) {
                                        p = first_word(line, "CapEff:");
                                        if (p) {
                                                r = parse_caps(c, CAP_OFFSET_EFFECTIVE, p);
                                                if (r < 0)
                                                        return r;

                                                c->mask |= SD_BUS_CREDS_EFFECTIVE_CAPS;
                                                continue;
                                        }
                                }

                                if (missing & SD_BUS_CREDS_PERMITTED_CAPS) {
                                        p = first_word(line, "CapPrm:");
                                        if (p) {
                                                r = parse_caps(c, CAP_OFFSET_PERMITTED, p);
                                                if (r < 0)
                                                        return r;

                                                c->mask |= SD_BUS_CREDS_PERMITTED_CAPS;
                                                continue;
                                        }
                                }

                                if (missing & SD_BUS_CREDS_INHERITABLE_CAPS) {
                                        p = first_word(line, "CapInh:");
                                        if (p) {
                                                r = parse_caps(c, CAP_OFFSET_INHERITABLE, p);
                                                if (r < 0)
                                                        return r;

                                                c->mask |= SD_BUS_CREDS_INHERITABLE_CAPS;
                                                continue;
                                        }
                                }

                                if (missing & SD_BUS_CREDS_BOUNDING_CAPS) {
                                        p = first_word(line, "CapBnd:");
                                        if (p) {
                                                r = parse_caps(c, CAP_OFFSET_BOUNDING, p);
                                                if (r < 0)
                                                        return r;

                                                c->mask |= SD_BUS_CREDS_BOUNDING_CAPS;
                                                continue;
                                        }
                                }
                        }
                }
        }

        if (missing & SD_BUS_CREDS_SELINUX_CONTEXT) {
                const char *p;

                p = procfs_file_alloca(pidref->pid, "attr/current");
                r = read_one_line_file(p, &c->label);
                if (r < 0) {
                        if (!IN_SET(r, -ENOENT, -EINVAL, -EPERM, -EACCES))
                                return r;
                } else
                        c->mask |= SD_BUS_CREDS_SELINUX_CONTEXT;
        }

        if (missing & SD_BUS_CREDS_COMM) {
                r = pid_get_comm(pidref->pid, &c->comm);
                if (r < 0) {
                        if (!ERRNO_IS_PRIVILEGE(r))
                                return r;
                } else
                        c->mask |= SD_BUS_CREDS_COMM;
        }

        if (missing & SD_BUS_CREDS_EXE) {
                r = get_process_exe(pidref->pid, &c->exe);
                if (r == -ESRCH) {
                        /* Unfortunately we cannot really distinguish
                         * the case here where the process does not
                         * exist, and /proc/$PID/exe being unreadable
                         * because $PID is a kernel thread. Hence,
                         * assume it is a kernel thread, and rely on
                         * that this case is caught with a later
                         * call. */
                        c->exe = NULL;
                        c->mask |= SD_BUS_CREDS_EXE;
                } else if (r < 0) {
                        if (!ERRNO_IS_PRIVILEGE(r))
                                return r;
                } else
                        c->mask |= SD_BUS_CREDS_EXE;
        }

        if (missing & SD_BUS_CREDS_CMDLINE) {
                const char *p;

                p = procfs_file_alloca(pidref->pid, "cmdline");
                r = read_full_file(p, &c->cmdline, &c->cmdline_size);
                if (r == -ENOENT)
                        return -ESRCH;
                if (r < 0) {
                        if (!ERRNO_IS_PRIVILEGE(r))
                                return r;
                } else {
                        if (c->cmdline_size == 0)
                                c->cmdline = mfree(c->cmdline);

                        c->mask |= SD_BUS_CREDS_CMDLINE;
                }
        }

        if (tid > 0 && (missing & SD_BUS_CREDS_TID_COMM)) {
                _cleanup_free_ char *p = NULL;

                if (asprintf(&p, "/proc/"PID_FMT"/task/"PID_FMT"/comm", pidref->pid, tid) < 0)
                        return -ENOMEM;

                r = read_one_line_file(p, &c->tid_comm);
                if (r == -ENOENT)
                        return -ESRCH;
                if (r < 0) {
                        if (!ERRNO_IS_PRIVILEGE(r))
                                return r;
                } else
                        c->mask |= SD_BUS_CREDS_TID_COMM;
        }

        if (missing & (SD_BUS_CREDS_CGROUP|SD_BUS_CREDS_UNIT|SD_BUS_CREDS_USER_UNIT|SD_BUS_CREDS_SLICE|SD_BUS_CREDS_USER_SLICE|SD_BUS_CREDS_SESSION|SD_BUS_CREDS_OWNER_UID)) {

                if (!c->cgroup) {
                        r = cg_pid_get_path(pidref->pid, &c->cgroup);
                        if (r < 0 && !ERRNO_IS_NEG_PRIVILEGE(r))
                                return r;
                }

                if (!c->cgroup_root) {
                        r = cg_get_root_path(&c->cgroup_root);
                        if (r < 0)
                                return r;
                }

                if (c->cgroup)
                        c->mask |= missing & (SD_BUS_CREDS_CGROUP|SD_BUS_CREDS_UNIT|SD_BUS_CREDS_USER_UNIT|SD_BUS_CREDS_SLICE|SD_BUS_CREDS_USER_SLICE|SD_BUS_CREDS_SESSION|SD_BUS_CREDS_OWNER_UID);
        }

        if (missing & SD_BUS_CREDS_AUDIT_SESSION_ID) {
                r = audit_session_from_pid(pidref, &c->audit_session_id);
                if (r == -ENODATA) {
                        /* ENODATA means: no audit session id assigned */
                        c->audit_session_id = AUDIT_SESSION_INVALID;
                        c->mask |= SD_BUS_CREDS_AUDIT_SESSION_ID;
                } else if (r < 0) {
                        if (!IN_SET(r, -EOPNOTSUPP, -ENOENT, -EPERM, -EACCES))
                                return r;
                } else
                        c->mask |= SD_BUS_CREDS_AUDIT_SESSION_ID;
        }

        if (missing & SD_BUS_CREDS_AUDIT_LOGIN_UID) {
                r = audit_loginuid_from_pid(pidref, &c->audit_login_uid);
                if (r == -ENODATA) {
                        /* ENODATA means: no audit login uid assigned */
                        c->audit_login_uid = UID_INVALID;
                        c->mask |= SD_BUS_CREDS_AUDIT_LOGIN_UID;
                } else if (r < 0) {
                        if (!IN_SET(r, -EOPNOTSUPP, -ENOENT, -EPERM, -EACCES))
                                return r;
                } else
                        c->mask |= SD_BUS_CREDS_AUDIT_LOGIN_UID;
        }

        if (missing & SD_BUS_CREDS_TTY) {
                r = get_ctty(pidref->pid, NULL, &c->tty);
                if (r == -ENXIO) {
                        /* ENXIO means: process has no controlling TTY */
                        c->tty = NULL;
                        c->mask |= SD_BUS_CREDS_TTY;
                } else if (r < 0) {
                        if (!IN_SET(r, -EPERM, -EACCES, -ENOENT))
                                return r;
                } else
                        c->mask |= SD_BUS_CREDS_TTY;
        }

        r = pidref_verify(pidref);
        if (r < 0)
                return r;

        /* Validate tid is still valid, too */
        if (tid > 0 && tid != pidref->pid && pid_is_unwaited(tid) == 0)
                return -ESRCH;

        c->augmented = missing & c->mask;

        return 0;
}
