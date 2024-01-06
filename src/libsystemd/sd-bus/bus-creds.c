/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/capability.h>
#include <stdlib.h>

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
}

_public_ sd_bus_creds *sd_bus_creds_ref(sd_bus_creds *c) {

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

_public_ sd_bus_creds *sd_bus_creds_unref(sd_bus_creds *c) {

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

        c = new0(sd_bus_creds, 1);
        if (!c)
                return NULL;

        c->allocated = true;
        c->n_ref = 1;
        return c;
}

_public_ int sd_bus_creds_new_from_pid(sd_bus_creds **ret, pid_t pid, uint64_t mask) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *c = NULL;
        int r;

        assert_return(pid >= 0, -EINVAL);
        assert_return(mask <= _SD_BUS_CREDS_ALL, -EOPNOTSUPP);
        assert_return(ret, -EINVAL);

        if (pid == 0)
                pid = getpid_cached();

        c = bus_creds_new();
        if (!c)
                return -ENOMEM;

        r = bus_creds_add_more(c, mask | SD_BUS_CREDS_AUGMENT, pid, 0);
        if (r < 0)
                return r;

        /* Check if the process existed at all, in case we haven't
         * figured that out already */
        r = pid_is_alive(pid);
        if (r < 0)
                return r;
        if (r == 0)
                return -ESRCH;

        *ret = TAKE_PTR(c);
        return 0;
}

_public_ int sd_bus_creds_get_uid(sd_bus_creds *c, uid_t *uid) {
        assert_return(c, -EINVAL);
        assert_return(uid, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_UID))
                return -ENODATA;

        *uid = c->uid;
        return 0;
}

_public_ int sd_bus_creds_get_euid(sd_bus_creds *c, uid_t *euid) {
        assert_return(c, -EINVAL);
        assert_return(euid, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_EUID))
                return -ENODATA;

        *euid = c->euid;
        return 0;
}

_public_ int sd_bus_creds_get_suid(sd_bus_creds *c, uid_t *suid) {
        assert_return(c, -EINVAL);
        assert_return(suid, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_SUID))
                return -ENODATA;

        *suid = c->suid;
        return 0;
}

_public_ int sd_bus_creds_get_fsuid(sd_bus_creds *c, uid_t *fsuid) {
        assert_return(c, -EINVAL);
        assert_return(fsuid, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_FSUID))
                return -ENODATA;

        *fsuid = c->fsuid;
        return 0;
}

_public_ int sd_bus_creds_get_gid(sd_bus_creds *c, gid_t *gid) {
        assert_return(c, -EINVAL);
        assert_return(gid, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_GID))
                return -ENODATA;

        *gid = c->gid;
        return 0;
}

_public_ int sd_bus_creds_get_egid(sd_bus_creds *c, gid_t *egid) {
        assert_return(c, -EINVAL);
        assert_return(egid, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_EGID))
                return -ENODATA;

        *egid = c->egid;
        return 0;
}

_public_ int sd_bus_creds_get_sgid(sd_bus_creds *c, gid_t *sgid) {
        assert_return(c, -EINVAL);
        assert_return(sgid, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_SGID))
                return -ENODATA;

        *sgid = c->sgid;
        return 0;
}

_public_ int sd_bus_creds_get_fsgid(sd_bus_creds *c, gid_t *fsgid) {
        assert_return(c, -EINVAL);
        assert_return(fsgid, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_FSGID))
                return -ENODATA;

        *fsgid = c->fsgid;
        return 0;
}

_public_ int sd_bus_creds_get_supplementary_gids(sd_bus_creds *c, const gid_t **gids) {
        assert_return(c, -EINVAL);
        assert_return(gids, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_SUPPLEMENTARY_GIDS))
                return -ENODATA;

        *gids = c->supplementary_gids;
        return (int) c->n_supplementary_gids;
}

_public_ int sd_bus_creds_get_pid(sd_bus_creds *c, pid_t *pid) {
        assert_return(c, -EINVAL);
        assert_return(pid, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_PID))
                return -ENODATA;

        assert(c->pid > 0);
        *pid = c->pid;
        return 0;
}

_public_ int sd_bus_creds_get_ppid(sd_bus_creds *c, pid_t *ppid) {
        assert_return(c, -EINVAL);
        assert_return(ppid, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_PPID))
                return -ENODATA;

        /* PID 1 has no parent process. Let's distinguish the case of
         * not knowing and not having a parent process by the returned
         * error code. */
        if (c->ppid == 0)
                return -ENXIO;

        *ppid = c->ppid;
        return 0;
}

_public_ int sd_bus_creds_get_tid(sd_bus_creds *c, pid_t *tid) {
        assert_return(c, -EINVAL);
        assert_return(tid, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_TID))
                return -ENODATA;

        assert(c->tid > 0);
        *tid = c->tid;
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

_public_ int sd_bus_creds_get_owner_uid(sd_bus_creds *c, uid_t *uid) {
        const char *shifted;
        int r;

        assert_return(c, -EINVAL);
        assert_return(uid, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_OWNER_UID))
                return -ENODATA;

        assert(c->cgroup);

        r = cg_shift_path(c->cgroup, c->cgroup_root, &shifted);
        if (r < 0)
                return r;

        return cg_path_get_owner_uid(shifted, uid);
}

_public_ int sd_bus_creds_get_cmdline(sd_bus_creds *c, char ***cmdline) {
        assert_return(c, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_CMDLINE))
                return -ENODATA;

        if (!c->cmdline)
                return -ENXIO;

        if (!c->cmdline_array) {
                c->cmdline_array = strv_parse_nulstr(c->cmdline, c->cmdline_size);
                if (!c->cmdline_array)
                        return -ENOMEM;
        }

        *cmdline = c->cmdline_array;
        return 0;
}

_public_ int sd_bus_creds_get_audit_session_id(sd_bus_creds *c, uint32_t *sessionid) {
        assert_return(c, -EINVAL);
        assert_return(sessionid, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_AUDIT_SESSION_ID))
                return -ENODATA;

        if (!audit_session_is_valid(c->audit_session_id))
                return -ENXIO;

        *sessionid = c->audit_session_id;
        return 0;
}

_public_ int sd_bus_creds_get_audit_login_uid(sd_bus_creds *c, uid_t *uid) {
        assert_return(c, -EINVAL);
        assert_return(uid, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_AUDIT_LOGIN_UID))
                return -ENODATA;

        if (!uid_is_valid(c->audit_login_uid))
                return -ENXIO;

        *uid = c->audit_login_uid;
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

_public_ int sd_bus_creds_get_unique_name(sd_bus_creds *c, const char **unique_name) {
        assert_return(c, -EINVAL);
        assert_return(unique_name, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_UNIQUE_NAME))
                return -ENODATA;

        *unique_name = c->unique_name;
        return 0;
}

_public_ int sd_bus_creds_get_well_known_names(sd_bus_creds *c, char ***well_known_names) {
        assert_return(c, -EINVAL);
        assert_return(well_known_names, -EINVAL);

        if (!(c->mask & SD_BUS_CREDS_WELL_KNOWN_NAMES))
                return -ENODATA;

        /* As a special hack we return the bus driver as well-known
         * names list when this is requested. */
        if (c->well_known_names_driver) {
                static const char* const wkn[] = {
                        "org.freedesktop.DBus",
                        NULL
                };

                *well_known_names = (char**) wkn;
                return 0;
        }

        if (c->well_known_names_local) {
                static const char* const wkn[] = {
                        "org.freedesktop.DBus.Local",
                        NULL
                };

                *well_known_names = (char**) wkn;
                return 0;
        }

        *well_known_names = c->well_known_names;
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
        unsigned i, j;

        assert(c);
        assert(p);

        max = DIV_ROUND_UP(cap_last_cap()+1, 32U);
        p += strspn(p, WHITESPACE);

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

        for (i = 0; i < sz; i++) {
                uint32_t v = 0;

                for (j = 0; j < 8; ++j) {
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

int bus_creds_add_more(sd_bus_creds *c, uint64_t mask, pid_t pid, pid_t tid) {
        uint64_t missing;
        int r;

        assert(c);
        assert(c->allocated);

        if (!(mask & SD_BUS_CREDS_AUGMENT))
                return 0;

        /* Try to retrieve PID from creds if it wasn't passed to us */
        if (pid > 0) {
                c->pid = pid;
                c->mask |= SD_BUS_CREDS_PID;
        } else if (c->mask & SD_BUS_CREDS_PID)
                pid = c->pid;
        else
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

        if (missing & (SD_BUS_CREDS_PPID |
                       SD_BUS_CREDS_UID | SD_BUS_CREDS_EUID | SD_BUS_CREDS_SUID | SD_BUS_CREDS_FSUID |
                       SD_BUS_CREDS_GID | SD_BUS_CREDS_EGID | SD_BUS_CREDS_SGID | SD_BUS_CREDS_FSGID |
                       SD_BUS_CREDS_SUPPLEMENTARY_GIDS |
                       SD_BUS_CREDS_EFFECTIVE_CAPS | SD_BUS_CREDS_INHERITABLE_CAPS |
                       SD_BUS_CREDS_PERMITTED_CAPS | SD_BUS_CREDS_BOUNDING_CAPS)) {

                _cleanup_fclose_ FILE *f = NULL;
                const char *p;

                p = procfs_file_alloca(pid, "status");

                f = fopen(p, "re");
                if (!f) {
                        if (errno == ENOENT)
                                return -ESRCH;
                        else if (!ERRNO_IS_PRIVILEGE(errno))
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
                                        p = startswith(line, "PPid:");
                                        if (p) {
                                                p += strspn(p, WHITESPACE);

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
                                        p = startswith(line, "Uid:");
                                        if (p) {
                                                unsigned long uid, euid, suid, fsuid;

                                                p += strspn(p, WHITESPACE);
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
                                        p = startswith(line, "Gid:");
                                        if (p) {
                                                unsigned long gid, egid, sgid, fsgid;

                                                p += strspn(p, WHITESPACE);
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

                                                        p += strspn(p, WHITESPACE);
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
                                        p = startswith(line, "CapEff:");
                                        if (p) {
                                                r = parse_caps(c, CAP_OFFSET_EFFECTIVE, p);
                                                if (r < 0)
                                                        return r;

                                                c->mask |= SD_BUS_CREDS_EFFECTIVE_CAPS;
                                                continue;
                                        }
                                }

                                if (missing & SD_BUS_CREDS_PERMITTED_CAPS) {
                                        p = startswith(line, "CapPrm:");
                                        if (p) {
                                                r = parse_caps(c, CAP_OFFSET_PERMITTED, p);
                                                if (r < 0)
                                                        return r;

                                                c->mask |= SD_BUS_CREDS_PERMITTED_CAPS;
                                                continue;
                                        }
                                }

                                if (missing & SD_BUS_CREDS_INHERITABLE_CAPS) {
                                        p = startswith(line, "CapInh:");
                                        if (p) {
                                                r = parse_caps(c, CAP_OFFSET_INHERITABLE, p);
                                                if (r < 0)
                                                        return r;

                                                c->mask |= SD_BUS_CREDS_INHERITABLE_CAPS;
                                                continue;
                                        }
                                }

                                if (missing & SD_BUS_CREDS_BOUNDING_CAPS) {
                                        p = startswith(line, "CapBnd:");
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

                p = procfs_file_alloca(pid, "attr/current");
                r = read_one_line_file(p, &c->label);
                if (r < 0) {
                        if (!IN_SET(r, -ENOENT, -EINVAL, -EPERM, -EACCES))
                                return r;
                } else
                        c->mask |= SD_BUS_CREDS_SELINUX_CONTEXT;
        }

        if (missing & SD_BUS_CREDS_COMM) {
                r = pid_get_comm(pid, &c->comm);
                if (r < 0) {
                        if (!ERRNO_IS_PRIVILEGE(r))
                                return r;
                } else
                        c->mask |= SD_BUS_CREDS_COMM;
        }

        if (missing & SD_BUS_CREDS_EXE) {
                r = get_process_exe(pid, &c->exe);
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

                p = procfs_file_alloca(pid, "cmdline");
                void *tmp;
                r = read_full_virtual_file(p, &tmp, &c->cmdline_size);
                c->cmdline = tmp;

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

                if (asprintf(&p, "/proc/"PID_FMT"/task/"PID_FMT"/comm", pid, tid) < 0)
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
                        r = cg_pid_get_path(NULL, pid, &c->cgroup);
                        if (r < 0) {
                                if (!ERRNO_IS_PRIVILEGE(r))
                                        return r;
                        }
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
                r = audit_session_from_pid(pid, &c->audit_session_id);
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
                r = audit_loginuid_from_pid(pid, &c->audit_login_uid);
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
                r = get_ctty(pid, NULL, &c->tty);
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

        /* In case only the exe path was to be read we cannot distinguish the case where the exe path was
         * unreadable because the process was a kernel thread, or when the process didn't exist at
         * all. Hence, let's do a final check, to be sure. */
        r = pid_is_alive(pid);
        if (r < 0)
                return r;
        if (r == 0)
                return -ESRCH;

        if (tid > 0 && tid != pid && pid_is_unwaited(tid) == 0)
                return -ESRCH;

        c->augmented = missing & c->mask;

        return 0;
}

int bus_creds_extend_by_pid(sd_bus_creds *c, uint64_t mask, sd_bus_creds **ret) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *n = NULL;
        int r;

        assert(c);
        assert(ret);

        if ((mask & ~c->mask) == 0 || (!(mask & SD_BUS_CREDS_AUGMENT))) {
                /* There's already all data we need, or augmentation
                 * wasn't turned on. */

                *ret = sd_bus_creds_ref(c);
                return 0;
        }

        n = bus_creds_new();
        if (!n)
                return -ENOMEM;

        /* Copy the original data over */

        if (c->mask & mask & SD_BUS_CREDS_PID) {
                n->pid = c->pid;
                n->mask |= SD_BUS_CREDS_PID;
        }

        if (c->mask & mask & SD_BUS_CREDS_TID) {
                n->tid = c->tid;
                n->mask |= SD_BUS_CREDS_TID;
        }

        if (c->mask & mask & SD_BUS_CREDS_PPID) {
                n->ppid = c->ppid;
                n->mask |= SD_BUS_CREDS_PPID;
        }

        if (c->mask & mask & SD_BUS_CREDS_UID) {
                n->uid = c->uid;
                n->mask |= SD_BUS_CREDS_UID;
        }

        if (c->mask & mask & SD_BUS_CREDS_EUID) {
                n->euid = c->euid;
                n->mask |= SD_BUS_CREDS_EUID;
        }

        if (c->mask & mask & SD_BUS_CREDS_SUID) {
                n->suid = c->suid;
                n->mask |= SD_BUS_CREDS_SUID;
        }

        if (c->mask & mask & SD_BUS_CREDS_FSUID) {
                n->fsuid = c->fsuid;
                n->mask |= SD_BUS_CREDS_FSUID;
        }

        if (c->mask & mask & SD_BUS_CREDS_GID) {
                n->gid = c->gid;
                n->mask |= SD_BUS_CREDS_GID;
        }

        if (c->mask & mask & SD_BUS_CREDS_EGID) {
                n->egid = c->egid;
                n->mask |= SD_BUS_CREDS_EGID;
        }

        if (c->mask & mask & SD_BUS_CREDS_SGID) {
                n->sgid = c->sgid;
                n->mask |= SD_BUS_CREDS_SGID;
        }

        if (c->mask & mask & SD_BUS_CREDS_FSGID) {
                n->fsgid = c->fsgid;
                n->mask |= SD_BUS_CREDS_FSGID;
        }

        if (c->mask & mask & SD_BUS_CREDS_SUPPLEMENTARY_GIDS) {
                if (c->supplementary_gids) {
                        n->supplementary_gids = newdup(gid_t, c->supplementary_gids, c->n_supplementary_gids);
                        if (!n->supplementary_gids)
                                return -ENOMEM;
                        n->n_supplementary_gids = c->n_supplementary_gids;
                } else {
                        n->supplementary_gids = NULL;
                        n->n_supplementary_gids = 0;
                }

                n->mask |= SD_BUS_CREDS_SUPPLEMENTARY_GIDS;
        }

        if (c->mask & mask & SD_BUS_CREDS_COMM) {
                assert(c->comm);

                n->comm = strdup(c->comm);
                if (!n->comm)
                        return -ENOMEM;

                n->mask |= SD_BUS_CREDS_COMM;
        }

        if (c->mask & mask & SD_BUS_CREDS_TID_COMM) {
                assert(c->tid_comm);

                n->tid_comm = strdup(c->tid_comm);
                if (!n->tid_comm)
                        return -ENOMEM;

                n->mask |= SD_BUS_CREDS_TID_COMM;
        }

        if (c->mask & mask & SD_BUS_CREDS_EXE) {
                if (c->exe) {
                        n->exe = strdup(c->exe);
                        if (!n->exe)
                                return -ENOMEM;
                } else
                        n->exe = NULL;

                n->mask |= SD_BUS_CREDS_EXE;
        }

        if (c->mask & mask & SD_BUS_CREDS_CMDLINE) {
                if (c->cmdline) {
                        n->cmdline = memdup(c->cmdline, c->cmdline_size);
                        if (!n->cmdline)
                                return -ENOMEM;

                        n->cmdline_size = c->cmdline_size;
                } else {
                        n->cmdline = NULL;
                        n->cmdline_size = 0;
                }

                n->mask |= SD_BUS_CREDS_CMDLINE;
        }

        if (c->mask & mask & (SD_BUS_CREDS_CGROUP|SD_BUS_CREDS_SESSION|SD_BUS_CREDS_UNIT|SD_BUS_CREDS_USER_UNIT|SD_BUS_CREDS_SLICE|SD_BUS_CREDS_USER_SLICE|SD_BUS_CREDS_OWNER_UID)) {
                assert(c->cgroup);

                n->cgroup = strdup(c->cgroup);
                if (!n->cgroup)
                        return -ENOMEM;

                n->cgroup_root = strdup(c->cgroup_root);
                if (!n->cgroup_root)
                        return -ENOMEM;

                n->mask |= mask & (SD_BUS_CREDS_CGROUP|SD_BUS_CREDS_SESSION|SD_BUS_CREDS_UNIT|SD_BUS_CREDS_USER_UNIT|SD_BUS_CREDS_SLICE|SD_BUS_CREDS_USER_SLICE|SD_BUS_CREDS_OWNER_UID);
        }

        if (c->mask & mask & (SD_BUS_CREDS_EFFECTIVE_CAPS|SD_BUS_CREDS_PERMITTED_CAPS|SD_BUS_CREDS_INHERITABLE_CAPS|SD_BUS_CREDS_BOUNDING_CAPS)) {
                assert(c->capability);

                n->capability = memdup(c->capability, DIV_ROUND_UP(cap_last_cap()+1, 32U) * 4 * 4);
                if (!n->capability)
                        return -ENOMEM;

                n->mask |= c->mask & mask & (SD_BUS_CREDS_EFFECTIVE_CAPS|SD_BUS_CREDS_PERMITTED_CAPS|SD_BUS_CREDS_INHERITABLE_CAPS|SD_BUS_CREDS_BOUNDING_CAPS);
        }

        if (c->mask & mask & SD_BUS_CREDS_SELINUX_CONTEXT) {
                assert(c->label);

                n->label = strdup(c->label);
                if (!n->label)
                        return -ENOMEM;
                n->mask |= SD_BUS_CREDS_SELINUX_CONTEXT;
        }

        if (c->mask & mask & SD_BUS_CREDS_AUDIT_SESSION_ID) {
                n->audit_session_id = c->audit_session_id;
                n->mask |= SD_BUS_CREDS_AUDIT_SESSION_ID;
        }
        if (c->mask & mask & SD_BUS_CREDS_AUDIT_LOGIN_UID) {
                n->audit_login_uid = c->audit_login_uid;
                n->mask |= SD_BUS_CREDS_AUDIT_LOGIN_UID;
        }

        if (c->mask & mask & SD_BUS_CREDS_TTY) {
                if (c->tty) {
                        n->tty = strdup(c->tty);
                        if (!n->tty)
                                return -ENOMEM;
                } else
                        n->tty = NULL;
                n->mask |= SD_BUS_CREDS_TTY;
        }

        if (c->mask & mask & SD_BUS_CREDS_UNIQUE_NAME) {
                assert(c->unique_name);

                n->unique_name = strdup(c->unique_name);
                if (!n->unique_name)
                        return -ENOMEM;
                n->mask |= SD_BUS_CREDS_UNIQUE_NAME;
        }

        if (c->mask & mask & SD_BUS_CREDS_WELL_KNOWN_NAMES) {
                if (strv_isempty(c->well_known_names))
                        n->well_known_names = NULL;
                else {
                        n->well_known_names = strv_copy(c->well_known_names);
                        if (!n->well_known_names)
                                return -ENOMEM;
                }
                n->well_known_names_driver = c->well_known_names_driver;
                n->well_known_names_local = c->well_known_names_local;
                n->mask |= SD_BUS_CREDS_WELL_KNOWN_NAMES;
        }

        if (c->mask & mask & SD_BUS_CREDS_DESCRIPTION) {
                assert(c->description);
                n->description = strdup(c->description);
                if (!n->description)
                        return -ENOMEM;
                n->mask |= SD_BUS_CREDS_DESCRIPTION;
        }

        n->augmented = c->augmented & n->mask;

        /* Get more data */

        r = bus_creds_add_more(n, mask, 0, 0);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(n);

        return 0;
}
