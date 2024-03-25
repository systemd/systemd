/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "machined.h"
#include "strv.h"
#include "user-util.h"

int manager_find_machine_for_uid(Manager *m, uid_t uid, Machine **ret_machine, uid_t *ret_internal_uid) {
        Machine *machine;
        int r;

        assert(m);
        assert(uid_is_valid(uid));

        /* Finds the machine for the specified host UID and returns it along with the UID translated into the
         * internal UID inside the machine */

        HASHMAP_FOREACH(machine, m->machines) {
                uid_t converted;

                r = machine_owns_uid(machine, uid, &converted);
                if (r < 0)
                        return r;
                if (r) {
                        if (ret_machine)
                                *ret_machine = machine;

                        if (ret_internal_uid)
                                *ret_internal_uid = converted;

                        return true;
                }
        }

        if (ret_machine)
                *ret_machine = NULL;
        if (ret_internal_uid)
                *ret_internal_uid = UID_INVALID;

        return false;
}

int manager_find_machine_for_gid(Manager *m, gid_t gid, Machine **ret_machine, gid_t *ret_internal_gid) {
        Machine *machine;
        int r;

        assert(m);
        assert(gid_is_valid(gid));

        HASHMAP_FOREACH(machine, m->machines) {
                gid_t converted;

                r = machine_owns_gid(machine, gid, &converted);
                if (r < 0)
                        return r;
                if (r) {
                        if (ret_machine)
                                *ret_machine = machine;

                        if (ret_internal_gid)
                                *ret_internal_gid = converted;

                        return true;
                }
        }

        if (ret_machine)
                *ret_machine = NULL;
        if (ret_internal_gid)
                *ret_internal_gid = GID_INVALID;

        return false;
}
