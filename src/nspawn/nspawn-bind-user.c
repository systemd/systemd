/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "fileio.h"
#include "format-util.h"
#include "log.h"
#include "nspawn.h"
#include "machine-bind-user.h"
#include "nspawn-bind-user.h"
#include "user-record.h"
#include "group-record.h"
#include "path-util.h"
#include "string-util.h"
#include "user-util.h"

static int write_and_symlink(
                const char *root,
                sd_json_variant *v,
                const char *name,
                uid_t uid,
                const char *suffix,
                WriteStringFileFlags extra_flags) {

        _cleanup_free_ char *j = NULL, *f = NULL, *p = NULL, *q = NULL;
        int r;

        assert(root);
        assert(v);
        assert(name);
        assert(uid_is_valid(uid));
        assert(suffix);

        r = sd_json_variant_format(v, SD_JSON_FORMAT_NEWLINE, &j);
        if (r < 0)
                return log_error_errno(r, "Failed to format user record JSON: %m");

        f = strjoin(name, suffix);
        if (!f)
                return log_oom();

        p = path_join(root, "/run/host/userdb/", f);
        if (!p)
                return log_oom();

        if (asprintf(&q, "%s/run/host/userdb/" UID_FMT "%s", root, uid, suffix) < 0)
                return log_oom();

        if (symlink(f, q) < 0)
                return log_error_errno(errno, "Failed to create symlink '%s': %m", q);

        r = userns_lchown(q, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to adjust access mode of '%s': %m", q);

        r = write_string_file(p, j, WRITE_STRING_FILE_CREATE|extra_flags);
        if (r < 0)
                return log_error_errno(r, "Failed to write %s: %m", p);

        r = userns_lchown(p, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to adjust access mode of '%s': %m", p);

        return 0;
}

int bind_user_setup(const MachineBindUserContext *c, const char *root) {
        static const UserRecordLoadFlags strip_flags = /* Removes privileged info */
                USER_RECORD_LOAD_MASK_PRIVILEGED|
                USER_RECORD_PERMISSIVE;
        static const UserRecordLoadFlags shadow_flags = /* Extracts privileged info */
                USER_RECORD_EXTRACT_PRIVILEGED|
                USER_RECORD_EMPTY_OK|
                USER_RECORD_PERMISSIVE;
        int r;

        assert(root);

        if (!c || c->n_data == 0)
                return 0;

        r = make_run_host(root);
        if (r < 0)
                return r;

        r = userns_mkdir(root, "/run/host/home", 0755, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to create /run/host/home: %m");

        r = userns_mkdir(root, "/run/host/userdb", 0755, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to create /run/host/userdb: %m");

        FOREACH_ARRAY(d, c->data, c->n_data) {
                _cleanup_(group_record_unrefp) GroupRecord *stripped_group = NULL, *shadow_group = NULL;
                _cleanup_(user_record_unrefp) UserRecord *stripped_user = NULL, *shadow_user = NULL;

                /* First, write shadow (i.e. privileged) data for group record */
                r = group_record_clone(d->payload_group, shadow_flags, &shadow_group);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract privileged information from group record: %m");

                if (!sd_json_variant_is_blank_object(shadow_group->json)) {
                        r = write_and_symlink(
                                        root,
                                        shadow_group->json,
                                        d->payload_group->group_name,
                                        d->payload_group->gid,
                                        ".group-privileged",
                                        WRITE_STRING_FILE_MODE_0600);
                        if (r < 0)
                                return r;
                }

                /* Second, write main part of group record. */
                r = group_record_clone(d->payload_group, strip_flags, &stripped_group);
                if (r < 0)
                        return log_error_errno(r, "Failed to strip privileged information from group record: %m");

                r = write_and_symlink(
                                root,
                                stripped_group->json,
                                d->payload_group->group_name,
                                d->payload_group->gid,
                                ".group",
                                0);
                if (r < 0)
                        return r;

                /* Third, write out user shadow data. i.e. extract privileged info from user record */
                r = user_record_clone(d->payload_user, shadow_flags, &shadow_user);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract privileged information from user record: %m");

                if (!sd_json_variant_is_blank_object(shadow_user->json)) {
                        r = write_and_symlink(
                                        root,
                                        shadow_user->json,
                                        d->payload_user->user_name,
                                        d->payload_user->uid,
                                        ".user-privileged",
                                        WRITE_STRING_FILE_MODE_0600);
                        if (r < 0)
                                return r;
                }

                /* Finally write out the main part of the user record */
                r = user_record_clone(d->payload_user, strip_flags, &stripped_user);
                if (r < 0)
                        return log_error_errno(r, "Failed to strip privileged information from user record: %m");

                r = write_and_symlink(
                                root,
                                stripped_user->json,
                                d->payload_user->user_name,
                                d->payload_user->uid,
                                ".user",
                                0);
                if (r < 0)
                        return r;
        }

        return 1;
}
