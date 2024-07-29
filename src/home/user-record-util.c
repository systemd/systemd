/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/xattr.h>

#include "sd-json.h"

#include "errno-util.h"
#include "fd-util.h"
#include "home-util.h"
#include "id128-util.h"
#include "json-util.h"
#include "libcrypt-util.h"
#include "memory-util.h"
#include "mountpoint-util.h"
#include "path-util.h"
#include "recovery-key.h"
#include "sha256.h"
#include "stat-util.h"
#include "user-record-util.h"
#include "user-util.h"

int user_record_synthesize(
                UserRecord *h,
                const char *user_name,
                const char *realm,
                const char *image_path,
                UserStorage storage,
                uid_t uid,
                gid_t gid) {

        _cleanup_free_ char *hd = NULL, *un = NULL, *ip = NULL, *rr = NULL, *user_name_and_realm = NULL;
        sd_id128_t mid;
        int r;

        assert(h);
        assert(user_name);
        assert(image_path);
        assert(IN_SET(storage, USER_LUKS, USER_SUBVOLUME, USER_FSCRYPT, USER_DIRECTORY));
        assert(uid_is_valid(uid));
        assert(gid_is_valid(gid));

        /* Fill in a home record from just a username and an image path. */

        if (h->json)
                return -EBUSY;

        if (!suitable_user_name(user_name))
                return -EINVAL;

        if (realm) {
                r = suitable_realm(realm);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EINVAL;
        }

        if (!suitable_image_path(image_path))
                return -EINVAL;

        r = sd_id128_get_machine(&mid);
        if (r < 0)
                return r;

        un = strdup(user_name);
        if (!un)
                return -ENOMEM;

        if (realm) {
                rr = strdup(realm);
                if (!rr)
                        return -ENOMEM;

                user_name_and_realm = strjoin(user_name, "@", realm);
                if (!user_name_and_realm)
                        return -ENOMEM;
        }

        ip = strdup(image_path);
        if (!ip)
                return -ENOMEM;

        hd = path_join(get_home_root(), user_name);
        if (!hd)
                return -ENOMEM;

        r = sd_json_buildo(
                        &h->json,
                        SD_JSON_BUILD_PAIR("userName", SD_JSON_BUILD_STRING(user_name)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!rr, "realm", SD_JSON_BUILD_STRING(realm)),
                        SD_JSON_BUILD_PAIR("disposition", JSON_BUILD_CONST_STRING("regular")),
                        SD_JSON_BUILD_PAIR("binding", SD_JSON_BUILD_OBJECT(
                                                           SD_JSON_BUILD_PAIR(SD_ID128_TO_STRING(mid), SD_JSON_BUILD_OBJECT(
                                                                                              SD_JSON_BUILD_PAIR("imagePath", SD_JSON_BUILD_STRING(image_path)),
                                                                                              SD_JSON_BUILD_PAIR("homeDirectory", SD_JSON_BUILD_STRING(hd)),
                                                                                              SD_JSON_BUILD_PAIR("storage", SD_JSON_BUILD_STRING(user_storage_to_string(storage))),
                                                                                              SD_JSON_BUILD_PAIR("uid", SD_JSON_BUILD_UNSIGNED(uid)),
                                                                                              SD_JSON_BUILD_PAIR("gid", SD_JSON_BUILD_UNSIGNED(gid)))))));
        if (r < 0)
                return r;

        free_and_replace(h->user_name, un);
        free_and_replace(h->realm, rr);
        free_and_replace(h->user_name_and_realm_auto, user_name_and_realm);
        free_and_replace(h->image_path, ip);
        free_and_replace(h->home_directory, hd);
        h->storage = storage;
        h->uid = uid;

        h->mask = USER_RECORD_REGULAR|USER_RECORD_BINDING;
        return 0;
}

int group_record_synthesize(GroupRecord *g, UserRecord *h) {
        _cleanup_free_ char *un = NULL, *rr = NULL, *group_name_and_realm = NULL, *description = NULL;
        sd_id128_t mid;
        int r;

        assert(g);
        assert(h);

        if (g->json)
                return -EBUSY;

        r = sd_id128_get_machine(&mid);
        if (r < 0)
                return r;

        un = strdup(h->user_name);
        if (!un)
                return -ENOMEM;

        if (h->realm) {
                rr = strdup(h->realm);
                if (!rr)
                        return -ENOMEM;

                group_name_and_realm = strjoin(un, "@", rr);
                if (!group_name_and_realm)
                        return -ENOMEM;
        }

        description = strjoin("Primary Group of User ", un);
        if (!description)
                return -ENOMEM;

        r = sd_json_buildo(
                        &g->json,
                        SD_JSON_BUILD_PAIR("groupName", SD_JSON_BUILD_STRING(un)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!rr, "realm", SD_JSON_BUILD_STRING(rr)),
                        SD_JSON_BUILD_PAIR("description", SD_JSON_BUILD_STRING(description)),
                        SD_JSON_BUILD_PAIR("binding", SD_JSON_BUILD_OBJECT(
                                                           SD_JSON_BUILD_PAIR(SD_ID128_TO_STRING(mid), SD_JSON_BUILD_OBJECT(
                                                                                              SD_JSON_BUILD_PAIR("gid", SD_JSON_BUILD_UNSIGNED(user_record_gid(h))))))),
                        SD_JSON_BUILD_PAIR_CONDITION(h->disposition >= 0, "disposition", SD_JSON_BUILD_STRING(user_disposition_to_string(user_record_disposition(h)))),
                        SD_JSON_BUILD_PAIR("status", SD_JSON_BUILD_OBJECT(
                                                           SD_JSON_BUILD_PAIR(SD_ID128_TO_STRING(mid), SD_JSON_BUILD_OBJECT(
                                                                                              SD_JSON_BUILD_PAIR("service", JSON_BUILD_CONST_STRING("io.systemd.Home")))))));
        if (r < 0)
                return r;

        free_and_replace(g->group_name, un);
        free_and_replace(g->realm, rr);
        free_and_replace(g->group_name_and_realm_auto, group_name_and_realm);
        g->gid = user_record_gid(h);
        g->disposition = h->disposition;

        g->mask = USER_RECORD_REGULAR|USER_RECORD_BINDING;
        return 0;
}

int user_record_reconcile(
                UserRecord *host,
                UserRecord *embedded,
                UserReconcileMode mode,
                UserRecord **ret) {

        int r, result;

        /* Reconciles the identity record stored on the host with the one embedded in a $HOME
         * directory. Returns the following error codes:
         *
         *     -EINVAL: one of the records not valid
         *     -REMCHG: identity records are not about the same user
         *     -ESTALE: embedded identity record is equally new or newer than supplied record
         *
         * Return the new record to use, which is either the embedded record updated with the host
         * binding or the host record. In both cases the secret data is stripped. */

        assert(host);
        assert(embedded);

        /* Make sure both records are initialized */
        if (!host->json || !embedded->json)
                return -EINVAL;

        /* Ensure these records actually contain user data */
        if (!(embedded->mask & host->mask & USER_RECORD_REGULAR))
                return -EINVAL;

        /* Make sure the user name and realm matches */
        if (!user_record_compatible(host, embedded))
                return -EREMCHG;

        /* Embedded identities may not contain secrets or binding info */
        if ((embedded->mask & (USER_RECORD_SECRET|USER_RECORD_BINDING)) != 0)
                return -EINVAL;

        /* The embedded record checked out, let's now figure out which of the two identities we'll consider
         * in effect from now on. We do this by checking the last change timestamp, and in doubt always let
         * the embedded data win. */
        if (host->last_change_usec != UINT64_MAX &&
            (embedded->last_change_usec == UINT64_MAX || host->last_change_usec > embedded->last_change_usec))

                /* The host version is definitely newer, either because it has a version at all and the
                 * embedded version doesn't or because it is numerically newer. */
                result = USER_RECONCILE_HOST_WON;

        else if (host->last_change_usec == embedded->last_change_usec) {

                /* The nominal version number of the host and the embedded identity is the same. If so, let's
                 * verify that, and tell the caller if we are ignoring embedded data. */

                r = user_record_masked_equal(host, embedded, USER_RECORD_REGULAR|USER_RECORD_PRIVILEGED|USER_RECORD_PER_MACHINE);
                if (r < 0)
                        return r;
                if (r > 0) {
                        if (mode == USER_RECONCILE_REQUIRE_NEWER)
                                return -ESTALE;

                        result = USER_RECONCILE_IDENTICAL;
                } else
                        result = USER_RECONCILE_HOST_WON;
        } else {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *extended = NULL;
                _cleanup_(user_record_unrefp) UserRecord *merged = NULL;
                sd_json_variant *e;

                /* The embedded version is newer */

                if (mode == USER_RECONCILE_REQUIRE_NEWER_OR_EQUAL)
                        return -ESTALE;

                /* Copy in the binding data */
                extended = sd_json_variant_ref(embedded->json);

                e = sd_json_variant_by_key(host->json, "binding");
                if (e) {
                        r = sd_json_variant_set_field(&extended, "binding", e);
                        if (r < 0)
                                return r;
                }

                merged = user_record_new();
                if (!merged)
                        return -ENOMEM;

                r = user_record_load(merged, extended, USER_RECORD_LOAD_MASK_SECRET|USER_RECORD_PERMISSIVE);
                if (r < 0)
                        return r;

                *ret = TAKE_PTR(merged);
                return USER_RECONCILE_EMBEDDED_WON; /* update */
        }

        /* Strip out secrets */
        r = user_record_clone(host, USER_RECORD_LOAD_MASK_SECRET|USER_RECORD_PERMISSIVE, ret);
        if (r < 0)
                return r;

        return result;
}

int user_record_add_binding(
                UserRecord *h,
                UserStorage storage,
                const char *image_path,
                sd_id128_t partition_uuid,
                sd_id128_t luks_uuid,
                sd_id128_t fs_uuid,
                const char *luks_cipher,
                const char *luks_cipher_mode,
                uint64_t luks_volume_key_size,
                const char *file_system_type,
                const char *home_directory,
                uid_t uid,
                gid_t gid) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *new_binding_entry = NULL, *binding = NULL;
        _cleanup_free_ char *blob = NULL, *ip = NULL, *hd = NULL, *ip_auto = NULL, *lc = NULL, *lcm = NULL, *fst = NULL;
        sd_id128_t mid;
        int r;

        assert(h);

        if (!h->json)
                return -EUNATCH;

        blob = path_join(home_system_blob_dir(), h->user_name);
        if (!blob)
                return -ENOMEM;

        r = sd_id128_get_machine(&mid);
        if (r < 0)
                return r;

        if (image_path) {
                ip = strdup(image_path);
                if (!ip)
                        return -ENOMEM;
        } else if (!h->image_path && storage >= 0) {
                r = user_record_build_image_path(storage, user_record_user_name_and_realm(h), &ip_auto);
                if (r < 0)
                        return r;
        }

        if (home_directory) {
                hd = strdup(home_directory);
                if (!hd)
                        return -ENOMEM;
        }

        if (file_system_type) {
                fst = strdup(file_system_type);
                if (!fst)
                        return -ENOMEM;
        }

        if (luks_cipher) {
                lc = strdup(luks_cipher);
                if (!lc)
                        return -ENOMEM;
        }

        if (luks_cipher_mode) {
                lcm = strdup(luks_cipher_mode);
                if (!lcm)
                        return -ENOMEM;
        }

        r = sd_json_buildo(
                        &new_binding_entry,
                        SD_JSON_BUILD_PAIR("blobDirectory", SD_JSON_BUILD_STRING(blob)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!image_path, "imagePath", SD_JSON_BUILD_STRING(image_path)),
                        SD_JSON_BUILD_PAIR_CONDITION(!sd_id128_is_null(partition_uuid), "partitionUuid", SD_JSON_BUILD_STRING(SD_ID128_TO_UUID_STRING(partition_uuid))),
                        SD_JSON_BUILD_PAIR_CONDITION(!sd_id128_is_null(luks_uuid), "luksUuid", SD_JSON_BUILD_STRING(SD_ID128_TO_UUID_STRING(luks_uuid))),
                        SD_JSON_BUILD_PAIR_CONDITION(!sd_id128_is_null(fs_uuid), "fileSystemUuid", SD_JSON_BUILD_STRING(SD_ID128_TO_UUID_STRING(fs_uuid))),
                        SD_JSON_BUILD_PAIR_CONDITION(!!luks_cipher, "luksCipher", SD_JSON_BUILD_STRING(luks_cipher)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!luks_cipher_mode, "luksCipherMode", SD_JSON_BUILD_STRING(luks_cipher_mode)),
                        SD_JSON_BUILD_PAIR_CONDITION(luks_volume_key_size != UINT64_MAX, "luksVolumeKeySize", SD_JSON_BUILD_UNSIGNED(luks_volume_key_size)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!file_system_type, "fileSystemType", SD_JSON_BUILD_STRING(file_system_type)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!home_directory, "homeDirectory", SD_JSON_BUILD_STRING(home_directory)),
                        SD_JSON_BUILD_PAIR_CONDITION(uid_is_valid(uid), "uid", SD_JSON_BUILD_UNSIGNED(uid)),
                        SD_JSON_BUILD_PAIR_CONDITION(gid_is_valid(gid), "gid", SD_JSON_BUILD_UNSIGNED(gid)),
                        SD_JSON_BUILD_PAIR_CONDITION(storage >= 0, "storage", SD_JSON_BUILD_STRING(user_storage_to_string(storage))));
        if (r < 0)
                return r;

        binding = sd_json_variant_ref(sd_json_variant_by_key(h->json, "binding"));
        if (binding) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *be = NULL;

                /* Merge the new entry with an old one, if that exists */
                be = sd_json_variant_ref(sd_json_variant_by_key(binding, SD_ID128_TO_STRING(mid)));
                if (be) {
                        r = sd_json_variant_merge_object(&be, new_binding_entry);
                        if (r < 0)
                                return r;

                        sd_json_variant_unref(new_binding_entry);
                        new_binding_entry = TAKE_PTR(be);
                }
        }

        r = sd_json_variant_set_field(&binding, SD_ID128_TO_STRING(mid), new_binding_entry);
        if (r < 0)
                return r;

        r = sd_json_variant_set_field(&h->json, "binding", binding);
        if (r < 0)
                return r;

        free_and_replace(h->blob_directory, blob);

        if (storage >= 0)
                h->storage = storage;

        if (ip)
                free_and_replace(h->image_path, ip);
        if (ip_auto)
                free_and_replace(h->image_path_auto, ip_auto);

        if (!sd_id128_is_null(partition_uuid))
                h->partition_uuid = partition_uuid;

        if (!sd_id128_is_null(luks_uuid))
                h->luks_uuid = luks_uuid;

        if (!sd_id128_is_null(fs_uuid))
                h->file_system_uuid = fs_uuid;

        if (lc)
                free_and_replace(h->luks_cipher, lc);
        if (lcm)
                free_and_replace(h->luks_cipher_mode, lcm);
        if (luks_volume_key_size != UINT64_MAX)
                h->luks_volume_key_size = luks_volume_key_size;

        if (fst)
                free_and_replace(h->file_system_type, fst);
        if (hd)
                free_and_replace(h->home_directory, hd);

        if (uid_is_valid(uid))
                h->uid = uid;
        if (gid_is_valid(gid))
                h->gid = gid;

        h->mask |= USER_RECORD_BINDING;
        return 1;
}

int user_record_test_home_directory(UserRecord *h) {
        const char *hd;
        int r;

        assert(h);

        /* Returns one of USER_TEST_ABSENT, USER_TEST_MOUNTED, USER_TEST_EXISTS on success */

        hd = user_record_home_directory(h);
        if (!hd)
                return -ENXIO;

        r = is_dir(hd, false);
        if (r == -ENOENT)
                return USER_TEST_ABSENT;
        if (r < 0)
                return r;
        if (r == 0)
                return -ENOTDIR;

        r = path_is_mount_point(hd);
        if (r < 0)
                return r;
        if (r > 0)
                return USER_TEST_MOUNTED;

        /* If the image path and the home directory are identical, then it's OK if the directory is
         * populated. */
        if (IN_SET(user_record_storage(h), USER_CLASSIC, USER_DIRECTORY, USER_SUBVOLUME, USER_FSCRYPT)) {
                const char *ip;

                ip = user_record_image_path(h);
                if (ip && path_equal(ip, hd))
                        return USER_TEST_EXISTS;
        }

        /* Otherwise it's not OK */
        r = dir_is_empty(hd, /* ignore_hidden_or_backup= */ false);
        if (r < 0)
                return r;
        if (r == 0)
                return -EBUSY;

        return USER_TEST_EXISTS;
}

int user_record_test_home_directory_and_warn(UserRecord *h) {
        int r;

        assert(h);

        r = user_record_test_home_directory(h);
        if (r == -ENXIO)
                return log_error_errno(r, "User record lacks home directory, refusing.");
        if (r == -ENOTDIR)
                return log_error_errno(r, "Home directory %s is not a directory, refusing.", user_record_home_directory(h));
        if (r == -EBUSY)
                return log_error_errno(r, "Home directory %s exists, is not mounted but populated, refusing.", user_record_home_directory(h));
        if (r < 0)
                return log_error_errno(r, "Failed to test whether the home directory %s exists: %m", user_record_home_directory(h));

        return r;
}

int user_record_test_image_path(UserRecord *h) {
        const char *ip;
        struct stat st;

        assert(h);

        if (user_record_storage(h) == USER_CIFS)
                return USER_TEST_UNDEFINED;

        ip = user_record_image_path(h);
        if (!ip)
                return -ENXIO;

        if (stat(ip, &st) < 0) {
                if (errno == ENOENT)
                        return USER_TEST_ABSENT;

                return -errno;
        }

        switch (user_record_storage(h)) {

        case USER_LUKS:
                if (S_ISREG(st.st_mode)) {
                        ssize_t n;
                        char x[2];

                        n = getxattr(ip, "user.home-dirty", x, sizeof(x));
                        if (n < 0) {
                                if (!ERRNO_IS_XATTR_ABSENT(errno))
                                        log_debug_errno(errno, "Unable to read dirty xattr off image file, ignoring: %m");

                        } else if (n == 1 && x[0] == '1')
                                return USER_TEST_DIRTY;

                        return USER_TEST_EXISTS;
                }

                if (S_ISBLK(st.st_mode)) {
                        /* For block devices we can't really be sure if the device referenced actually is the
                         * fs we look for or some other file system (think: what does /dev/sdb1 refer
                         * to?). Hence, let's return USER_TEST_MAYBE as an ambiguous return value for these
                         * case, except if the device path used is one of the paths that is based on a
                         * filesystem or partition UUID or label, because in those cases we can be sure we
                         * are referring to the right device. */

                        if (PATH_STARTSWITH_SET(ip,
                                                "/dev/disk/by-uuid/",
                                                "/dev/disk/by-partuuid/",
                                                "/dev/disk/by-partlabel/",
                                                "/dev/disk/by-label/"))
                                return USER_TEST_EXISTS;

                        return USER_TEST_MAYBE;
                }

                return -EBADFD;

        case USER_CLASSIC:
        case USER_DIRECTORY:
        case USER_SUBVOLUME:
        case USER_FSCRYPT:
                if (S_ISDIR(st.st_mode))
                        return USER_TEST_EXISTS;

                return -ENOTDIR;

        default:
                assert_not_reached();
        }
}

int user_record_test_image_path_and_warn(UserRecord *h) {
        int r;

        assert(h);

        r = user_record_test_image_path(h);
        if (r == -ENXIO)
                return log_error_errno(r, "User record lacks image path, refusing.");
        if (r == -EBADFD)
                return log_error_errno(r, "Image path %s is not a regular file or block device, refusing.", user_record_image_path(h));
        if (r == -ENOTDIR)
                return log_error_errno(r, "Image path %s is not a directory, refusing.", user_record_image_path(h));
        if (r < 0)
                return log_error_errno(r, "Failed to test whether image path %s exists: %m", user_record_image_path(h));

        return r;
}

int user_record_test_password(UserRecord *h, UserRecord *secret) {
        int r;

        assert(h);

        /* Checks whether any of the specified passwords matches any of the hashed passwords of the entry */

        if (strv_isempty(h->hashed_password))
                return -ENXIO;

        STRV_FOREACH(i, secret->password) {
                r = test_password_many(h->hashed_password, *i);
                if (r < 0)
                        return r;
                if (r > 0)
                        return 0;
        }

        return -ENOKEY;
}

int user_record_test_recovery_key(UserRecord *h, UserRecord *secret) {
        int r;

        assert(h);

        /* Checks whether any of the specified passwords matches any of the hashed recovery keys of the entry */

        if (h->n_recovery_key == 0)
                return -ENXIO;

        STRV_FOREACH(i, secret->password) {
                for (size_t j = 0; j < h->n_recovery_key; j++) {
                        _cleanup_(erase_and_freep) char *mangled = NULL;
                        const char *p;

                        if (streq(h->recovery_key[j].type, "modhex64")) {
                                /* If this key is for a modhex64 recovery key, then try to normalize the
                                 * passphrase to make things more robust: that way the password becomes case
                                 * insensitive and the dashes become optional. */

                                r = normalize_recovery_key(*i, &mangled);
                                if (r == -EINVAL) /* Not a valid modhex64 passphrase, don't bother */
                                        continue;
                                if (r < 0)
                                        return r;

                                p = mangled;
                        } else
                                p = *i; /* Unknown recovery key types process as is */

                        r = test_password_one(h->recovery_key[j].hashed_password, p);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                return 0;
                }
        }

        return -ENOKEY;
}

int user_record_set_disk_size(UserRecord *h, uint64_t disk_size) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *new_per_machine = NULL, *midv = NULL, *midav = NULL, *ne = NULL;
        _cleanup_free_ sd_json_variant **array = NULL;
        size_t idx = SIZE_MAX, n;
        sd_json_variant *per_machine;
        sd_id128_t mid;
        int r;

        assert(h);

        if (!h->json)
                return -EUNATCH;

        r = sd_id128_get_machine(&mid);
        if (r < 0)
                return r;

        r = sd_json_variant_new_string(&midv, SD_ID128_TO_STRING(mid));
        if (r < 0)
                return r;

        r = sd_json_variant_new_array(&midav, (sd_json_variant*[]) { midv }, 1);
        if (r < 0)
                return r;

        per_machine = sd_json_variant_by_key(h->json, "perMachine");
        if (per_machine) {
                size_t i;

                if (!sd_json_variant_is_array(per_machine))
                        return -EINVAL;

                n = sd_json_variant_elements(per_machine);

                array = new(sd_json_variant*, n + 1);
                if (!array)
                        return -ENOMEM;

                for (i = 0; i < n; i++) {
                        sd_json_variant *m;

                        array[i] = sd_json_variant_by_index(per_machine, i);

                        if (!sd_json_variant_is_object(array[i]))
                                return -EINVAL;

                        m = sd_json_variant_by_key(array[i], "matchMachineId");
                        if (!m) {
                                /* No machineId field? Let's ignore this, but invalidate what we found so far */
                                idx = SIZE_MAX;
                                continue;
                        }

                        if (sd_json_variant_equal(m, midv) ||
                            sd_json_variant_equal(m, midav)) {
                                /* Matches exactly what we are looking for. Let's use this */
                                idx = i;
                                continue;
                        }

                        r = per_machine_id_match(m, SD_JSON_PERMISSIVE);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                /* Also matches what we are looking for, but with a broader match. In this
                                 * case let's ignore this entry, and add a new specific one to the end. */
                                idx = SIZE_MAX;
                }

                if (idx == SIZE_MAX)
                        idx = n++; /* Nothing suitable found, place new entry at end */
                else
                        ne = sd_json_variant_ref(array[idx]);

        } else {
                array = new(sd_json_variant*, 1);
                if (!array)
                        return -ENOMEM;

                idx = 0;
                n = 1;
        }

        if (!ne) {
                r = sd_json_variant_set_field(&ne, "matchMachineId", midav);
                if (r < 0)
                        return r;
        }

        r = sd_json_variant_set_field_unsigned(&ne, "diskSize", disk_size);
        if (r < 0)
                return r;

        assert(idx < n);
        array[idx] = ne;

        r = sd_json_variant_new_array(&new_per_machine, array, n);
        if (r < 0)
                return r;

        r = sd_json_variant_set_field(&h->json, "perMachine", new_per_machine);
        if (r < 0)
                return r;

        h->disk_size = disk_size;
        h->mask |= USER_RECORD_PER_MACHINE;
        return 0;
}

int user_record_update_last_changed(UserRecord *h, bool with_password) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        usec_t n;
        int r;

        assert(h);

        if (!h->json)
                return -EUNATCH;

        n = now(CLOCK_REALTIME);

        /* refuse downgrading */
        if (h->last_change_usec != UINT64_MAX && h->last_change_usec >= n)
                return -ECHRNG;
        if (h->last_password_change_usec != UINT64_MAX && h->last_password_change_usec >= n)
                return -ECHRNG;

        v = sd_json_variant_ref(h->json);

        r = sd_json_variant_set_field_unsigned(&v, "lastChangeUSec", n);
        if (r < 0)
                return r;

        if (with_password) {
                r = sd_json_variant_set_field_unsigned(&v, "lastPasswordChangeUSec", n);
                if (r < 0)
                        return r;

                h->last_password_change_usec = n;
        }

        h->last_change_usec = n;

        sd_json_variant_unref(h->json);
        h->json = TAKE_PTR(v);

        h->mask |= USER_RECORD_REGULAR;
        return 0;
}

int user_record_make_hashed_password(UserRecord *h, char **secret, bool extend) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *priv = NULL;
        _cleanup_strv_free_ char **np = NULL;
        int r;

        assert(h);
        assert(secret);

        /* Initializes the hashed password list from the specified plaintext passwords */

        if (extend) {
                np = strv_copy(h->hashed_password);
                if (!np)
                        return -ENOMEM;

                strv_uniq(np);
        }

        STRV_FOREACH(i, secret) {
                _cleanup_(erase_and_freep) char *hashed = NULL;

                r = hash_password(*i, &hashed);
                if (r < 0)
                        return r;

                r = strv_consume(&np, TAKE_PTR(hashed));
                if (r < 0)
                        return r;
        }

        priv = sd_json_variant_ref(sd_json_variant_by_key(h->json, "privileged"));

        if (strv_isempty(np))
                r = sd_json_variant_filter(&priv, STRV_MAKE("hashedPassword"));
        else {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *new_array = NULL;

                r = sd_json_variant_new_array_strv(&new_array, np);
                if (r < 0)
                        return r;

                r = sd_json_variant_set_field(&priv, "hashedPassword", new_array);
        }
        if (r < 0)
                return r;

        r = sd_json_variant_set_field(&h->json, "privileged", priv);
        if (r < 0)
                return r;

        strv_free_and_replace(h->hashed_password, np);

        SET_FLAG(h->mask, USER_RECORD_PRIVILEGED, !sd_json_variant_is_blank_object(priv));
        return 0;
}

int user_record_set_hashed_password(UserRecord *h, char **hashed_password) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *priv = NULL;
        _cleanup_strv_free_ char **copy = NULL;
        int r;

        assert(h);

        priv = sd_json_variant_ref(sd_json_variant_by_key(h->json, "privileged"));

        if (strv_isempty(hashed_password))
                r = sd_json_variant_filter(&priv, STRV_MAKE("hashedPassword"));
        else {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;

                copy = strv_copy(hashed_password);
                if (!copy)
                        return -ENOMEM;

                strv_uniq(copy);

                r = sd_json_variant_new_array_strv(&array, copy);
                if (r < 0)
                        return r;

                r = sd_json_variant_set_field(&priv, "hashedPassword", array);
        }
        if (r < 0)
                return r;

        r = sd_json_variant_set_field(&h->json, "privileged", priv);
        if (r < 0)
                return r;

        strv_free_and_replace(h->hashed_password, copy);

        SET_FLAG(h->mask, USER_RECORD_PRIVILEGED, !sd_json_variant_is_blank_object(priv));
        return 0;
}

int user_record_set_password(UserRecord *h, char **password, bool prepend) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        _cleanup_strv_free_erase_ char **e = NULL;
        int r;

        assert(h);

        if (prepend) {
                e = strv_copy(password);
                if (!e)
                        return -ENOMEM;

                r = strv_extend_strv(&e, h->password, true);
                if (r < 0)
                        return r;

                strv_uniq(e);

                if (strv_equal(h->password, e))
                        return 0;

        } else {
                if (strv_equal(h->password, password))
                        return 0;

                e = strv_copy(password);
                if (!e)
                        return -ENOMEM;

                strv_uniq(e);
        }

        w = sd_json_variant_ref(sd_json_variant_by_key(h->json, "secret"));

        if (strv_isempty(e))
                r = sd_json_variant_filter(&w, STRV_MAKE("password"));
        else {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *l = NULL;

                r = sd_json_variant_new_array_strv(&l, e);
                if (r < 0)
                        return r;

                sd_json_variant_sensitive(l);

                r = sd_json_variant_set_field(&w, "password", l);
        }
        if (r < 0)
                return r;

        sd_json_variant_sensitive(w);

        r = sd_json_variant_set_field(&h->json, "secret", w);
        if (r < 0)
                return r;

        strv_free_and_replace(h->password, e);

        SET_FLAG(h->mask, USER_RECORD_SECRET, !sd_json_variant_is_blank_object(w));
        return 0;
}

int user_record_set_token_pin(UserRecord *h, char **pin, bool prepend) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        _cleanup_strv_free_erase_ char **e = NULL;
        int r;

        assert(h);

        if (prepend) {
                e = strv_copy(pin);
                if (!e)
                        return -ENOMEM;

                r = strv_extend_strv(&e, h->token_pin, true);
                if (r < 0)
                        return r;

                strv_uniq(e);

                if (strv_equal(h->token_pin, e))
                        return 0;

        } else {
                if (strv_equal(h->token_pin, pin))
                        return 0;

                e = strv_copy(pin);
                if (!e)
                        return -ENOMEM;

                strv_uniq(e);
        }

        w = sd_json_variant_ref(sd_json_variant_by_key(h->json, "secret"));

        if (strv_isempty(e))
                r = sd_json_variant_filter(&w, STRV_MAKE("tokenPin"));
        else {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *l = NULL;

                r = sd_json_variant_new_array_strv(&l, e);
                if (r < 0)
                        return r;

                sd_json_variant_sensitive(l);

                r = sd_json_variant_set_field(&w, "tokenPin", l);
        }
        if (r < 0)
                return r;

        sd_json_variant_sensitive(w);

        r = sd_json_variant_set_field(&h->json, "secret", w);
        if (r < 0)
                return r;

        strv_free_and_replace(h->token_pin, e);

        SET_FLAG(h->mask, USER_RECORD_SECRET, !sd_json_variant_is_blank_object(w));
        return 0;
}

int user_record_set_pkcs11_protected_authentication_path_permitted(UserRecord *h, int b) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        int r;

        assert(h);

        w = sd_json_variant_ref(sd_json_variant_by_key(h->json, "secret"));

        if (b < 0)
                r = sd_json_variant_filter(&w, STRV_MAKE("pkcs11ProtectedAuthenticationPathPermitted"));
        else
                r = sd_json_variant_set_field_boolean(&w, "pkcs11ProtectedAuthenticationPathPermitted", b);
        if (r < 0)
                return r;

        if (sd_json_variant_is_blank_object(w))
                r = sd_json_variant_filter(&h->json, STRV_MAKE("secret"));
        else {
                sd_json_variant_sensitive(w);

                r = sd_json_variant_set_field(&h->json, "secret", w);
        }
        if (r < 0)
                return r;

        h->pkcs11_protected_authentication_path_permitted = b;

        SET_FLAG(h->mask, USER_RECORD_SECRET, !sd_json_variant_is_blank_object(w));
        return 0;
}

int user_record_set_fido2_user_presence_permitted(UserRecord *h, int b) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        int r;

        assert(h);

        w = sd_json_variant_ref(sd_json_variant_by_key(h->json, "secret"));

        if (b < 0)
                r = sd_json_variant_filter(&w, STRV_MAKE("fido2UserPresencePermitted"));
        else
                r = sd_json_variant_set_field_boolean(&w, "fido2UserPresencePermitted", b);
        if (r < 0)
                return r;

        if (sd_json_variant_is_blank_object(w))
                r = sd_json_variant_filter(&h->json, STRV_MAKE("secret"));
        else
                r = sd_json_variant_set_field(&h->json, "secret", w);
        if (r < 0)
                return r;

        h->fido2_user_presence_permitted = b;

        SET_FLAG(h->mask, USER_RECORD_SECRET, !sd_json_variant_is_blank_object(w));
        return 0;
}

int user_record_set_fido2_user_verification_permitted(UserRecord *h, int b) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        int r;

        assert(h);

        w = sd_json_variant_ref(sd_json_variant_by_key(h->json, "secret"));

        if (b < 0)
                r = sd_json_variant_filter(&w, STRV_MAKE("fido2UserVerificationPermitted"));
        else
                r = sd_json_variant_set_field_boolean(&w, "fido2UserVerificationPermitted", b);
        if (r < 0)
                return r;

        if (sd_json_variant_is_blank_object(w))
                r = sd_json_variant_filter(&h->json, STRV_MAKE("secret"));
        else
                r = sd_json_variant_set_field(&h->json, "secret", w);
        if (r < 0)
                return r;

        h->fido2_user_verification_permitted = b;

        SET_FLAG(h->mask, USER_RECORD_SECRET, !sd_json_variant_is_blank_object(w));
        return 0;
}

static bool per_machine_entry_empty(sd_json_variant *v) {
        const char *k;
        _unused_ sd_json_variant *e;

        JSON_VARIANT_OBJECT_FOREACH(k, e, v)
                if (!STR_IN_SET(k, "matchMachineId", "matchHostname"))
                        return false;

        return true;
}

int user_record_set_password_change_now(UserRecord *h, int b) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        sd_json_variant *per_machine;
        int r;

        assert(h);

        w = sd_json_variant_ref(h->json);

        if (b < 0)
                r = sd_json_variant_filter(&w, STRV_MAKE("passwordChangeNow"));
        else
                r = sd_json_variant_set_field_boolean(&w, "passwordChangeNow", b);
        if (r < 0)
                return r;

        /* Also drop the field from all perMachine entries */
        per_machine = sd_json_variant_by_key(w, "perMachine");
        if (per_machine) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
                sd_json_variant *e;

                JSON_VARIANT_ARRAY_FOREACH(e, per_machine) {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *z = NULL;

                        if (!sd_json_variant_is_object(e))
                                return -EINVAL;

                        z = sd_json_variant_ref(e);

                        r = sd_json_variant_filter(&z, STRV_MAKE("passwordChangeNow"));
                        if (r < 0)
                                return r;

                        if (per_machine_entry_empty(z))
                                continue;

                        r = sd_json_variant_append_array(&array, z);
                        if (r < 0)
                                return r;
                }

                if (sd_json_variant_is_blank_array(array))
                        r = sd_json_variant_filter(&w, STRV_MAKE("perMachine"));
                else
                        r = sd_json_variant_set_field(&w, "perMachine", array);
                if (r < 0)
                        return r;

                SET_FLAG(h->mask, USER_RECORD_PER_MACHINE, !sd_json_variant_is_blank_array(array));
        }

        sd_json_variant_unref(h->json);
        h->json = TAKE_PTR(w);

        h->password_change_now = b;

        return 0;
}

int user_record_merge_secret(UserRecord *h, UserRecord *secret) {
        int r;

        assert(h);
        assert(secret);

        /* Merges the secrets from 'secret' into 'h'. */

        r = user_record_set_password(h, secret->password, true);
        if (r < 0)
                return r;

        r = user_record_set_token_pin(h, secret->token_pin, true);
        if (r < 0)
                return r;

        if (secret->pkcs11_protected_authentication_path_permitted >= 0) {
                r = user_record_set_pkcs11_protected_authentication_path_permitted(
                                h,
                                secret->pkcs11_protected_authentication_path_permitted);
                if (r < 0)
                        return r;
        }

        if (secret->fido2_user_presence_permitted >= 0) {
                r = user_record_set_fido2_user_presence_permitted(
                                h,
                                secret->fido2_user_presence_permitted);
                if (r < 0)
                        return r;
        }

        if (secret->fido2_user_verification_permitted >= 0) {
                r = user_record_set_fido2_user_verification_permitted(
                                h,
                                secret->fido2_user_verification_permitted);
                if (r < 0)
                        return r;
        }

        return 0;
}

int user_record_good_authentication(UserRecord *h) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *w = NULL, *z = NULL;
        uint64_t counter, usec;
        sd_id128_t mid;
        int r;

        assert(h);

        switch (h->good_authentication_counter) {
        case UINT64_MAX:
                counter = 1;
                break;
        case UINT64_MAX-1:
                counter = h->good_authentication_counter; /* saturate */
                break;
        default:
                counter = h->good_authentication_counter + 1;
                break;
        }

        usec = now(CLOCK_REALTIME);

        r = sd_id128_get_machine(&mid);
        if (r < 0)
                return r;

        v = sd_json_variant_ref(h->json);
        w = sd_json_variant_ref(sd_json_variant_by_key(v, "status"));
        z = sd_json_variant_ref(sd_json_variant_by_key(w, SD_ID128_TO_STRING(mid)));

        r = sd_json_variant_set_field_unsigned(&z, "goodAuthenticationCounter", counter);
        if (r < 0)
                return r;

        r = sd_json_variant_set_field_unsigned(&z, "lastGoodAuthenticationUSec", usec);
        if (r < 0)
                return r;

        r = sd_json_variant_set_field(&w, SD_ID128_TO_STRING(mid), z);
        if (r < 0)
                return r;

        r = sd_json_variant_set_field(&v, "status", w);
        if (r < 0)
                return r;

        sd_json_variant_unref(h->json);
        h->json = TAKE_PTR(v);

        h->good_authentication_counter = counter;
        h->last_good_authentication_usec = usec;

        h->mask |= USER_RECORD_STATUS;
        return 0;
}

int user_record_bad_authentication(UserRecord *h) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *w = NULL, *z = NULL;
        uint64_t counter, usec;
        sd_id128_t mid;
        int r;

        assert(h);

        switch (h->bad_authentication_counter) {
        case UINT64_MAX:
                counter = 1;
                break;
        case UINT64_MAX-1:
                counter = h->bad_authentication_counter; /* saturate */
                break;
        default:
                counter = h->bad_authentication_counter + 1;
                break;
        }

        usec = now(CLOCK_REALTIME);

        r = sd_id128_get_machine(&mid);
        if (r < 0)
                return r;

        v = sd_json_variant_ref(h->json);
        w = sd_json_variant_ref(sd_json_variant_by_key(v, "status"));
        z = sd_json_variant_ref(sd_json_variant_by_key(w, SD_ID128_TO_STRING(mid)));

        r = sd_json_variant_set_field_unsigned(&z, "badAuthenticationCounter", counter);
        if (r < 0)
                return r;

        r = sd_json_variant_set_field_unsigned(&z, "lastBadAuthenticationUSec", usec);
        if (r < 0)
                return r;

        r = sd_json_variant_set_field(&w, SD_ID128_TO_STRING(mid), z);
        if (r < 0)
                return r;

        r = sd_json_variant_set_field(&v, "status", w);
        if (r < 0)
                return r;

        sd_json_variant_unref(h->json);
        h->json = TAKE_PTR(v);

        h->bad_authentication_counter = counter;
        h->last_bad_authentication_usec = usec;

        h->mask |= USER_RECORD_STATUS;
        return 0;
}

int user_record_ratelimit(UserRecord *h) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *w = NULL, *z = NULL;
        usec_t usec, new_ratelimit_begin_usec, new_ratelimit_count;
        sd_id128_t mid;
        int r;

        assert(h);

        usec = now(CLOCK_REALTIME);

        if (h->ratelimit_begin_usec != UINT64_MAX && h->ratelimit_begin_usec > usec) {
                /* Hmm, start-time is after the current time? If so, the RTC most likely doesn't work. */
                new_ratelimit_begin_usec = usec;
                new_ratelimit_count = 1;
                log_debug("Rate limit timestamp is in the future, assuming incorrect system clock, resetting limit.");
        } else if (h->ratelimit_begin_usec == UINT64_MAX ||
                 usec_add(h->ratelimit_begin_usec, user_record_ratelimit_interval_usec(h)) <= usec) {
                /* Fresh start */
                new_ratelimit_begin_usec = usec;
                new_ratelimit_count = 1;
        } else if (h->ratelimit_count < user_record_ratelimit_burst(h)) {
                /* Count up */
                new_ratelimit_begin_usec = h->ratelimit_begin_usec;
                new_ratelimit_count = h->ratelimit_count + 1;
        } else
                /* Limit hit */
                return 0;

        r = sd_id128_get_machine(&mid);
        if (r < 0)
                return r;

        v = sd_json_variant_ref(h->json);
        w = sd_json_variant_ref(sd_json_variant_by_key(v, "status"));
        z = sd_json_variant_ref(sd_json_variant_by_key(w, SD_ID128_TO_STRING(mid)));

        r = sd_json_variant_set_field_unsigned(&z, "rateLimitBeginUSec", new_ratelimit_begin_usec);
        if (r < 0)
                return r;

        r = sd_json_variant_set_field_unsigned(&z, "rateLimitCount", new_ratelimit_count);
        if (r < 0)
                return r;

        r = sd_json_variant_set_field(&w, SD_ID128_TO_STRING(mid), z);
        if (r < 0)
                return r;

        r = sd_json_variant_set_field(&v, "status", w);
        if (r < 0)
                return r;

        sd_json_variant_unref(h->json);
        h->json = TAKE_PTR(v);

        h->ratelimit_begin_usec = new_ratelimit_begin_usec;
        h->ratelimit_count = new_ratelimit_count;

        h->mask |= USER_RECORD_STATUS;
        return 1;
}

int user_record_is_supported(UserRecord *hr, sd_bus_error *error) {
        assert(hr);

        if (hr->disposition >= 0 && hr->disposition != USER_REGULAR)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Cannot manage anything but regular users.");

        if (hr->storage >= 0 && !IN_SET(hr->storage, USER_LUKS, USER_DIRECTORY, USER_SUBVOLUME, USER_FSCRYPT, USER_CIFS))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "User record has storage type this service cannot manage.");

        if (gid_is_valid(hr->gid) && hr->uid != (uid_t) hr->gid)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "User record has to have matching UID/GID fields.");

        if (hr->service && !streq(hr->service, "io.systemd.Home"))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Not accepted with service not matching io.systemd.Home.");

        if (hr->blob_directory) {
                /* This function is always called w/o binding section, so if hr->blob_dir is set then the caller set it themselves */
                assert((hr->mask & USER_RECORD_BINDING) == 0);
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Cannot manage custom blob directories.");
        }

        if (sd_json_variant_by_key(hr->json, HOMEWORK_BLOB_FDMAP_FIELD))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "User record contains unsafe internal fields.");

        return 0;
}

bool user_record_shall_rebalance(UserRecord *h) {
        assert(h);

        if (user_record_rebalance_weight(h) == REBALANCE_WEIGHT_OFF)
                return false;

        if (user_record_storage(h) != USER_LUKS)
                return false;

        if (!path_startswith(user_record_image_path(h), get_home_root())) /* This is the only pool we rebalance in */
                return false;

        return true;
}

int user_record_set_rebalance_weight(UserRecord *h, uint64_t weight) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *new_per_machine_array = NULL, *machine_id_variant = NULL,
                *machine_id_array = NULL, *per_machine_entry = NULL;
        _cleanup_free_ sd_json_variant **array = NULL;
        size_t idx = SIZE_MAX, n;
        sd_json_variant *per_machine;
        sd_id128_t mid;
        int r;

        assert(h);

        if (!h->json)
                return -EUNATCH;

        r = sd_id128_get_machine(&mid);
        if (r < 0)
                return r;

        r = sd_json_variant_new_id128(&machine_id_variant, mid);
        if (r < 0)
                return r;

        r = sd_json_variant_new_array(&machine_id_array, (sd_json_variant*[]) { machine_id_variant }, 1);
        if (r < 0)
                return r;

        per_machine = sd_json_variant_by_key(h->json, "perMachine");
        if (per_machine) {
                if (!sd_json_variant_is_array(per_machine))
                        return -EINVAL;

                n = sd_json_variant_elements(per_machine);

                array = new(sd_json_variant*, n + 1);
                if (!array)
                        return -ENOMEM;

                for (size_t i = 0; i < n; i++) {
                        sd_json_variant *m;

                        array[i] = sd_json_variant_by_index(per_machine, i);

                        if (!sd_json_variant_is_object(array[i]))
                                return -EINVAL;

                        m = sd_json_variant_by_key(array[i], "matchMachineId");
                        if (!m) {
                                /* No machineId field? Let's ignore this, but invalidate what we found so far */
                                idx = SIZE_MAX;
                                continue;
                        }

                        if (sd_json_variant_equal(m, machine_id_variant) ||
                            sd_json_variant_equal(m, machine_id_array)) {
                                /* Matches exactly what we are looking for. Let's use this */
                                idx = i;
                                continue;
                        }

                        r = per_machine_id_match(m, SD_JSON_PERMISSIVE);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                /* Also matches what we are looking for, but with a broader match. In this
                                 * case let's ignore this entry, and add a new specific one to the end. */
                                idx = SIZE_MAX;
                }

                if (idx == SIZE_MAX)
                        idx = n++; /* Nothing suitable found, place new entry at end */
                else
                        per_machine_entry = sd_json_variant_ref(array[idx]);

        } else {
                array = new(sd_json_variant*, 1);
                if (!array)
                        return -ENOMEM;

                idx = 0;
                n = 1;
        }

        if (!per_machine_entry) {
                r = sd_json_variant_set_field(&per_machine_entry, "matchMachineId", machine_id_array);
                if (r < 0)
                        return r;
        }

        if (weight == REBALANCE_WEIGHT_UNSET)
                r = sd_json_variant_set_field(&per_machine_entry, "rebalanceWeight", NULL); /* set explicitly to NULL (so that the perMachine setting we are setting here can override the global setting) */
        else
                r = sd_json_variant_set_field_unsigned(&per_machine_entry, "rebalanceWeight", weight);
        if (r < 0)
                return r;

        assert(idx < n);
        array[idx] = per_machine_entry;

        r = sd_json_variant_new_array(&new_per_machine_array, array, n);
        if (r < 0)
                return r;

        r = sd_json_variant_set_field(&h->json, "perMachine", new_per_machine_array);
        if (r < 0)
                return r;

        h->rebalance_weight = weight;
        h->mask |= USER_RECORD_PER_MACHINE;
        return 0;
}

int user_record_ensure_blob_manifest(UserRecord *h, Hashmap *blobs, const char **ret_failed) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_hashmap_free_ Hashmap *manifest = NULL;
        const char *filename;
        void *key, *value;
        uint64_t total_size = 0;
        int r;

        assert(h);
        assert(h->json);
        assert(blobs);
        assert(ret_failed);

        /* Ensures that blobManifest exists (possibly creating it using the
         * contents of blobs), and that the set of keys in both hashmaps are
         * exactly the same. If it fails to handle one blob file, the filename
         * is put it ret_failed for nicer error reporting. ret_failed is a pointer
         * to the same memory blobs uses to store its keys, so it is valid for
         * as long as blobs is valid and the corresponding key isn't removed! */

        if (h->blob_manifest) {
                /* blobManifest already exists. In this case we verify
                 * that the sets of keys are equal and that's it */

                HASHMAP_FOREACH_KEY(value, key, h->blob_manifest)
                        if (!hashmap_contains(blobs, key))
                                return -EINVAL;
                HASHMAP_FOREACH_KEY(value, key, blobs)
                        if (!hashmap_contains(h->blob_manifest, key))
                                return -EINVAL;

                return 0;
        }

        /* blobManifest doesn't exist, so we need to create it */

        HASHMAP_FOREACH_KEY(value, filename, blobs) {
                _cleanup_free_ char *filename_dup = NULL;
                _cleanup_free_ uint8_t *hash = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *hash_json = NULL;
                int fd = PTR_TO_FD(value);
                off_t initial, size;

                *ret_failed = filename;

                filename_dup = strdup(filename);
                if (!filename_dup)
                        return -ENOMEM;

                hash = malloc(SHA256_DIGEST_SIZE);
                if (!hash)
                        return -ENOMEM;

                initial = lseek(fd, 0, SEEK_CUR);
                if (initial < 0)
                        return -errno;

                r = sha256_fd(fd, BLOB_DIR_MAX_SIZE, hash);
                if (r < 0)
                        return r;

                size = lseek(fd, 0, SEEK_CUR);
                if (size < 0)
                        return -errno;
                if (!DEC_SAFE(&size, initial))
                        return -EOVERFLOW;

                if (!INC_SAFE(&total_size, size))
                        total_size = UINT64_MAX;
                if (total_size > BLOB_DIR_MAX_SIZE)
                        return -EFBIG;

                if (lseek(fd, initial, SEEK_SET) < 0)
                        return -errno;

                r = sd_json_variant_new_hex(&hash_json, hash, SHA256_DIGEST_SIZE);
                if (r < 0)
                        return r;

                r = hashmap_ensure_put(&manifest, &path_hash_ops_free_free, filename_dup, hash);
                if (r < 0)
                        return r;
                TAKE_PTR(filename_dup); /* Ownership transfers to hashmap */
                TAKE_PTR(hash);

                r = sd_json_variant_set_field(&v, filename, hash_json);
                if (r < 0)
                        return r;

                *ret_failed = NULL;
        }

        r = json_variant_set_field_non_null(&h->json, "blobManifest", v);
        if (r < 0)
                return r;

        h->blob_manifest = TAKE_PTR(manifest);
        return 0;
}
