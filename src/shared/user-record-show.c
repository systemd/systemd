/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cap-list.h"
#include "format-util.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "hashmap.h"
#include "hexdecoct.h"
#include "path-util.h"
#include "percent-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "sha256.h"
#include "strv.h"
#include "terminal-util.h"
#include "user-record-show.h"
#include "user-util.h"
#include "userdb.h"

const char* user_record_state_color(const char *state) {
        if (STR_IN_SET(state, "unfixated", "absent"))
                return ansi_grey();
        else if (streq(state, "active"))
                return ansi_highlight_green();
        else if (STR_IN_SET(state, "locked", "dirty"))
                 return ansi_highlight_yellow();

        return NULL;
}

static void show_self_modifiable(
                const char *heading,
                char **field,
                const char **value) {

        assert(heading);

        /* Helper function for printing the various self_modifiable_* fields from the user record */

        if (!value)
                /* Case 1: no value is set and no default either */
                printf("%13s %snone%s\n", heading, ansi_highlight(), ansi_normal());
        else if (strv_isempty((char**) value))
                /* Case 2: the array is explicitly set to empty by the administrator */
                printf("%13s %sdisabled by administrator%s\n", heading, ansi_highlight_red(), ansi_normal());
        else if (!field)
                /* Case 3: we have values, but the field is NULL. This means that we're using the defaults.
                 * We list them anyways, because they're security-sensitive to the administrator */
                STRV_FOREACH(i, value)
                        printf("%13s %s%s%s\n", i == value ? heading : "", ansi_grey(), *i, ansi_normal());
        else
                /* Case 4: we have a list provided by the administrator */
                STRV_FOREACH(i, value)
                        printf("%13s %s\n", i == value ? heading : "", *i);
}

static void show_tmpfs_limit(const char *tmpfs, const TmpfsLimit *limit, uint32_t scale) {
        assert(tmpfs);
        assert(limit);

        if (!limit->is_set)
                return;

        printf("   %s Limit:", tmpfs);

        if (limit->limit != UINT64_MAX)
                printf(" %s", FORMAT_BYTES(limit->limit));
        if (limit->limit == UINT64_MAX || limit->limit_scale != UINT32_MAX) {
                if (limit->limit != UINT64_MAX)
                        printf(" or");

                printf(" %i%%", UINT32_SCALE_TO_PERCENT(scale));
        }
        printf("\n");
}

void user_record_show(UserRecord *hr, bool show_full_group_info) {
        _cleanup_strv_free_ char **langs = NULL;
        const char *hd, *ip, *shell;
        UserStorage storage;
        usec_t t;
        size_t k;
        int r, b;

        printf("   User name: %s\n",
               user_record_user_name_and_realm(hr));

        if (!strv_isempty(hr->aliases)) {
                STRV_FOREACH(i, hr->aliases)
                        printf(i == hr->aliases ?
                               "       Alias: %s" : ", %s", *i);
                putchar('\n');
        }

        if (hr->state) {
                const char *color;

                color = user_record_state_color(hr->state);

                printf("       State: %s%s%s\n",
                       strempty(color), hr->state, color ? ansi_normal() : "");
        }

        printf(" Disposition: %s\n", user_disposition_to_string(user_record_disposition(hr)));

        if (hr->last_change_usec != USEC_INFINITY) {
                printf(" Last Change: %s\n", FORMAT_TIMESTAMP(hr->last_change_usec));

                if (hr->last_change_usec > now(CLOCK_REALTIME))
                        printf("              %sModification time lies in the future, system clock wrong?%s\n",
                               ansi_highlight_yellow(), ansi_normal());
        }

        if (hr->last_password_change_usec != USEC_INFINITY &&
            hr->last_password_change_usec != hr->last_change_usec)
                printf(" Last Passw.: %s\n", FORMAT_TIMESTAMP(hr->last_password_change_usec));

        r = user_record_test_blocked(hr);
        switch (r) {

        case -ENOLCK:
                printf("    Login OK: %sno%s (record is locked)\n", ansi_highlight_red(), ansi_normal());
                break;

        case -EL2HLT:
                printf("    Login OK: %sno%s (record not valid yet))\n", ansi_highlight_red(), ansi_normal());
                break;

        case -EL3HLT:
                printf("    Login OK: %sno%s (record not valid anymore))\n", ansi_highlight_red(), ansi_normal());
                break;

        case -ESTALE:
        default: {
                usec_t y;

                if (r < 0 && r != -ESTALE) {
                        errno = -r;
                        printf("    Login OK: %sno%s (%m)\n", ansi_highlight_red(), ansi_normal());
                        break;
                }

                if (is_nologin_shell(user_record_shell(hr))) {
                        printf("    Login OK: %sno%s (nologin shell)\n", ansi_highlight_red(), ansi_normal());
                        break;
                }

                y = user_record_ratelimit_next_try(hr);
                if (y != USEC_INFINITY && y > now(CLOCK_REALTIME)) {
                        printf("    Login OK: %sno%s (ratelimit)\n", ansi_highlight_red(), ansi_normal());
                        break;
                }

                printf("    Login OK: %syes%s\n", ansi_highlight_green(), ansi_normal());
                break;
        }}

        r = user_record_test_password_change_required(hr);
        switch (r) {

        case -EKEYREVOKED:
                printf(" Password OK: %schange now%s\n", ansi_highlight_yellow(), ansi_normal());
                break;

        case -EOWNERDEAD:
                printf(" Password OK: %sexpired%s (change now!)\n", ansi_highlight_yellow(), ansi_normal());
                break;

        case -EKEYREJECTED:
                printf(" Password OK: %sexpired%s (for good)\n", ansi_highlight_red(), ansi_normal());
                break;

        case -EKEYEXPIRED:
                printf(" Password OK: %sexpires soon%s\n", ansi_highlight_yellow(), ansi_normal());
                break;

        case -ENETDOWN:
                printf(" Password OK: %sno timestamp%s\n", ansi_highlight_red(), ansi_normal());
                break;

        case -EROFS:
                printf(" Password OK: %schange not permitted%s\n", ansi_highlight_yellow(), ansi_normal());
                break;

        case -ESTALE:
                printf(" Password OK: %slast password change in future%s\n", ansi_highlight_yellow(), ansi_normal());
                break;

        default:
                if (r < 0) {
                        errno = -r;
                        printf(" Password OK: %sno%s (%m)\n", ansi_highlight_yellow(), ansi_normal());
                        break;
                }

                if (strv_isempty(hr->hashed_password)) {
                        if (hr->incomplete) /* Record might be incomplete, due to privs */
                                break;
                        printf(" Password OK: %sno%s (none set)\n", ansi_highlight(), ansi_normal());
                        break;
                }
                if (strv_contains(hr->hashed_password, "")) {
                        printf(" Password OK: %sno%s (empty set)\n", ansi_highlight_red(), ansi_normal());
                        break;
                }
                bool has_valid_passwords = false;
                STRV_FOREACH(p, hr->hashed_password)
                        if (!hashed_password_is_locked_or_invalid(*p)) {
                                has_valid_passwords = true;
                                break;
                        }
                if (has_valid_passwords)
                        printf(" Password OK: %syes%s\n", ansi_highlight_green(), ansi_normal());
                else
                        printf(" Password OK: %sno%s (locked)\n", ansi_highlight(), ansi_normal());
        }
        if (uid_is_valid(hr->uid))
                printf("         UID: " UID_FMT "\n", hr->uid);
        if (gid_is_valid(hr->gid)) {
                if (show_full_group_info) {
                        _cleanup_(group_record_unrefp) GroupRecord *gr = NULL;

                        r = groupdb_by_gid(hr->gid, /* match= */ NULL, /* flags= */ 0, &gr);
                        if (r < 0) {
                                errno = -r;
                                printf("         GID: " GID_FMT " (unresolvable: %m)\n", hr->gid);
                        } else
                                printf("         GID: " GID_FMT " (%s)\n", hr->gid, gr->group_name);
                } else
                        printf("         GID: " GID_FMT "\n", hr->gid);
        } else if (uid_is_valid(hr->uid)) /* Show UID as GID if not separately configured */
                printf("         GID: " GID_FMT "\n", (gid_t) hr->uid);

        if (show_full_group_info) {
                _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;

                r = membershipdb_by_user(hr->user_name, 0, &iterator);
                if (r < 0) {
                        errno = -r;
                        printf(" Aux. Groups: (can't acquire: %m)\n");
                } else {
                        const char *prefix = " Aux. Groups:";

                        for (;;) {
                                _cleanup_free_ char *group = NULL;

                                r = membershipdb_iterator_get(iterator, NULL, &group);
                                if (r == -ESRCH)
                                        break;
                                if (r < 0) {
                                        errno = -r;
                                        printf("%s (can't iterate: %m)\n", prefix);
                                        break;
                                }

                                printf("%s %s\n", prefix, group);
                                prefix = "             ";
                        }
                }
        }

        if (hr->real_name && !streq(hr->real_name, hr->user_name))
                printf("   Real Name: %s\n", hr->real_name);

        hd = user_record_home_directory(hr);
        if (hd) {
                printf("   Directory: %s", hd);

                if (hr->fallback_home_directory && hr->use_fallback)
                        printf(" %s(fallback)%s", ansi_highlight_yellow(), ansi_normal());

                printf("\n");
        }

        if (hr->blob_directory) {
                _cleanup_free_ char **filenames = NULL;
                size_t n_filenames = 0;

                r = hashmap_dump_keys_sorted(hr->blob_manifest, (void***) &filenames, &n_filenames);
                if (r < 0) {
                        errno = -r;
                        printf("   Blob Dir.: %s (can't iterate: %m)\n", hr->blob_directory);
                } else
                        printf("   Blob Dir.: %s\n", hr->blob_directory);

                for (size_t i = 0; i < n_filenames; i++) {
                        _cleanup_free_ char *path = NULL, *link = NULL, *hash = NULL;
                        const char *filename = filenames[i];
                        const uint8_t *hash_bytes = hashmap_get(hr->blob_manifest, filename);
                        bool last = i == n_filenames - 1;

                        path = path_join(hr->blob_directory, filename);
                        if (path)
                                (void) terminal_urlify_path(path, filename, &link);
                        hash = hexmem(hash_bytes, SHA256_DIGEST_SIZE);

                        printf("              %s %s %s(%s)%s\n",
                               special_glyph(last ? SPECIAL_GLYPH_TREE_RIGHT : SPECIAL_GLYPH_TREE_BRANCH),
                               link ?: filename,
                               ansi_grey(),
                               hash ?: "can't display hash",
                               ansi_normal());
                }
        }

        storage = user_record_storage(hr);
        if (storage >= 0) /* Let's be political, and clarify which storage we like, and which we don't. About CIFS we don't complain. */
                printf("     Storage: %s%s\n", user_storage_to_string(storage),
                       storage == USER_LUKS ? " (strong encryption)" :
                       storage == USER_FSCRYPT ? " (weak encryption)" :
                       IN_SET(storage, USER_DIRECTORY, USER_SUBVOLUME) ? " (no encryption)" : "");

        ip = user_record_image_path(hr);
        if (ip && !streq_ptr(ip, hd))
                printf("  Image Path: %s\n", ip);

        b = user_record_removable(hr);
        if (b >= 0)
                printf("   Removable: %s\n", yes_no(b));

        shell = user_record_shell(hr);
        if (shell) {
                printf("       Shell: %s", shell);

                if (hr->fallback_shell && hr->use_fallback)
                        printf(" %s(fallback)%s", ansi_highlight_yellow(), ansi_normal());

                printf("\n");
        }

        if (hr->email_address)
                printf("       Email: %s\n", hr->email_address);
        if (hr->location)
                printf("    Location: %s\n", hr->location);
        if (hr->password_hint)
                printf(" Passw. Hint: %s\n", hr->password_hint);
        if (hr->icon_name)
                printf("   Icon Name: %s\n", hr->icon_name);

        if (hr->time_zone)
                printf("   Time Zone: %s\n", hr->time_zone);

        r = user_record_languages(hr, &langs);
        if (r < 0) {
                errno = -r;
                printf("   Languages: (can't acquire: %m)\n");
        } else if (!strv_isempty(langs)) {
                STRV_FOREACH(i, langs)
                        printf(i == langs ? "   Languages: %s" : ", %s", *i);
                printf("\n");
        }

        if (hr->locked >= 0)
                printf("      Locked: %s\n", yes_no(hr->locked));

        if (hr->not_before_usec != UINT64_MAX)
                printf("  Not Before: %s\n", FORMAT_TIMESTAMP(hr->not_before_usec));

        if (hr->not_after_usec != UINT64_MAX)
                printf("   Not After: %s\n", FORMAT_TIMESTAMP(hr->not_after_usec));

        if (hr->umask != MODE_INVALID)
                printf("       UMask: 0%03o\n", hr->umask);

        if (nice_is_valid(hr->nice_level))
                printf("        Nice: %i\n", hr->nice_level);

        for (int j = 0; j < _RLIMIT_MAX; j++) {
                if (hr->rlimits[j])
                        printf("       Limit: RLIMIT_%s=%" PRIu64 ":%" PRIu64 "\n",
                               rlimit_to_string(j), (uint64_t) hr->rlimits[j]->rlim_cur, (uint64_t) hr->rlimits[j]->rlim_max);
        }

        if (hr->tasks_max != UINT64_MAX)
                printf("   Tasks Max: %" PRIu64 "\n", hr->tasks_max);

        if (hr->memory_high != UINT64_MAX)
                printf(" Memory High: %s\n", FORMAT_BYTES(hr->memory_high));

        if (hr->memory_max != UINT64_MAX)
                printf("  Memory Max: %s\n", FORMAT_BYTES(hr->memory_max));

        if (hr->cpu_weight == CGROUP_WEIGHT_IDLE)
                printf("  CPU Weight: %s\n", "idle");
        else if (hr->cpu_weight != UINT64_MAX)
                printf("  CPU Weight: %" PRIu64 "\n", hr->cpu_weight);

        if (hr->io_weight != UINT64_MAX)
                printf("   IO Weight: %" PRIu64 "\n", hr->io_weight);

        show_tmpfs_limit("TMP", &hr->tmp_limit, user_record_tmp_limit_scale(hr));
        show_tmpfs_limit("SHM", &hr->dev_shm_limit, user_record_dev_shm_limit_scale(hr));

        if (hr->access_mode != MODE_INVALID)
                printf(" Access Mode: 0%03o\n", user_record_access_mode(hr));

        uint64_t caps = user_record_capability_bounding_set(hr);
        if (caps != UINT64_MAX) {
                _cleanup_free_ char *scaps = NULL;

                (void) capability_set_to_string_negative(caps, &scaps);
                printf(" Bound. Caps: %s\n", strna(scaps));
        }

        caps = user_record_capability_ambient_set(hr);
        if (caps != UINT64_MAX) {
                _cleanup_free_ char *scaps = NULL;

                (void) capability_set_to_string(caps, &scaps);
                printf("Ambient Caps: %s\n", strna(scaps));
        }

        if (storage == USER_LUKS) {
                printf("LUKS Discard: online=%s offline=%s\n", yes_no(user_record_luks_discard(hr)), yes_no(user_record_luks_offline_discard(hr)));

                if (!sd_id128_is_null(hr->luks_uuid))
                        printf("   LUKS UUID: " SD_ID128_UUID_FORMAT_STR "\n", SD_ID128_FORMAT_VAL(hr->luks_uuid));
                if (!sd_id128_is_null(hr->partition_uuid))
                        printf("   Part UUID: " SD_ID128_UUID_FORMAT_STR "\n", SD_ID128_FORMAT_VAL(hr->partition_uuid));
                if (!sd_id128_is_null(hr->file_system_uuid))
                        printf("     FS UUID: " SD_ID128_UUID_FORMAT_STR "\n", SD_ID128_FORMAT_VAL(hr->file_system_uuid));

                if (hr->file_system_type)
                        printf(" File System: %s\n", user_record_file_system_type(hr));

                if (hr->luks_extra_mount_options)
                        printf("LUKS MntOpts: %s\n", hr->luks_extra_mount_options);

                if (hr->luks_cipher)
                        printf(" LUKS Cipher: %s\n", hr->luks_cipher);
                if (hr->luks_cipher_mode)
                        printf(" Cipher Mode: %s\n", hr->luks_cipher_mode);
                if (hr->luks_volume_key_size != UINT64_MAX)
                        printf("  Volume Key: %" PRIu64 "bit\n", hr->luks_volume_key_size * 8);

                if (hr->luks_pbkdf_type)
                        printf("  PBKDF Type: %s\n", hr->luks_pbkdf_type);
                if (hr->luks_pbkdf_hash_algorithm)
                        printf("  PBKDF Hash: %s\n", hr->luks_pbkdf_hash_algorithm);
                if (hr->luks_pbkdf_force_iterations != UINT64_MAX)
                        printf(" PBKDF Iters: %" PRIu64 "\n", hr->luks_pbkdf_force_iterations);
                if (hr->luks_pbkdf_time_cost_usec != UINT64_MAX)
                        printf("  PBKDF Time: %s\n", FORMAT_TIMESPAN(hr->luks_pbkdf_time_cost_usec, 0));
                if (hr->luks_pbkdf_memory_cost != UINT64_MAX)
                        printf(" PBKDF Bytes: %s\n", FORMAT_BYTES(hr->luks_pbkdf_memory_cost));

                if (hr->luks_pbkdf_parallel_threads != UINT64_MAX)
                        printf("PBKDF Thread: %" PRIu64 "\n", hr->luks_pbkdf_parallel_threads);
                if (hr->luks_sector_size != UINT64_MAX)
                        printf(" Sector Size: %" PRIu64 "\n", hr->luks_sector_size);

        } else if (storage == USER_CIFS) {

                if (hr->cifs_service)
                        printf("CIFS Service: %s\n", hr->cifs_service);

                if (hr->cifs_extra_mount_options)
                        printf("CIFS MntOpts: %s\n", hr->cifs_extra_mount_options);
        }

        if (hr->cifs_user_name)
                printf("   CIFS User: %s\n", user_record_cifs_user_name(hr));
        if (hr->cifs_domain)
                printf(" CIFS Domain: %s\n", hr->cifs_domain);

        if (storage != USER_CLASSIC)
                printf(" Mount Flags: %s %s %s\n",
                       hr->nosuid ? "nosuid" : "suid",
                       hr->nodev ? "nodev" : "dev",
                       hr->noexec ? "noexec" : "exec");

        if (hr->skeleton_directory)
                printf("  Skel. Dir.: %s\n", user_record_skeleton_directory(hr));

        if (hr->disk_size != UINT64_MAX)
                printf("   Disk Size: %s\n", FORMAT_BYTES(hr->disk_size));

        if (hr->disk_usage != UINT64_MAX) {
                if (hr->disk_size != UINT64_MAX) {
                        unsigned permille;

                        permille = (unsigned) DIV_ROUND_UP(hr->disk_usage * 1000U, hr->disk_size); /* Round up! */
                        printf("  Disk Usage: %s (= %u.%01u%%)\n",
                               FORMAT_BYTES(hr->disk_usage),
                               permille / 10, permille % 10);
                } else
                        printf("  Disk Usage: %s\n", FORMAT_BYTES(hr->disk_usage));
        }

        if (hr->disk_free != UINT64_MAX) {
                if (hr->disk_size != UINT64_MAX) {
                        const char *color_on, *color_off;
                        unsigned permille;

                        permille = (unsigned) ((hr->disk_free * 1000U) / hr->disk_size); /* Round down! */

                        /* Color the output red or yellow if we are below 10% resp. 25% free. Because 10% and
                         * 25% can be a lot of space still, let's additionally make some absolute
                         * restrictions: 1G and 2G */
                        if (permille <= 100U &&
                            hr->disk_free < 1024U*1024U*1024U /* 1G */) {
                                color_on = ansi_highlight_red();
                                color_off = ansi_normal();
                        } else if (permille <= 250U &&
                                   hr->disk_free < 2U*1024U*1024U*1024U /* 2G */) {
                                color_on = ansi_highlight_yellow();
                                color_off = ansi_normal();
                        } else
                                color_on = color_off = "";

                        printf("   Disk Free: %s%s (= %u.%01u%%)%s\n",
                               color_on,
                               FORMAT_BYTES(hr->disk_free),
                               permille / 10, permille % 10,
                               color_off);
                } else
                        printf("   Disk Free: %s\n", FORMAT_BYTES(hr->disk_free));
        }

        if (hr->disk_floor != UINT64_MAX)
                printf("  Disk Floor: %s\n", FORMAT_BYTES(hr->disk_floor));

        if (hr->disk_ceiling != UINT64_MAX)
                printf("Disk Ceiling: %s\n", FORMAT_BYTES(hr->disk_ceiling));

        if (hr->good_authentication_counter != UINT64_MAX)
                printf("  Good Auth.: %" PRIu64 "\n", hr->good_authentication_counter);

        if (hr->last_good_authentication_usec != UINT64_MAX)
                printf("   Last Good: %s\n", FORMAT_TIMESTAMP(hr->last_good_authentication_usec));

        if (hr->bad_authentication_counter != UINT64_MAX)
                printf("   Bad Auth.: %" PRIu64 "\n", hr->bad_authentication_counter);

        if (hr->last_bad_authentication_usec != UINT64_MAX)
                printf("    Last Bad: %s\n", FORMAT_TIMESTAMP(hr->last_bad_authentication_usec));

        t = user_record_ratelimit_next_try(hr);
        if (t != USEC_INFINITY) {
                usec_t n = now(CLOCK_REALTIME);

                if (t <= n)
                        printf("    Next Try: anytime\n");
                else
                        printf("    Next Try: %sin %s%s\n",
                               ansi_highlight_red(),
                               FORMAT_TIMESPAN(t - n, USEC_PER_SEC),
                               ansi_normal());
        }

        if (storage != USER_CLASSIC)
                printf(" Auth. Limit: %" PRIu64 " attempts per %s\n", user_record_ratelimit_burst(hr),
                       FORMAT_TIMESPAN(user_record_ratelimit_interval_usec(hr), 0));

        if (hr->enforce_password_policy >= 0)
                printf(" Passwd Pol.: %s\n", yes_no(hr->enforce_password_policy));

        if (hr->password_change_min_usec != UINT64_MAX ||
            hr->password_change_max_usec != UINT64_MAX ||
            hr->password_change_warn_usec != UINT64_MAX ||
            hr->password_change_inactive_usec != UINT64_MAX) {

                printf(" Passwd Chg.:");

                if (hr->password_change_min_usec != UINT64_MAX) {
                        printf(" min %s", FORMAT_TIMESPAN(hr->password_change_min_usec, 0));

                        if (hr->password_change_max_usec != UINT64_MAX)
                                printf(" …");
                }

                if (hr->password_change_max_usec != UINT64_MAX)
                        printf(" max %s", FORMAT_TIMESPAN(hr->password_change_max_usec, 0));

                if (hr->password_change_warn_usec != UINT64_MAX)
                        printf("/warn %s", FORMAT_TIMESPAN(hr->password_change_warn_usec, 0));

                if (hr->password_change_inactive_usec != UINT64_MAX)
                        printf("/inactive %s", FORMAT_TIMESPAN(hr->password_change_inactive_usec, 0));

                printf("\n");
        }

        if (hr->password_change_now >= 0)
                printf("Pas. Ch. Now: %s\n", yes_no(hr->password_change_now));

        if (hr->drop_caches >= 0 || user_record_drop_caches(hr))
                printf(" Drop Caches: %s\n", yes_no(user_record_drop_caches(hr)));

        if (hr->auto_resize_mode >= 0)
                printf(" Auto Resize: %s\n", auto_resize_mode_to_string(user_record_auto_resize_mode(hr)));

        if (hr->rebalance_weight != REBALANCE_WEIGHT_UNSET) {
                uint64_t rb;

                rb = user_record_rebalance_weight(hr);
                if (rb == REBALANCE_WEIGHT_OFF)
                        printf("   Rebalance: off\n");
                else
                        printf("   Rebalance: weight %" PRIu64 "\n", rb);
        }

        if (!strv_isempty(hr->ssh_authorized_keys))
                printf("SSH Pub. Key: %zu\n", strv_length(hr->ssh_authorized_keys));

        if (!strv_isempty(hr->pkcs11_token_uri))
                STRV_FOREACH(i, hr->pkcs11_token_uri)
                        printf(i == hr->pkcs11_token_uri ?
                               "PKCS11 Token: %s\n" :
                               "              %s\n", *i);

        if (hr->n_fido2_hmac_credential > 0)
                printf(" FIDO2 Token: %zu\n", hr->n_fido2_hmac_credential);

        if (!strv_isempty(hr->recovery_key_type))
                printf("Recovery Key: %zu\n", strv_length(hr->recovery_key_type));

        k = strv_length(hr->hashed_password);
        if (k == 0)
                printf("   Passwords: %snone%s\n",
                       user_record_disposition(hr) == USER_REGULAR ? ansi_highlight_yellow() : ansi_normal(), ansi_normal());
        else
                printf("   Passwords: %zu\n", k);

        if (hr->signed_locally >= 0)
                printf("  Local Sig.: %s\n", yes_no(hr->signed_locally));

        if (hr->stop_delay_usec != UINT64_MAX)
                printf("  Stop Delay: %s\n", FORMAT_TIMESPAN(hr->stop_delay_usec, 0));

        if (hr->auto_login >= 0)
                printf("Autom. Login: %s\n", yes_no(hr->auto_login));

        if (hr->preferred_session_launcher)
                printf("Sess. Launch: %s\n", hr->preferred_session_launcher);
        if (hr->preferred_session_type)
                printf("Session Type: %s\n", hr->preferred_session_type);

        if (hr->kill_processes >= 0)
                printf("  Kill Proc.: %s\n", yes_no(hr->kill_processes));

        if (hr->service)
                printf("     Service: %s\n", hr->service);

        show_self_modifiable("Self Modify:",
                             hr->self_modifiable_fields,
                             user_record_self_modifiable_fields(hr));
        show_self_modifiable("(Blobs)",
                             hr->self_modifiable_blobs,
                             user_record_self_modifiable_blobs(hr));
        show_self_modifiable("(Privileged)",
                             hr->self_modifiable_privileged,
                             user_record_self_modifiable_privileged(hr));
}

void group_record_show(GroupRecord *gr, bool show_full_user_info) {
        int r;

        printf("  Group name: %s\n",
               group_record_group_name_and_realm(gr));

        printf(" Disposition: %s\n", user_disposition_to_string(group_record_disposition(gr)));

        if (gr->last_change_usec != USEC_INFINITY)
                printf(" Last Change: %s\n", FORMAT_TIMESTAMP(gr->last_change_usec));

        if (gid_is_valid(gr->gid))
                printf("         GID: " GID_FMT "\n", gr->gid);

        if (show_full_user_info) {
                _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;

                r = membershipdb_by_group(gr->group_name, 0, &iterator);
                if (r < 0) {
                        errno = -r;
                        printf("     Members: (can't acquire: %m)");
                } else {
                        const char *prefix = "     Members:";

                        for (;;) {
                                _cleanup_free_ char *user = NULL;

                                r = membershipdb_iterator_get(iterator, &user, NULL);
                                if (r == -ESRCH)
                                        break;
                                if (r < 0) {
                                        errno = -r;
                                        printf("%s (can't iterate: %m\n", prefix);
                                        break;
                                }

                                printf("%s %s\n", prefix, user);
                                prefix = "             ";
                        }
                }
        } else {
                const char *prefix = "     Members:";

                STRV_FOREACH(i, gr->members) {
                        printf("%s %s\n", prefix, *i);
                        prefix = "             ";
                }
        }

        if (!strv_isempty(gr->administrators)) {
                const char *prefix = "      Admins:";

                STRV_FOREACH(i, gr->administrators) {
                        printf("%s %s\n", prefix, *i);
                        prefix = "             ";
                }
        }

        if (gr->description && !streq(gr->description, gr->group_name))
                printf(" Description: %s\n", gr->description);

        if (!strv_isempty(gr->hashed_password))
                printf("   Passwords: %zu\n", strv_length(gr->hashed_password));

        if (gr->service)
                printf("     Service: %s\n", gr->service);
}
