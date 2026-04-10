/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "boot-entry.h"
#include "bootctl.h"
#include "bootspec-util.h"
#include "devnum-util.h"
#include "efi-loader.h"
#include "errno-util.h"
#include "log.h"
#include "parse-util.h"
#include "path-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

int boot_config_load_and_select(
                BootConfig *config,
                const char *root,
                const char *esp_path,
                dev_t esp_devid,
                const char *xbootldr_path,
                dev_t xbootldr_devid) {

        int r;

        /* If XBOOTLDR and ESP actually refer to the same block device, suppress XBOOTLDR, since it would
         * find the same entries twice. */
        bool same = esp_path && xbootldr_path && devnum_set_and_equal(esp_devid, xbootldr_devid);

        r = boot_config_load(config, esp_path, same ? NULL : xbootldr_path);
        if (r < 0)
                return r;

        if (!root) {
                _cleanup_strv_free_ char **efi_entries = NULL;

                r = efi_loader_get_entries(&efi_entries);
                if (r == -ENOENT || ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        log_debug_errno(r, "Boot loader reported no entries.");
                else if (r < 0)
                        log_warning_errno(r, "Failed to determine entries reported by boot loader, ignoring: %m");
                else
                        (void) boot_config_augment_from_loader(config, efi_entries, /* auto_only= */ false);
        }

        return boot_config_select_special_entries(config, /* skip_efivars= */ !!root);
}

int boot_entry_make_commit_filename(
                const char *entry_token,
                uint64_t entry_commit,
                const char *version,
                unsigned profile_nr,
                unsigned tries_left,
                char **ret) {

        assert(ret);

        /* Generate a new entry filename from the entry token, the commit number, and (optionally) the
         * image/OS version (if non-zero) the profile number, and the number of tries left. */

        if (!filename_part_is_valid(entry_token))
                return -EINVAL;
        if (!entry_commit_valid(entry_commit))
                return -EINVAL;

        _cleanup_free_ char *filename = asprintf_safe("%s-commit_%" PRIu64, entry_token, entry_commit);
        if (!filename)
                return -ENOMEM;
        if (version && !strextend(&filename, ".", version))
                return -ENOMEM;
        if (profile_nr > 0 && strextendf(&filename, "@%u", profile_nr) < 0)
                return -ENOMEM;
        if (tries_left != UINT_MAX && strextendf(&filename, "+%u", tries_left) < 0)
                return -ENOMEM;
        if (!strextend(&filename, ".conf"))
                return -ENOMEM;

        if (!filename_is_valid(filename) || string_has_cc(filename, /* ok= */ NULL) || !utf8_is_valid(filename))
                return -EINVAL;

        *ret = TAKE_PTR(filename);
        return 0;
}

int boot_entry_parse_commit_filename(
                const char *filename,
                char **ret_entry_token,
                uint64_t *ret_entry_commit) {

        int r;

        assert(filename);

        if (!filename_is_valid(filename))
                return -EINVAL;

        _cleanup_free_ char *stripped = NULL;
        r = boot_filename_extract_tries(filename, &stripped, /* ret_tries_left= */ NULL, /* ret_tries_done= */ NULL);
        if (r < 0)
                return r;

        const char *a = strrstr_no_case(stripped, "-commit_");
        if (!a)
                return -EBADMSG;

        const char *c = endswith_no_case(stripped, ".conf");
        if (!c)
                return -EBADMSG;

        assert(a < c);

        _cleanup_free_ char *entry_token = strndup(stripped, a - stripped);
        if (!entry_token)
                return -ENOMEM;

        if (!boot_entry_token_valid(entry_token))
                return -EBADMSG;

        const char *b = a + STRLEN("-commit_");
        size_t n = strspn(b, DIGITS);
        if (n <= 0 || !IN_SET(b[n], '.', '@'))
                return -EBADMSG;

        _cleanup_free_ char *entry_commit_string = strndup(b, n);
        if (!entry_commit_string)
                return -ENOMEM;

        uint64_t entry_commit;
        r = safe_atou64_full(entry_commit_string, 10, &entry_commit);
        if (r < 0)
                return r;
        if (!entry_commit_valid(entry_commit))
                return -EBADMSG;

        if (ret_entry_token)
                *ret_entry_token = TAKE_PTR(entry_token);
        if (ret_entry_commit)
                *ret_entry_commit = entry_commit;

        return 0;
}

int boot_entry_parse_commit(
                BootEntry *entry,
                char **ret_entry_token,
                uint64_t *ret_entry_commit) {

        int r;

        assert(entry);

        if (entry->type != BOOT_ENTRY_TYPE1)
                return -EADDRNOTAVAIL;

        _cleanup_free_ char *fn = NULL;
        r = path_extract_filename(entry->path, &fn);
        if (r < 0)
                return r;

        return boot_entry_parse_commit_filename(fn, ret_entry_token, ret_entry_commit);
}

int boot_config_find_oldest_commit(
                BootConfig *config,
                const char *entry_token,
                char ***ret_ids) {

        int r;

        assert(config);
        assert(entry_token);

        uint64_t commit_oldest = UINT64_MAX, commit_2nd_oldest = UINT64_MAX, commit_blocked = UINT64_MAX;

        FOREACH_ARRAY(b, config->entries, config->n_entries) {
                _cleanup_free_ char *et = NULL;
                uint64_t ec;

                r = boot_entry_parse_commit(b, &et, &ec);
                if (r == -EADDRNOTAVAIL)
                        continue;
                if (r < 0) {
                        log_debug_errno(r, "Failed to parse entry filename of '%s', ignoring: %m", strna(b->id));
                        continue;
                }

                if (!streq(et, entry_token)) /* Not ours? */
                        continue;

                if (ec < commit_oldest) {
                        commit_2nd_oldest = commit_oldest;
                        commit_oldest = ec;
                } else if (ec > commit_oldest && ec < commit_2nd_oldest)
                        commit_2nd_oldest = ec;

                if (boot_config_selected_entry(config) == b) {
                        assert(commit_blocked == UINT64_MAX);
                        commit_blocked = ec;
                        continue;
                }
        }

        uint64_t commit_picked;
        if (commit_oldest == UINT64_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(ENXIO), "No matching entry found while determining oldest entry.");
        if (commit_oldest != commit_blocked)
                commit_picked = commit_oldest;
        else {
                if (commit_2nd_oldest == UINT64_MAX)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBUSY), "Only matching entry found while determining oldest entry is current one, skipping it.");

                commit_picked = commit_2nd_oldest;
        }

        log_debug("Determined commit %" PRIu64 " to be oldest.", commit_picked);

        _cleanup_(strv_freep) char **l = NULL;
        FOREACH_ARRAY(b, config->entries, config->n_entries) {
                _cleanup_free_ char *et = NULL;
                uint64_t ec;

                r = boot_entry_parse_commit(b, &et, &ec);
                if (r < 0) {
                        log_debug_errno(r, "Failed to parse entry filename of '%s', ignoring: %m", strna(b->id));
                        continue;
                }

                if (!streq(et, entry_token)) /* Not ours? */
                        continue;

                if (ec != commit_picked)
                        continue;

                r = strv_extend(&l, b->id);
                if (r < 0)
                        return r;
        }

        assert(!strv_isempty(l));

        *ret_ids = TAKE_PTR(l);
        return 0;
}
