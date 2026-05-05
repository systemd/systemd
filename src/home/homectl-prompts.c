/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bitfield.h"
#include "chase.h"
#include "glyph-util.h"
#include "group-record.h"
#include "homectl-prompts.h"
#include "log.h"
#include "parse-util.h"
#include "prompt-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "user-util.h"
#include "userdb.h"

static int acquire_group_list(char ***ret) {
        _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;
        _cleanup_strv_free_ char **groups = NULL;
        UserDBMatch match = USERDB_MATCH_NULL;
        int r;

        assert(ret);

        match.disposition_mask = INDEXES_TO_MASK(uint64_t, USER_REGULAR, USER_SYSTEM);

        r = groupdb_all(&match, USERDB_SUPPRESS_SHADOW, &iterator);
        if (r == -ENOLINK)
                log_debug_errno(r, "No groups found. (Didn't check via Varlink.)");
        else if (r == -ESRCH)
                log_debug_errno(r, "No groups found.");
        else if (r < 0)
                return log_debug_errno(r, "Failed to enumerate groups, ignoring: %m");
        else
                for (;;) {
                        _cleanup_(group_record_unrefp) GroupRecord *gr = NULL;

                        r = groupdb_iterator_get(iterator, &match, &gr);
                        if (r == -ESRCH)
                                break;
                        if (r < 0)
                                return log_debug_errno(r, "Failed to acquire next group: %m");

                        if (group_record_disposition(gr) == USER_REGULAR) {
                                _cleanup_(user_record_unrefp) UserRecord *ur = NULL;

                                /* Filter groups here that belong to a specific user, and are named like them */

                                UserDBMatch user_match = USERDB_MATCH_NULL;
                                user_match.disposition_mask = INDEX_TO_MASK(uint64_t, USER_REGULAR);

                                r = userdb_by_name(gr->group_name, &user_match, USERDB_SUPPRESS_SHADOW, &ur);
                                if (r < 0 && r != -ESRCH)
                                        return log_debug_errno(r, "Failed to check if matching user exists for group '%s': %m", gr->group_name);

                                if (r >= 0 && user_record_gid(ur) == gr->gid)
                                        continue;
                        }

                        r = strv_extend(&groups, gr->group_name);
                        if (r < 0)
                                return log_oom();
                }

        strv_sort(groups);

        *ret = TAKE_PTR(groups);
        return !!*ret;
}

static int group_completion_callback(const char *key, GetCompletionsFlags flags, char ***ret_list, void *userdata) {
        char ***available = userdata;
        int r;

        if (!*available) {
                r = acquire_group_list(available);
                if (r < 0)
                        log_debug_errno(r, "Failed to enumerate available groups, ignoring: %m");
        }

        _cleanup_strv_free_ char **l = strv_copy(*available);
        if (!l)
                return -ENOMEM;

        if (!FLAGS_SET(flags, GET_COMPLETIONS_PRESELECT)) {
                r = strv_extend(&l, "list");
                if (r < 0)
                        return r;
        }

        *ret_list = TAKE_PTR(l);
        return 0;
}

int prompt_groups(const char *username, char ***ret_groups) {
        int r;

        assert(username);
        assert(ret_groups);

        _cleanup_strv_free_ char **available = NULL, **groups = NULL;
        for (;;) {
                strv_sort_uniq(groups);

                if (!strv_isempty(groups)) {
                        _cleanup_free_ char *j = strv_join(groups, ", ");
                        if (!j)
                                return log_oom();

                        log_info("Currently selected groups: %s", j);
                }

                _cleanup_free_ char *s = NULL;
                r = ask_string_full(
                                &s,
                                group_completion_callback,
                                &available,
                                "%s Please enter an auxiliary group for user %s (empty to continue, \"list\" to list available groups): ",
                                glyph(GLYPH_LABEL),
                                username);
                if (r < 0)
                        return log_error_errno(r, "Failed to query user for auxiliary group: %m");

                if (isempty(s))
                        break;

                if (streq(s, "list")) {
                        if (!available) {
                                r = acquire_group_list(&available);
                                if (r < 0)
                                        log_warning_errno(r, "Failed to enumerate available groups, ignoring: %m");
                                if (r == 0)
                                        log_notice("Did not find any available groups");
                                if (r <= 0)
                                        continue;
                        }

                        r = show_menu(available,
                                      /* n_columns= */ 3,
                                      /* column_width= */ 20,
                                      /* ellipsize_percentage= */ 60,
                                      /* grey_prefix= */ NULL,
                                      /* with_numbers= */ true);
                        if (r < 0)
                                return log_error_errno(r, "Failed to show menu: %m");

                        putchar('\n');
                        continue;
                };

                if (!strv_isempty(available)) {
                        unsigned u;
                        r = safe_atou(s, &u);
                        if (r >= 0) {
                                if (u <= 0 || u > strv_length(available)) {
                                        log_error("Specified entry number out of range.");
                                        continue;
                                }

                                log_info("Selected '%s'.", available[u-1]);

                                r = strv_extend(&groups, available[u-1]);
                                if (r < 0)
                                        return log_oom();

                                continue;
                        }
                }

                if (!valid_user_group_name(s, /* flags= */ 0)) {
                        log_notice("Specified group name is not a valid UNIX group name, try again: %s", s);
                        continue;
                }

                r = groupdb_by_name(s, /* match= */ NULL, USERDB_SUPPRESS_SHADOW|USERDB_EXCLUDE_DYNAMIC_USER, /* ret= */ NULL);
                if (r == -ESRCH) {
                        log_notice("Specified auxiliary group does not exist, try again: %s", s);
                        continue;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to check if specified group '%s' already exists: %m", s);

                log_info("Selected '%s'.", s);

                r = strv_extend(&groups, s);
                if (r < 0)
                        return log_oom();
        }

        *ret_groups = TAKE_PTR(groups);
        return 0;
}

static int shell_is_ok(const char *path, void *userdata) {
        int r;

        assert(path);

        if (!valid_shell(path)) {
                log_error("String '%s' is not a valid path to a shell, refusing.", path);
                return false;
        }

        r = chase_and_access(path, /* root= */ NULL, CHASE_MUST_BE_REGULAR, X_OK, /* ret_path= */ NULL);
        if (r == -ENOENT) {
                log_error_errno(r, "Shell '%s' does not exist, try again.", path);
                return false;
        }
        if (ERRNO_IS_NEG_PRIVILEGE(r)) {
                log_error_errno(r, "File '%s' is not executable, try again.", path);
                return false;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to check if shell '%s' exists and is executable: %m", path);

        return true;
}

int prompt_shell(const char *username, char **ret_shell) {
        assert(username);
        assert(ret_shell);

        _cleanup_free_ char *q = strjoin("Please enter the shell to use for user ", username);
        if (!q)
                return log_oom();

        return prompt_loop(
                        q,
                        GLYPH_SHELL,
                        /* menu= */ NULL,
                        /* accepted= */ NULL,
                        /* ellipsize_percentage= */ 0,
                        /* n_columns= */ 3,
                        /* column_width= */ 20,
                        shell_is_ok,
                        /* refresh= */ NULL,
                        /* userdata= */ NULL,
                        PROMPT_MAY_SKIP|PROMPT_SILENT_VALIDATE,
                        ret_shell);
}
