/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "bitfield.h"
#include "build.h"
#include "dirent-util.h"
#include "errno-list.h"
#include "escape.h"
#include "fd-util.h"
#include "format-table.h"
#include "format-util.h"
#include "main-func.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "socket-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "uid-classification.h"
#include "uid-range.h"
#include "user-record-show.h"
#include "user-util.h"
#include "userdb.h"
#include "verbs.h"
#include "virt.h"

static enum {
        OUTPUT_CLASSIC,
        OUTPUT_TABLE,
        OUTPUT_FRIENDLY,
        OUTPUT_JSON,
        _OUTPUT_INVALID = -EINVAL,
} arg_output = _OUTPUT_INVALID;

static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static char** arg_services = NULL;
static UserDBFlags arg_userdb_flags = 0;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
static bool arg_chain = false;
static uint64_t arg_disposition_mask = UINT64_MAX;
static uid_t arg_uid_min = 0;
static uid_t arg_uid_max = UID_INVALID-1;
static bool arg_fuzzy = false;
static bool arg_boundaries = true;

STATIC_DESTRUCTOR_REGISTER(arg_services, strv_freep);

static const char *user_disposition_to_color(UserDisposition d) {
        assert(d >= 0);
        assert(d < _USER_DISPOSITION_MAX);

        switch (d) {
        case USER_INTRINSIC:
                return ansi_red();

        case USER_SYSTEM:
        case USER_DYNAMIC:
                return ansi_green();

        case USER_CONTAINER:
        case USER_FOREIGN:
                return ansi_cyan();

        case USER_RESERVED:
                return ansi_red();

        default:
                return NULL;
        }
}

static const char* shell_to_color(const char *shell) {
        return !shell || is_nologin_shell(shell) ? ansi_grey() : NULL;
}

static int show_user(UserRecord *ur, Table *table) {
        int r;

        assert(ur);

        switch (arg_output) {

        case OUTPUT_CLASSIC:
                if (!uid_is_valid(ur->uid))
                        break;

                printf("%s:x:" UID_FMT ":" GID_FMT ":%s:%s:%s\n",
                       ur->user_name,
                       ur->uid,
                       user_record_gid(ur),
                       strempty(user_record_real_name(ur)),
                       user_record_home_directory(ur),
                       user_record_shell(ur));

                break;

        case OUTPUT_JSON:
                sd_json_variant_dump(ur->json, arg_json_format_flags, NULL, NULL);
                break;

        case OUTPUT_FRIENDLY:
                user_record_show(ur, true);

                if (ur->incomplete) {
                        fflush(stdout);
                        log_warning("Warning: lacking rights to acquire privileged fields of user record of '%s', output incomplete.", ur->user_name);
                }

                break;

        case OUTPUT_TABLE: {
                assert(table);
                UserDisposition d = user_record_disposition(ur);
                const char *sh = user_record_shell(ur);

                r = table_add_many(
                                table,
                                TABLE_STRING, "",
                                TABLE_STRING, ur->user_name,
                                TABLE_SET_COLOR, user_disposition_to_color(d),
                                TABLE_STRING, user_disposition_to_string(d),
                                TABLE_UID, ur->uid,
                                TABLE_GID, user_record_gid(ur),
                                TABLE_STRING, empty_to_null(ur->real_name),
                                TABLE_PATH, user_record_home_directory(ur),
                                TABLE_PATH, sh,
                                TABLE_SET_COLOR, shell_to_color(sh),
                                TABLE_INT, 0);
                if (r < 0)
                        return table_log_add_error(r);

                break;
        }

        default:
                assert_not_reached();
        }

        return 0;
}

static bool test_show_mapped(void) {
        /* Show mapped user range only in environments where user mapping is a thing. */
        return running_in_userns() > 0;
}

static const struct {
        uid_t first, last;
        const char *name;
        UserDisposition disposition;
        bool (*test)(void);
} uid_range_table[] = {
        {
                .first = 1,
                .last = SYSTEM_UID_MAX,
                .name = "system",
                .disposition = USER_SYSTEM,
        },
        {
                .first = DYNAMIC_UID_MIN,
                .last = DYNAMIC_UID_MAX,
                .name = "dynamic system",
                .disposition = USER_DYNAMIC,
        },
        {
                .first = CONTAINER_UID_MIN,
                .last = CONTAINER_UID_MAX,
                .name = "container",
                .disposition = USER_CONTAINER,
        },
        {
                .first = FOREIGN_UID_MIN,
                .last = FOREIGN_UID_MAX,
                .name = "foreign",
                .disposition = USER_FOREIGN,
        },
#if ENABLE_HOMED
        {
                .first = HOME_UID_MIN,
                .last = HOME_UID_MAX,
                .name = "systemd-homed",
                .disposition = USER_REGULAR,
        },
#endif
        {
                .first = MAP_UID_MIN,
                .last = MAP_UID_MAX,
                .name = "mapped",
                .disposition = USER_REGULAR,
                .test = test_show_mapped,
        },
};

static int table_add_uid_boundaries(Table *table, const UIDRange *p) {
        int r, n_added = 0;

        assert(table);

        FOREACH_ELEMENT(i, uid_range_table) {
                _cleanup_free_ char *name = NULL, *comment = NULL;

                if (!BIT_SET(arg_disposition_mask, i->disposition))
                        continue;

                if (!uid_range_covers(p, i->first, i->last - i->first + 1))
                        continue;

                if (i->test && !i->test())
                        continue;

                name = strjoin(special_glyph(SPECIAL_GLYPH_ARROW_DOWN),
                               " begin ", i->name, " users ",
                               special_glyph(SPECIAL_GLYPH_ARROW_DOWN));
                if (!name)
                        return log_oom();

                comment = strjoin("First ", i->name, " user");
                if (!comment)
                        return log_oom();

                r = table_add_many(
                                table,
                                TABLE_STRING, special_glyph(SPECIAL_GLYPH_TREE_TOP),
                                TABLE_STRING, name,
                                TABLE_SET_COLOR, ansi_grey(),
                                TABLE_STRING, user_disposition_to_string(i->disposition),
                                TABLE_SET_COLOR, ansi_grey(),
                                TABLE_UID, i->first,
                                TABLE_SET_COLOR, ansi_grey(),
                                TABLE_EMPTY,
                                TABLE_STRING, comment,
                                TABLE_SET_COLOR, ansi_grey(),
                                TABLE_EMPTY,
                                TABLE_EMPTY,
                                TABLE_INT, -1); /* sort before any other entry with the same UID */
                if (r < 0)
                        return table_log_add_error(r);

                free(name);
                name = strjoin(special_glyph(SPECIAL_GLYPH_ARROW_UP),
                               " end ", i->name, " users ",
                               special_glyph(SPECIAL_GLYPH_ARROW_UP));
                if (!name)
                        return log_oom();

                free(comment);
                comment = strjoin("Last ", i->name, " user");
                if (!comment)
                        return log_oom();

                r = table_add_many(
                                table,
                                TABLE_STRING, special_glyph(SPECIAL_GLYPH_TREE_RIGHT),
                                TABLE_STRING, name,
                                TABLE_SET_COLOR, ansi_grey(),
                                TABLE_STRING, user_disposition_to_string(i->disposition),
                                TABLE_SET_COLOR, ansi_grey(),
                                TABLE_UID, i->last,
                                TABLE_SET_COLOR, ansi_grey(),
                                TABLE_EMPTY,
                                TABLE_STRING, comment,
                                TABLE_SET_COLOR, ansi_grey(),
                                TABLE_EMPTY,
                                TABLE_EMPTY,
                                TABLE_INT, 1); /* sort after any other entry with the same UID */
                if (r < 0)
                        return table_log_add_error(r);

                n_added += 2;
        }

        return n_added;
}

static int add_unavailable_uid(Table *table, uid_t start, uid_t end) {
        _cleanup_free_ char *name = NULL;
        int r;

        assert(table);
        assert(start <= end);

        name = strjoin(special_glyph(SPECIAL_GLYPH_ARROW_DOWN),
                       " begin unavailable users ",
                       special_glyph(SPECIAL_GLYPH_ARROW_DOWN));
        if (!name)
                return log_oom();

        r = table_add_many(
                        table,
                        TABLE_STRING, special_glyph(SPECIAL_GLYPH_TREE_TOP),
                        TABLE_STRING, name,
                        TABLE_SET_COLOR, ansi_grey(),
                        TABLE_EMPTY,
                        TABLE_UID, start,
                        TABLE_SET_COLOR, ansi_grey(),
                        TABLE_EMPTY,
                        TABLE_STRING, "First unavailable user",
                        TABLE_SET_COLOR, ansi_grey(),
                        TABLE_EMPTY,
                        TABLE_EMPTY,
                        TABLE_INT, -1); /* sort before an other entry with the same UID */
        if (r < 0)
                return table_log_add_error(r);

        free(name);
        name = strjoin(special_glyph(SPECIAL_GLYPH_ARROW_UP),
                       " end unavailable users ",
                       special_glyph(SPECIAL_GLYPH_ARROW_UP));
        if (!name)
                return log_oom();

        r = table_add_many(
                        table,
                        TABLE_STRING, special_glyph(SPECIAL_GLYPH_TREE_RIGHT),
                        TABLE_STRING, name,
                        TABLE_SET_COLOR, ansi_grey(),
                        TABLE_EMPTY,
                        TABLE_UID, end,
                        TABLE_SET_COLOR, ansi_grey(),
                        TABLE_EMPTY,
                        TABLE_STRING, "Last unavailable user",
                        TABLE_SET_COLOR, ansi_grey(),
                        TABLE_EMPTY,
                        TABLE_EMPTY,
                        TABLE_INT, 1); /* sort after any other entry with the same UID */
        if (r < 0)
                return table_log_add_error(r);

        return 2;
}

static int table_add_uid_map(
                Table *table,
                const UIDRange *p,
                int (*add_unavailable)(Table *t, uid_t start, uid_t end)) {

        uid_t focus = 0;
        int n_added = 0, r;

        assert(table);
        assert(add_unavailable);

        if (!p)
                return 0;

        FOREACH_ARRAY(x, p->entries, p->n_entries) {
                if (focus < x->start) {
                        r = add_unavailable(table, focus, x->start-1);
                        if (r < 0)
                                return r;

                        n_added += r;
                }

                if (x->start > UINT32_MAX - x->nr) { /* overflow check */
                        focus = UINT32_MAX;
                        break;
                }

                focus = x->start + x->nr;
        }

        if (focus < UINT32_MAX-1) {
                r = add_unavailable(table, focus, UINT32_MAX-1);
                if (r < 0)
                        return r;

                n_added += r;
        }

        return n_added;
}

static int display_user(int argc, char *argv[], void *userdata) {
        _cleanup_(table_unrefp) Table *table = NULL;
        bool draw_separator = false;
        int ret = 0, r;

        if (arg_output < 0)
                arg_output = argc > 1 && !arg_fuzzy ? OUTPUT_FRIENDLY : OUTPUT_TABLE;

        if (arg_output == OUTPUT_TABLE) {
                table = table_new(" ", "name", "disposition", "uid", "gid", "realname", "home", "shell", "order");
                if (!table)
                        return log_oom();

                (void) table_set_align_percent(table, table_get_cell(table, 0, 3), 100);
                (void) table_set_align_percent(table, table_get_cell(table, 0, 4), 100);
                table_set_ersatz_string(table, TABLE_ERSATZ_DASH);
                (void) table_set_sort(table, (size_t) 3, (size_t) 8);
                (void) table_hide_column_from_display(table, (size_t) 8);
                if (!arg_boundaries)
                        (void) table_hide_column_from_display(table, (size_t) 0);
        }

        _cleanup_(userdb_match_done) UserDBMatch match = {
                .disposition_mask = arg_disposition_mask,
                .uid_min = arg_uid_min,
                .uid_max = arg_uid_max,
        };

        if (argc > 1 && !arg_fuzzy)
                STRV_FOREACH(i, argv + 1) {
                        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;

                        r = userdb_by_name(*i, &match, arg_userdb_flags|USERDB_PARSE_NUMERIC, &ur);
                        if (r < 0) {
                                if (r == -ESRCH)
                                        log_error_errno(r, "User %s does not exist.", *i);
                                else if (r == -EHOSTDOWN)
                                        log_error_errno(r, "Selected user database service is not available for this request.");
                                else if (r == -ENOEXEC)
                                        log_error_errno(r, "User '%s' exists but does not match specified filter.", *i);
                                else
                                        log_error_errno(r, "Failed to find user %s: %m", *i);

                                RET_GATHER(ret, r);
                        } else {
                                if (draw_separator && arg_output == OUTPUT_FRIENDLY)
                                        putchar('\n');

                                r = show_user(ur, table);
                                if (r < 0)
                                        return r;

                                draw_separator = true;
                        }
                }
        else {
                if (argc > 1) {
                        /* If there are further arguments, they are the fuzzy match strings. */
                        match.fuzzy_names = strv_copy(strv_skip(argv, 1));
                        if (!match.fuzzy_names)
                                return log_oom();
                }

                _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;
                r = userdb_all(&match, arg_userdb_flags, &iterator);
                if (r == -ENOLINK) /* ENOLINK → Didn't find answer without Varlink, and didn't try Varlink because was configured to off. */
                        log_debug_errno(r, "No entries found. (Didn't check via Varlink.)");
                else if (r == -ESRCH) /* ESRCH → Couldn't find any suitable entry, but we checked all sources */
                        log_debug_errno(r, "No entries found.");
                else if (r < 0)
                        return log_error_errno(r, "Failed to enumerate users: %m");
                else {
                        for (;;) {
                                _cleanup_(user_record_unrefp) UserRecord *ur = NULL;

                                r = userdb_iterator_get(iterator, &match, &ur);
                                if (r == -ESRCH)
                                        break;
                                if (r == -EHOSTDOWN)
                                        return log_error_errno(r, "Selected user database service is not available for this request.");
                                if (r < 0)
                                        return log_error_errno(r, "Failed acquire next user: %m");

                                if (draw_separator && arg_output == OUTPUT_FRIENDLY)
                                        putchar('\n');

                                r = show_user(ur, table);
                                if (r < 0)
                                        return r;

                                draw_separator = true;
                        }
                }
        }

        if (table) {
                int boundary_lines = 0, uid_map_lines = 0;

                if (arg_boundaries) {
                        _cleanup_(uid_range_freep) UIDRange *uid_range = NULL;

                        r = uid_range_load_userns(/* path = */ NULL, UID_RANGE_USERNS_INSIDE, &uid_range);
                        if (r < 0)
                                log_debug_errno(r, "Failed to load /proc/self/uid_map, ignoring: %m");

                        boundary_lines = table_add_uid_boundaries(table, uid_range);
                        if (boundary_lines < 0)
                                return boundary_lines;

                        uid_map_lines = table_add_uid_map(table, uid_range, add_unavailable_uid);
                        if (uid_map_lines < 0)
                                return uid_map_lines;
                }

                if (!table_isempty(table)) {
                        r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, arg_legend);
                        if (r < 0)
                                return table_log_print_error(r);
                }

                if (arg_legend) {
                        size_t k;

                        k = table_get_rows(table) - 1 - boundary_lines - uid_map_lines;
                        if (k > 0)
                                printf("\n%zu users listed.\n", k);
                        else
                                printf("No users.\n");
                }
        }

        return ret;
}

static int show_group(GroupRecord *gr, Table *table) {
        int r;

        assert(gr);

        switch (arg_output) {

        case OUTPUT_CLASSIC: {
                _cleanup_free_ char *m = NULL;

                if (!gid_is_valid(gr->gid))
                        break;

                m = strv_join(gr->members, ",");
                if (!m)
                        return log_oom();

                printf("%s:x:" GID_FMT ":%s\n",
                       gr->group_name,
                       gr->gid,
                       m);
                break;
        }

        case OUTPUT_JSON:
                sd_json_variant_dump(gr->json, arg_json_format_flags, NULL, NULL);
                break;

        case OUTPUT_FRIENDLY:
                group_record_show(gr, true);

                if (gr->incomplete) {
                        fflush(stdout);
                        log_warning("Warning: lacking rights to acquire privileged fields of group record of '%s', output incomplete.", gr->group_name);
                }

                break;

        case OUTPUT_TABLE: {
                UserDisposition d;

                assert(table);
                d = group_record_disposition(gr);

                r = table_add_many(
                                table,
                                TABLE_STRING, "",
                                TABLE_STRING, gr->group_name,
                                TABLE_SET_COLOR, user_disposition_to_color(d),
                                TABLE_STRING, user_disposition_to_string(d),
                                TABLE_GID, gr->gid,
                                TABLE_STRING, gr->description,
                                TABLE_INT, 0);
                if (r < 0)
                        return table_log_add_error(r);

                break;
        }

        default:
                assert_not_reached();
        }

        return 0;
}

static int table_add_gid_boundaries(Table *table, const UIDRange *p) {
        int r, n_added = 0;

        assert(table);

        FOREACH_ELEMENT(i, uid_range_table) {
                _cleanup_free_ char *name = NULL, *comment = NULL;

                if (!BIT_SET(arg_disposition_mask, i->disposition))
                        continue;

                if (!uid_range_covers(p, i->first, i->last - i->first + 1))
                        continue;

                if (i->test && !i->test())
                        continue;

                name = strjoin(special_glyph(SPECIAL_GLYPH_ARROW_DOWN),
                               " begin ", i->name, " groups ",
                               special_glyph(SPECIAL_GLYPH_ARROW_DOWN));
                if (!name)
                        return log_oom();

                comment = strjoin("First ", i->name, " group");
                if (!comment)
                        return log_oom();

                r = table_add_many(
                                table,
                                TABLE_STRING, special_glyph(SPECIAL_GLYPH_TREE_TOP),
                                TABLE_STRING, name,
                                TABLE_SET_COLOR, ansi_grey(),
                                TABLE_STRING, user_disposition_to_string(i->disposition),
                                TABLE_SET_COLOR, ansi_grey(),
                                TABLE_GID, i->first,
                                TABLE_SET_COLOR, ansi_grey(),
                                TABLE_STRING, comment,
                                TABLE_SET_COLOR, ansi_grey(),
                                TABLE_INT, -1); /* sort before any other entry with the same GID */
                if (r < 0)
                        return table_log_add_error(r);

                free(name);
                name = strjoin(special_glyph(SPECIAL_GLYPH_ARROW_UP),
                               " end ", i->name, " groups ",
                               special_glyph(SPECIAL_GLYPH_ARROW_UP));
                if (!name)
                        return log_oom();

                free(comment);
                comment = strjoin("Last ", i->name, " group");
                if (!comment)
                        return log_oom();

                r = table_add_many(
                                table,
                                TABLE_STRING, special_glyph(SPECIAL_GLYPH_TREE_RIGHT),
                                TABLE_STRING, name,
                                TABLE_SET_COLOR, ansi_grey(),
                                TABLE_STRING, user_disposition_to_string(i->disposition),
                                TABLE_SET_COLOR, ansi_grey(),
                                TABLE_GID, i->last,
                                TABLE_SET_COLOR, ansi_grey(),
                                TABLE_STRING, comment,
                                TABLE_SET_COLOR, ansi_grey(),
                                TABLE_INT, 1); /* sort after any other entry with the same GID */
                if (r < 0)
                        return table_log_add_error(r);

                n_added += 2;
        }

        return n_added;
}

static int add_unavailable_gid(Table *table, uid_t start, uid_t end) {
        _cleanup_free_ char *name = NULL;
        int r;

        assert(table);
        assert(start <= end);

        name = strjoin(special_glyph(SPECIAL_GLYPH_ARROW_DOWN),
                       " begin unavailable groups ",
                       special_glyph(SPECIAL_GLYPH_ARROW_DOWN));
        if (!name)
                return log_oom();

        r = table_add_many(
                        table,
                        TABLE_STRING, special_glyph(SPECIAL_GLYPH_TREE_TOP),
                        TABLE_STRING, name,
                        TABLE_SET_COLOR, ansi_grey(),
                        TABLE_EMPTY,
                        TABLE_GID, start,
                        TABLE_SET_COLOR, ansi_grey(),
                        TABLE_STRING, "First unavailable group",
                        TABLE_SET_COLOR, ansi_grey(),
                        TABLE_INT, -1); /* sort before any other entry with the same GID */
        if (r < 0)
                return table_log_add_error(r);

        free(name);
        name = strjoin(special_glyph(SPECIAL_GLYPH_ARROW_UP),
                       " end unavailable groups ",
                       special_glyph(SPECIAL_GLYPH_ARROW_UP));
        if (!name)
                return log_oom();

        r = table_add_many(
                        table,
                        TABLE_STRING, special_glyph(SPECIAL_GLYPH_TREE_RIGHT),
                        TABLE_STRING, name,
                        TABLE_SET_COLOR, ansi_grey(),
                        TABLE_EMPTY,
                        TABLE_GID, end,
                        TABLE_SET_COLOR, ansi_grey(),
                        TABLE_STRING, "Last unavailable group",
                        TABLE_SET_COLOR, ansi_grey(),
                        TABLE_INT, 1); /* sort after any other entry with the same GID */
        if (r < 0)
                return table_log_add_error(r);

        return 2;
}

static int display_group(int argc, char *argv[], void *userdata) {
        _cleanup_(table_unrefp) Table *table = NULL;
        bool draw_separator = false;
        int ret = 0, r;

        if (arg_output < 0)
                arg_output = argc > 1 && !arg_fuzzy ? OUTPUT_FRIENDLY : OUTPUT_TABLE;

        if (arg_output == OUTPUT_TABLE) {
                table = table_new(" ", "name", "disposition", "gid", "description", "order");
                if (!table)
                        return log_oom();

                (void) table_set_align_percent(table, table_get_cell(table, 0, 3), 100);
                table_set_ersatz_string(table, TABLE_ERSATZ_DASH);
                (void) table_set_sort(table, (size_t) 3, (size_t) 5);
                (void) table_hide_column_from_display(table, (size_t) 5);
                if (!arg_boundaries)
                        (void) table_hide_column_from_display(table, (size_t) 0);
        }

        _cleanup_(userdb_match_done) UserDBMatch match = {
                .disposition_mask = arg_disposition_mask,
                .gid_min = arg_uid_min,
                .gid_max = arg_uid_max,
        };

        if (argc > 1 && !arg_fuzzy)
                STRV_FOREACH(i, argv + 1) {
                        _cleanup_(group_record_unrefp) GroupRecord *gr = NULL;

                        r = groupdb_by_name(*i, &match, arg_userdb_flags|USERDB_PARSE_NUMERIC, &gr);
                        if (r < 0) {
                                if (r == -ESRCH)
                                        log_error_errno(r, "Group %s does not exist.", *i);
                                else if (r == -EHOSTDOWN)
                                        log_error_errno(r, "Selected group database service is not available for this request.");
                                else if (r == -ENOEXEC)
                                        log_error_errno(r, "Group '%s' exists but does not match specified filter.", *i);
                                else
                                        log_error_errno(r, "Failed to find group %s: %m", *i);

                                RET_GATHER(ret, r);
                        } else {
                                if (draw_separator && arg_output == OUTPUT_FRIENDLY)
                                        putchar('\n');

                                r = show_group(gr, table);
                                if (r < 0)
                                        return r;

                                draw_separator = true;
                        }
                }
        else {
                if (argc > 1) {
                        match.fuzzy_names = strv_copy(strv_skip(argv, 1));
                        if (!match.fuzzy_names)
                                return log_oom();
                }

                _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;
                r = groupdb_all(&match, arg_userdb_flags, &iterator);
                if (r == -ENOLINK)
                        log_debug_errno(r, "No entries found. (Didn't check via Varlink.)");
                else if (r == -ESRCH)
                        log_debug_errno(r, "No entries found.");
                else if (r < 0)
                        return log_error_errno(r, "Failed to enumerate groups: %m");
                else {
                        for (;;) {
                                _cleanup_(group_record_unrefp) GroupRecord *gr = NULL;

                                r = groupdb_iterator_get(iterator, &match, &gr);
                                if (r == -ESRCH)
                                        break;
                                if (r == -EHOSTDOWN)
                                        return log_error_errno(r, "Selected group database service is not available for this request.");
                                if (r < 0)
                                        return log_error_errno(r, "Failed acquire next group: %m");

                                if (draw_separator && arg_output == OUTPUT_FRIENDLY)
                                        putchar('\n');

                                r = show_group(gr, table);
                                if (r < 0)
                                        return r;

                                draw_separator = true;
                        }
                }
        }

        if (table) {
                int boundary_lines = 0, gid_map_lines = 0;

                if (arg_boundaries) {
                        _cleanup_(uid_range_freep) UIDRange *gid_range = NULL;
                        r = uid_range_load_userns(/* path = */ NULL, GID_RANGE_USERNS_INSIDE, &gid_range);
                        if (r < 0)
                                log_debug_errno(r, "Failed to load /proc/self/gid_map, ignoring: %m");

                        boundary_lines = table_add_gid_boundaries(table, gid_range);
                        if (boundary_lines < 0)
                                return boundary_lines;

                        gid_map_lines = table_add_uid_map(table, gid_range, add_unavailable_gid);
                        if (gid_map_lines < 0)
                                return gid_map_lines;
                }

                if (!table_isempty(table)) {
                        r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, arg_legend);
                        if (r < 0)
                                return table_log_print_error(r);
                }

                if (arg_legend) {
                        size_t k;

                        k = table_get_rows(table) - 1 - boundary_lines - gid_map_lines;
                        if (k > 0)
                                printf("\n%zu groups listed.\n", k);
                        else
                                printf("No groups.\n");
                }
        }

        return ret;
}

static int show_membership(const char *user, const char *group, Table *table) {
        int r;

        assert(user);
        assert(group);

        switch (arg_output) {

        case OUTPUT_CLASSIC:
                /* Strictly speaking there's no 'classic' output for this concept, but let's output it in
                 * similar style to the classic output for user/group info */

                printf("%s:%s\n", user, group);
                break;

        case OUTPUT_JSON: {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                r = sd_json_buildo(
                                &v,
                                SD_JSON_BUILD_PAIR("user", SD_JSON_BUILD_STRING(user)),
                                SD_JSON_BUILD_PAIR("group", SD_JSON_BUILD_STRING(group)));
                if (r < 0)
                        return log_error_errno(r, "Failed to build JSON object: %m");

                sd_json_variant_dump(v, arg_json_format_flags, NULL, NULL);
                break;
        }

        case OUTPUT_FRIENDLY:
                /* Hmm, this is not particularly friendly, but not sure how we could do this better */
                printf("%s: %s\n", group, user);
                break;

        case OUTPUT_TABLE:
                assert(table);

                r = table_add_many(
                                table,
                                TABLE_STRING, user,
                                TABLE_STRING, group);
                if (r < 0)
                        return table_log_add_error(r);

                break;

        default:
                assert_not_reached();
        }

        return 0;
}

static int display_memberships(int argc, char *argv[], void *userdata) {
        _cleanup_(table_unrefp) Table *table = NULL;
        int ret = 0, r;

        if (arg_output < 0)
                arg_output = OUTPUT_TABLE;

        if (arg_output == OUTPUT_TABLE) {
                table = table_new("user", "group");
                if (!table)
                        return log_oom();

                (void) table_set_sort(table, (size_t) 0, (size_t) 1);
        }

        if (argc > 1)
                STRV_FOREACH(i, argv + 1) {
                        _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;

                        if (streq(argv[0], "users-in-group")) {
                                r = membershipdb_by_group(*i, arg_userdb_flags, &iterator);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to enumerate users in group: %m");
                        } else if (streq(argv[0], "groups-of-user")) {
                                r = membershipdb_by_user(*i, arg_userdb_flags, &iterator);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to enumerate groups of user: %m");
                        } else
                                assert_not_reached();

                        for (;;) {
                                _cleanup_free_ char *user = NULL, *group = NULL;

                                r = membershipdb_iterator_get(iterator, &user, &group);
                                if (r == -ESRCH)
                                        break;
                                if (r == -EHOSTDOWN)
                                        return log_error_errno(r, "Selected membership database service is not available for this request.");
                                if (r < 0)
                                        return log_error_errno(r, "Failed acquire next membership: %m");

                                r = show_membership(user, group, table);
                                if (r < 0)
                                        return r;
                        }
                }
        else {
                _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;

                r = membershipdb_all(arg_userdb_flags, &iterator);
                if (r == -ENOLINK)
                        log_debug_errno(r, "No entries found. (Didn't check via Varlink.)");
                else if (r == -ESRCH)
                        log_debug_errno(r, "No entries found.");
                else if (r < 0)
                        return log_error_errno(r, "Failed to enumerate memberships: %m");
                else {
                        for (;;) {
                                _cleanup_free_ char *user = NULL, *group = NULL;

                                r = membershipdb_iterator_get(iterator, &user, &group);
                                if (r == -ESRCH)
                                        break;
                                if (r == -EHOSTDOWN)
                                        return log_error_errno(r, "Selected membership database service is not available for this request.");
                                if (r < 0)
                                        return log_error_errno(r, "Failed acquire next membership: %m");

                                r = show_membership(user, group, table);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        if (table) {
                if (!table_isempty(table)) {
                        r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, arg_legend);
                        if (r < 0)
                                return table_log_print_error(r);
                }

                if (arg_legend) {
                        if (table_isempty(table))
                                printf("No memberships.\n");
                        else
                                printf("\n%zu memberships listed.\n", table_get_rows(table) - 1);
                }
        }

        return ret;
}

static int display_services(int argc, char *argv[], void *userdata) {
        _cleanup_(table_unrefp) Table *t = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        int r;

        d = opendir("/run/systemd/userdb/");
        if (!d) {
                if (errno == ENOENT) {
                        log_info("No services.");
                        return 0;
                }

                return log_error_errno(errno, "Failed to open /run/systemd/userdb/: %m");
        }

        t = table_new("service", "listening");
        if (!t)
                return log_oom();

        (void) table_set_sort(t, (size_t) 0);

        FOREACH_DIRENT(de, d, return -errno) {
                _cleanup_free_ char *j = NULL, *no = NULL;
                _cleanup_close_ int fd = -EBADF;

                j = path_join("/run/systemd/userdb/", de->d_name);
                if (!j)
                        return log_oom();

                fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to allocate AF_UNIX/SOCK_STREAM socket: %m");

                r = connect_unix_path(fd, dirfd(d), de->d_name);
                if (r < 0) {
                        no = strjoin("No (", errno_to_name(r), ")");
                        if (!no)
                                return log_oom();
                }

                r = table_add_many(t,
                                   TABLE_STRING, de->d_name,
                                   TABLE_STRING, no ?: "yes",
                                   TABLE_SET_COLOR, ansi_highlight_green_red(!no));
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (!table_isempty(t)) {
                r = table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
                if (r < 0)
                        return table_log_print_error(r);
        }

        if (arg_legend && arg_output != OUTPUT_JSON) {
                if (table_isempty(t))
                        printf("No services.\n");
                else
                        printf("\n%zu services listed.\n", table_get_rows(t) - 1);
        }

        return 0;
}

static int ssh_authorized_keys(int argc, char *argv[], void *userdata) {
        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
        char **chain_invocation;
        int r;

        assert(argc >= 2);

        if (arg_chain) {
                /* If --chain is specified, the rest of the command line is the chain command */

                if (argc < 3)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "No chain command line specified, refusing.");

                /* Make similar restrictions on the chain command as OpenSSH itself makes on the primary command. */
                if (!path_is_absolute(argv[2]))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Chain invocation of ssh-authorized-keys commands requires an absolute binary path argument.");

                if (!path_is_normalized(argv[2]))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Chain invocation of ssh-authorized-keys commands requires an normalized binary path argument.");

                chain_invocation = argv + 2;
        } else {
                /* If --chain is not specified, then refuse any further arguments */

                if (argc > 2)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Too many arguments.");

                chain_invocation = NULL;
        }

        r = userdb_by_name(argv[1], /* match= */ NULL, arg_userdb_flags, &ur);
        if (r == -ESRCH)
                log_error_errno(r, "User %s does not exist.", argv[1]);
        else if (r == -EHOSTDOWN)
                log_error_errno(r, "Selected user database service is not available for this request.");
        else if (r == -EINVAL)
                log_error_errno(r, "Failed to find user %s: %m (Invalid user name?)", argv[1]);
        else if (r < 0)
                log_error_errno(r, "Failed to find user %s: %m", argv[1]);
        else {
                if (strv_isempty(ur->ssh_authorized_keys))
                        log_debug("User record for %s has no public SSH keys.", argv[1]);
                else
                        STRV_FOREACH(i, ur->ssh_authorized_keys)
                                printf("%s\n", *i);

                if (ur->incomplete) {
                        fflush(stdout);
                        log_warning("Warning: lacking rights to acquire privileged fields of user record of '%s', output incomplete.", ur->user_name);
                }
        }

        if (chain_invocation) {
                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *s = NULL;

                        s = quote_command_line(chain_invocation, SHELL_ESCAPE_EMPTY);
                        if (!s)
                                return log_oom();

                        log_debug("Chain invoking: %s", s);
                }

                fflush(stdout);
                execv(chain_invocation[0], chain_invocation);
                if (errno == ENOENT) /* Let's handle ENOENT gracefully */
                        log_warning_errno(errno, "Chain executable '%s' does not exist, ignoring chain invocation.", chain_invocation[0]);
                else {
                        log_error_errno(errno, "Failed to invoke chain executable '%s': %m", chain_invocation[0]);
                        if (r >= 0)
                                r = -errno;
                }
        }

        return r;
}

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        pager_open(arg_pager_flags);

        r = terminal_urlify_man("userdbctl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] COMMAND ...\n\n"
               "%sShow user and group information.%s\n"
               "\nCommands:\n"
               "  user [USER…]               Inspect user\n"
               "  group [GROUP…]             Inspect group\n"
               "  users-in-group [GROUP…]    Show users that are members of specified groups\n"
               "  groups-of-user [USER…]     Show groups the specified users are members of\n"
               "  services                   Show enabled database services\n"
               "  ssh-authorized-keys USER   Show SSH authorized keys for user\n"
               "\nOptions:\n"
               "  -h --help                  Show this help\n"
               "     --version               Show package version\n"
               "     --no-pager              Do not pipe output into a pager\n"
               "     --no-legend             Do not show the headers and footers\n"
               "     --output=MODE           Select output mode (classic, friendly, table, json)\n"
               "  -j                         Equivalent to --output=json\n"
               "  -s --service=SERVICE[:SERVICE…]\n"
               "                             Query the specified service\n"
               "     --with-nss=BOOL         Control whether to include glibc NSS data\n"
               "  -N                         Do not synthesize or include glibc NSS data\n"
               "                             (Same as --synthesize=no --with-nss=no)\n"
               "     --synthesize=BOOL       Synthesize root/nobody user\n"
               "     --with-dropin=BOOL      Control whether to include drop-in records\n"
               "     --with-varlink=BOOL     Control whether to talk to services at all\n"
               "     --multiplexer=BOOL      Control whether to use the multiplexer\n"
               "     --json=pretty|short     JSON output mode\n"
               "     --chain                 Chain another command\n"
               "     --uid-min=ID            Filter by minimum UID/GID (default 0)\n"
               "     --uid-max=ID            Filter by maximum UID/GID (default 4294967294)\n"
               "  -z --fuzzy                 Do a fuzzy name search\n"
               "     --disposition=VALUE     Filter by disposition\n"
               "  -I                         Equivalent to --disposition=intrinsic\n"
               "  -S                         Equivalent to --disposition=system\n"
               "  -R                         Equivalent to --disposition=regular\n"
               "     --boundaries=BOOL       Show/hide UID/GID range boundaries in output\n"
               "  -B                         Equivalent to --boundaries=no\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
                ARG_OUTPUT,
                ARG_WITH_NSS,
                ARG_WITH_DROPIN,
                ARG_WITH_VARLINK,
                ARG_SYNTHESIZE,
                ARG_MULTIPLEXER,
                ARG_JSON,
                ARG_CHAIN,
                ARG_UID_MIN,
                ARG_UID_MAX,
                ARG_DISPOSITION,
                ARG_BOUNDARIES,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'              },
                { "version",      no_argument,       NULL, ARG_VERSION      },
                { "no-pager",     no_argument,       NULL, ARG_NO_PAGER     },
                { "no-legend",    no_argument,       NULL, ARG_NO_LEGEND    },
                { "output",       required_argument, NULL, ARG_OUTPUT       },
                { "service",      required_argument, NULL, 's'              },
                { "with-nss",     required_argument, NULL, ARG_WITH_NSS     },
                { "with-dropin",  required_argument, NULL, ARG_WITH_DROPIN  },
                { "with-varlink", required_argument, NULL, ARG_WITH_VARLINK },
                { "synthesize",   required_argument, NULL, ARG_SYNTHESIZE   },
                { "multiplexer",  required_argument, NULL, ARG_MULTIPLEXER  },
                { "json",         required_argument, NULL, ARG_JSON         },
                { "chain",        no_argument,       NULL, ARG_CHAIN        },
                { "uid-min",      required_argument, NULL, ARG_UID_MIN      },
                { "uid-max",      required_argument, NULL, ARG_UID_MAX      },
                { "fuzzy",        no_argument,       NULL, 'z'              },
                { "disposition",  required_argument, NULL, ARG_DISPOSITION  },
                { "boundaries",   required_argument, NULL, ARG_BOUNDARIES   },
                {}
        };

        const char *e;
        int r;

        assert(argc >= 0);
        assert(argv);

        /* We are going to update this environment variable with our own, hence let's first read what is already set */
        e = getenv("SYSTEMD_ONLY_USERDB");
        if (e) {
                char **l;

                l = strv_split(e, ":");
                if (!l)
                        return log_oom();

                strv_free(arg_services);
                arg_services = l;
        }

        /* Resetting to 0 forces the invocation of an internal initialization routine of getopt_long()
         * that checks for GNU extensions in optstring ('-' or '+' at the beginning). */
        optind = 0;

        for (;;) {
                int c;

                c = getopt_long(argc, argv,
                                arg_chain ? "+hjs:NISRzB" : "hjs:NISRzB", /* When --chain was used disable parsing of further switches */
                                options, NULL);
                if (c < 0)
                        break;

                switch (c) {

                case 'h':
                        return help(0, NULL, NULL);

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case ARG_OUTPUT:
                        if (isempty(optarg))
                                arg_output = _OUTPUT_INVALID;
                        else if (streq(optarg, "classic"))
                                arg_output = OUTPUT_CLASSIC;
                        else if (streq(optarg, "friendly"))
                                arg_output = OUTPUT_FRIENDLY;
                        else if (streq(optarg, "json"))
                                arg_output = OUTPUT_JSON;
                        else if (streq(optarg, "table"))
                                arg_output = OUTPUT_TABLE;
                        else if (streq(optarg, "help")) {
                                puts("classic\n"
                                     "friendly\n"
                                     "json\n"
                                     "table");
                                return 0;
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid --output= mode: %s", optarg);

                        arg_json_format_flags = arg_output == OUTPUT_JSON ? SD_JSON_FORMAT_PRETTY|SD_JSON_FORMAT_COLOR_AUTO : SD_JSON_FORMAT_OFF;
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

                        arg_output = sd_json_format_enabled(arg_json_format_flags) ? OUTPUT_JSON : _OUTPUT_INVALID;
                        break;

                case 'j':
                        arg_json_format_flags = SD_JSON_FORMAT_PRETTY|SD_JSON_FORMAT_COLOR_AUTO;
                        arg_output = OUTPUT_JSON;
                        break;

                case 's':
                        if (isempty(optarg))
                                arg_services = strv_free(arg_services);
                        else {
                                r = strv_split_and_extend(&arg_services, optarg, ":", /* filter_duplicates = */ true);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse -s/--service= argument: %m");
                        }

                        break;

                case 'N':
                        arg_userdb_flags |= USERDB_EXCLUDE_NSS|USERDB_DONT_SYNTHESIZE_INTRINSIC|USERDB_DONT_SYNTHESIZE_FOREIGN;
                        break;

                case ARG_WITH_NSS:
                        r = parse_boolean_argument("--with-nss=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_userdb_flags, USERDB_EXCLUDE_NSS, !r);
                        break;

                case ARG_WITH_DROPIN:
                        r = parse_boolean_argument("--with-dropin=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_userdb_flags, USERDB_EXCLUDE_DROPIN, !r);
                        break;

                case ARG_WITH_VARLINK:
                        r = parse_boolean_argument("--with-varlink=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_userdb_flags, USERDB_EXCLUDE_VARLINK, !r);
                        break;

                case ARG_SYNTHESIZE:
                        r = parse_boolean_argument("--synthesize=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_userdb_flags, USERDB_DONT_SYNTHESIZE_INTRINSIC|USERDB_DONT_SYNTHESIZE_FOREIGN, !r);
                        break;

                case ARG_MULTIPLEXER:
                        r = parse_boolean_argument("--multiplexer=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_userdb_flags, USERDB_AVOID_MULTIPLEXER, !r);
                        break;

                case ARG_CHAIN:
                        arg_chain = true;
                        break;

                case ARG_DISPOSITION: {
                        UserDisposition d = user_disposition_from_string(optarg);
                        if (d < 0)
                                return log_error_errno(d, "Unknown user disposition: %s", optarg);

                        if (arg_disposition_mask == UINT64_MAX)
                                arg_disposition_mask = 0;

                        arg_disposition_mask |= UINT64_C(1) << d;
                        break;
                }

                case 'I':
                        if (arg_disposition_mask == UINT64_MAX)
                                arg_disposition_mask = 0;

                        arg_disposition_mask |= UINT64_C(1) << USER_INTRINSIC;
                        break;

                case 'S':
                        if (arg_disposition_mask == UINT64_MAX)
                                arg_disposition_mask = 0;

                        arg_disposition_mask |= UINT64_C(1) << USER_SYSTEM;
                        break;

                case 'R':
                        if (arg_disposition_mask == UINT64_MAX)
                                arg_disposition_mask = 0;

                        arg_disposition_mask |= UINT64_C(1) << USER_REGULAR;
                        break;

                case ARG_UID_MIN:
                        r = parse_uid(optarg, &arg_uid_min);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --uid-min= value: %s", optarg);
                        break;

                case ARG_UID_MAX:
                        r = parse_uid(optarg, &arg_uid_max);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --uid-max= value: %s", optarg);
                        break;

                case 'z':
                        arg_fuzzy = true;
                        break;

                case ARG_BOUNDARIES:
                        r = parse_boolean_argument("boundaries", optarg, &arg_boundaries);
                        if (r < 0)
                                return r;
                        break;

                case 'B':
                        arg_boundaries = false;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }
        }

        if (arg_uid_min > arg_uid_max)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Minimum UID/GID " UID_FMT " is above maximum UID/GID " UID_FMT ", refusing.", arg_uid_min, arg_uid_max);

        /* If not mask was specified, use the all bits on mask */
        if (arg_disposition_mask == UINT64_MAX)
                arg_disposition_mask = USER_DISPOSITION_MASK_ALL;

        return 1;
}

static int run(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "help",                VERB_ANY, VERB_ANY, 0,            help                },
                { "user",                VERB_ANY, VERB_ANY, VERB_DEFAULT, display_user        },
                { "group",               VERB_ANY, VERB_ANY, 0,            display_group       },
                { "users-in-group",      VERB_ANY, VERB_ANY, 0,            display_memberships },
                { "groups-of-user",      VERB_ANY, VERB_ANY, 0,            display_memberships },
                { "services",            VERB_ANY, 1,        0,            display_services    },

                /* This one is a helper for sshd_config's AuthorizedKeysCommand= setting, it's not a
                 * user-facing verb and thus should not appear in man pages or --help texts. */
                { "ssh-authorized-keys", 2,        VERB_ANY, 0,            ssh_authorized_keys },
                {}
        };

        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_services) {
                _cleanup_free_ char *e = NULL;

                e = strv_join(arg_services, ":");
                if (!e)
                        return log_oom();

                if (setenv("SYSTEMD_ONLY_USERDB", e, true) < 0)
                        return log_error_errno(r, "Failed to set $SYSTEMD_ONLY_USERDB: %m");

                log_info("Enabled services: %s", e);
        } else
                assert_se(unsetenv("SYSTEMD_ONLY_USERDB") == 0);

        return dispatch_verb(argc, argv, verbs, NULL);
}

DEFINE_MAIN_FUNCTION(run);
