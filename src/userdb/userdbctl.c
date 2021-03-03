/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <utmp.h>

#include "dirent-util.h"
#include "errno-list.h"
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
#include "user-record-show.h"
#include "user-util.h"
#include "userdb.h"
#include "verbs.h"

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

STATIC_DESTRUCTOR_REGISTER(arg_services, strv_freep);

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
                json_variant_dump(ur->json, JSON_FORMAT_COLOR_AUTO|JSON_FORMAT_PRETTY, NULL, 0);
                break;

        case OUTPUT_FRIENDLY:
                user_record_show(ur, true);

                if (ur->incomplete) {
                        fflush(stdout);
                        log_warning("Warning: lacking rights to acquire privileged fields of user record of '%s', output incomplete.", ur->user_name);
                }

                break;

        case OUTPUT_TABLE:
                assert(table);

                r = table_add_many(
                                table,
                                TABLE_STRING, ur->user_name,
                                TABLE_STRING, user_disposition_to_string(user_record_disposition(ur)),
                                TABLE_UID, ur->uid,
                                TABLE_GID, user_record_gid(ur),
                                TABLE_STRING, empty_to_null(ur->real_name),
                                TABLE_STRING, user_record_home_directory(ur),
                                TABLE_STRING, user_record_shell(ur),
                                TABLE_INT, (int) user_record_disposition(ur));
                if (r < 0)
                        return table_log_add_error(r);

                break;

        default:
                assert_not_reached("Unexpected output mode");
        }

        return 0;
}

static int display_user(int argc, char *argv[], void *userdata) {
        _cleanup_(table_unrefp) Table *table = NULL;
        bool draw_separator = false;
        int ret = 0, r;

        if (arg_output < 0)
                arg_output = argc > 1 ? OUTPUT_FRIENDLY : OUTPUT_TABLE;

        if (arg_output == OUTPUT_TABLE) {
                table = table_new("name", "disposition", "uid", "gid", "realname", "home", "shell", "disposition-numeric");
                if (!table)
                        return log_oom();

                (void) table_set_align_percent(table, table_get_cell(table, 0, 2), 100);
                (void) table_set_align_percent(table, table_get_cell(table, 0, 3), 100);
                (void) table_set_empty_string(table, "-");
                (void) table_set_sort(table, (size_t) 7, (size_t) 2);
                (void) table_set_display(table, (size_t) 0, (size_t) 1, (size_t) 2, (size_t) 3, (size_t) 4, (size_t) 5, (size_t) 6);
        }

        if (argc > 1) {
                char **i;

                STRV_FOREACH(i, argv + 1) {
                        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
                        uid_t uid;

                        if (parse_uid(*i, &uid) >= 0)
                                r = userdb_by_uid(uid, arg_userdb_flags, &ur);
                        else
                                r = userdb_by_name(*i, arg_userdb_flags, &ur);
                        if (r < 0) {
                                if (r == -ESRCH)
                                        log_error_errno(r, "User %s does not exist.", *i);
                                else if (r == -EHOSTDOWN)
                                        log_error_errno(r, "Selected user database service is not available for this request.");
                                else
                                        log_error_errno(r, "Failed to find user %s: %m", *i);

                                if (ret >= 0)
                                        ret = r;
                        } else {
                                if (draw_separator && arg_output == OUTPUT_FRIENDLY)
                                        putchar('\n');

                                r = show_user(ur, table);
                                if (r < 0)
                                        return r;

                                draw_separator = true;
                        }
                }
        } else {
                _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;

                r = userdb_all(arg_userdb_flags, &iterator);
                if (r < 0)
                        return log_error_errno(r, "Failed to enumerate users: %m");

                for (;;) {
                        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;

                        r = userdb_iterator_get(iterator, &ur);
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

        if (table) {
                r = table_print(table, NULL);
                if (r < 0)
                        return table_log_print_error(r);
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
                json_variant_dump(gr->json, JSON_FORMAT_COLOR_AUTO|JSON_FORMAT_PRETTY, NULL, 0);
                break;

        case OUTPUT_FRIENDLY:
                group_record_show(gr, true);

                if (gr->incomplete) {
                        fflush(stdout);
                        log_warning("Warning: lacking rights to acquire privileged fields of group record of '%s', output incomplete.", gr->group_name);
                }

                break;

        case OUTPUT_TABLE:
                assert(table);

                r = table_add_many(
                                table,
                                TABLE_STRING, gr->group_name,
                                TABLE_STRING, user_disposition_to_string(group_record_disposition(gr)),
                                TABLE_GID, gr->gid,
                                TABLE_STRING, gr->description,
                                TABLE_INT, (int) group_record_disposition(gr));
                if (r < 0)
                        return table_log_add_error(r);

                break;

        default:
                assert_not_reached("Unexpected display mode");
        }

        return 0;
}


static int display_group(int argc, char *argv[], void *userdata) {
        _cleanup_(table_unrefp) Table *table = NULL;
        bool draw_separator = false;
        int ret = 0, r;

        if (arg_output < 0)
                arg_output = argc > 1 ? OUTPUT_FRIENDLY : OUTPUT_TABLE;

        if (arg_output == OUTPUT_TABLE) {
                table = table_new("name", "disposition", "gid", "description", "disposition-numeric");
                if (!table)
                        return log_oom();

                (void) table_set_align_percent(table, table_get_cell(table, 0, 2), 100);
                (void) table_set_empty_string(table, "-");
                (void) table_set_sort(table, (size_t) 3, (size_t) 2);
                (void) table_set_display(table, (size_t) 0, (size_t) 1, (size_t) 2, (size_t) 3);
        }

        if (argc > 1) {
                char **i;

                STRV_FOREACH(i, argv + 1) {
                        _cleanup_(group_record_unrefp) GroupRecord *gr = NULL;
                        gid_t gid;

                        if (parse_gid(*i, &gid) >= 0)
                                r = groupdb_by_gid(gid, arg_userdb_flags, &gr);
                        else
                                r = groupdb_by_name(*i, arg_userdb_flags, &gr);
                        if (r < 0) {
                                if (r == -ESRCH)
                                        log_error_errno(r, "Group %s does not exist.", *i);
                                else if (r == -EHOSTDOWN)
                                        log_error_errno(r, "Selected group database service is not available for this request.");
                                else
                                        log_error_errno(r, "Failed to find group %s: %m", *i);

                                if (ret >= 0)
                                        ret = r;
                        } else {
                                if (draw_separator && arg_output == OUTPUT_FRIENDLY)
                                        putchar('\n');

                                r = show_group(gr, table);
                                if (r < 0)
                                        return r;

                                draw_separator = true;
                        }
                }

        } else {
                _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;

                r = groupdb_all(arg_userdb_flags, &iterator);
                if (r < 0)
                        return log_error_errno(r, "Failed to enumerate groups: %m");

                for (;;) {
                        _cleanup_(group_record_unrefp) GroupRecord *gr = NULL;

                        r = groupdb_iterator_get(iterator, &gr);
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

        if (table) {
                r = table_print(table, NULL);
                if (r < 0)
                        return table_log_print_error(r);
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
                _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

                r = json_build(&v, JSON_BUILD_OBJECT(
                                               JSON_BUILD_PAIR("user", JSON_BUILD_STRING(user)),
                                               JSON_BUILD_PAIR("group", JSON_BUILD_STRING(group))));
                if (r < 0)
                        return log_error_errno(r, "Failed to build JSON object: %m");

                json_variant_dump(v, JSON_FORMAT_PRETTY|JSON_FORMAT_COLOR_AUTO, NULL, NULL);
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
                assert_not_reached("Unexpected output mode");
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

        if (argc > 1) {
                char **i;

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
                                assert_not_reached("Unexpected verb");

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
        } else {
                _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;

                r = membershipdb_all(arg_userdb_flags, &iterator);
                if (r < 0)
                        return log_error_errno(r, "Failed to enumerate memberships: %m");

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

        if (table) {
                r = table_print(table, NULL);
                if (r < 0)
                        return table_log_print_error(r);
        }

        return ret;
}

static int display_services(int argc, char *argv[], void *userdata) {
        _cleanup_(table_unrefp) Table *t = NULL;
        _cleanup_(closedirp) DIR *d = NULL;
        struct dirent *de;
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
                union sockaddr_union sockaddr;
                socklen_t sockaddr_len;
                _cleanup_close_ int fd = -1;

                j = path_join("/run/systemd/userdb/", de->d_name);
                if (!j)
                        return log_oom();

                r = sockaddr_un_set_path(&sockaddr.un, j);
                if (r < 0)
                        return log_error_errno(r, "Path %s does not fit in AF_UNIX socket address: %m", j);
                sockaddr_len = r;

                fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (fd < 0)
                        return log_error_errno(r, "Failed to allocate AF_UNIX/SOCK_STREAM socket: %m");

                if (connect(fd, &sockaddr.un, sockaddr_len) < 0) {
                        no = strjoin("No (", errno_to_name(errno), ")");
                        if (!no)
                                return log_oom();
                }

                r = table_add_many(t,
                                   TABLE_STRING, de->d_name,
                                   TABLE_STRING, no ?: "yes",
                                   TABLE_SET_COLOR, no ? ansi_highlight_red() : ansi_highlight_green());
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (table_get_rows(t) <= 0) {
                log_info("No services.");
                return 0;
        }

        if (arg_output == OUTPUT_JSON)
                table_print_json(t, NULL, JSON_FORMAT_PRETTY|JSON_FORMAT_COLOR_AUTO);
        else
                table_print(t, NULL);

        return 0;
}

static int ssh_authorized_keys(int argc, char *argv[], void *userdata) {
        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
        int r;

        r = userdb_by_name(argv[1], arg_userdb_flags, &ur);
        if (r == -ESRCH)
                return log_error_errno(r, "User %s does not exist.", argv[1]);
        else if (r == -EHOSTDOWN)
                return log_error_errno(r, "Selected user database service is not available for this request.");
        else if (r == -EINVAL)
                return log_error_errno(r, "Failed to find user %s: %m (Invalid user name?)", argv[1]);
        else if (r < 0)
                return log_error_errno(r, "Failed to find user %s: %m", argv[1]);

        if (strv_isempty(ur->ssh_authorized_keys))
                log_debug("User record for %s has no public SSH keys.", argv[1]);
        else {
                char **i;

                STRV_FOREACH(i, ur->ssh_authorized_keys)
                        printf("%s\n", *i);
        }

        if (ur->incomplete) {
                fflush(stdout);
                log_warning("Warning: lacking rights to acquire privileged fields of user record of '%s', output incomplete.", ur->user_name);
        }

        return EXIT_SUCCESS;
}

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        (void) pager_open(arg_pager_flags);

        r = terminal_urlify_man("userdbctl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] COMMAND ...\n\n"
               "%sShow user and group information.%s\n"
               "\nCommands:\n"
               "  user [USER…]               Inspect user\n"
               "  group [GROUP…]             Inspect group\n"
               "  users-in-group [GROUP…]    Show users that are members of specified group(s)\n"
               "  groups-of-user [USER…]     Show groups the specified user(s) is a member of\n"
               "  services                   Show enabled database services\n"
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
                ARG_SYNTHESIZE,
        };

        static const struct option options[] = {
                { "help",       no_argument,       NULL, 'h'            },
                { "version",    no_argument,       NULL, ARG_VERSION    },
                { "no-pager",   no_argument,       NULL, ARG_NO_PAGER   },
                { "no-legend",  no_argument,       NULL, ARG_NO_LEGEND  },
                { "output",     required_argument, NULL, ARG_OUTPUT     },
                { "service",    required_argument, NULL, 's'            },
                { "with-nss",   required_argument, NULL, ARG_WITH_NSS   },
                { "synthesize", required_argument, NULL, ARG_SYNTHESIZE },
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

        for (;;) {
                int c;

                c = getopt_long(argc, argv, "hjs:N", options, NULL);
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
                        if (streq(optarg, "classic"))
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

                        break;

                case 'j':
                        arg_output = OUTPUT_JSON;
                        break;

                case 's':
                        if (isempty(optarg))
                                arg_services = strv_free(arg_services);
                        else {
                                _cleanup_strv_free_ char **l = NULL;

                                l = strv_split(optarg, ":");
                                if (!l)
                                        return log_oom();

                                r = strv_extend_strv(&arg_services, l, true);
                                if (r < 0)
                                        return log_oom();
                        }

                        break;

                case 'N':
                        arg_userdb_flags |= USERDB_AVOID_NSS|USERDB_DONT_SYNTHESIZE;
                        break;

                case ARG_WITH_NSS:
                        r = parse_boolean_argument("--with-nss=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_userdb_flags, USERDB_AVOID_NSS, !r);
                        break;

                case ARG_SYNTHESIZE:
                        r = parse_boolean_argument("--synthesize=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_userdb_flags, USERDB_DONT_SYNTHESIZE, !r);
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }
        }

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
                { "ssh-authorized-keys", 2,        2,        0,            ssh_authorized_keys },
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
