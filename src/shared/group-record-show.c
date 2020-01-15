/* SPDX-License-Identifier: LGPL-2.1+ */

#include "format-util.h"
#include "group-record-show.h"
#include "strv.h"
#include "user-util.h"
#include "userdb.h"

void group_record_show(GroupRecord *gr, bool show_full_user_info) {
        int r;

        printf("  Group name: %s\n",
               group_record_group_name_and_realm(gr));

        printf(" Disposition: %s\n", user_disposition_to_string(group_record_disposition(gr)));

        if (gr->last_change_usec != USEC_INFINITY) {
                char buf[FORMAT_TIMESTAMP_MAX];
                printf(" Last Change: %s\n", format_timestamp(buf, sizeof(buf), gr->last_change_usec));
        }

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
                char **i;

                STRV_FOREACH(i, gr->members) {
                        printf("%s %s\n", prefix, *i);
                        prefix = "             ";
                }
        }

        if (!strv_isempty(gr->administrators)) {
                const char *prefix = "      Admins:";
                char **i;

                STRV_FOREACH(i, gr->administrators) {
                        printf("%s %s\n", prefix, *i);
                        prefix = "             ";
                }
        }

        if (!strv_isempty(gr->hashed_password))
                printf("   Passwords: %zu\n", strv_length(gr->hashed_password));

        if (gr->service)
                printf("     Service: %s\n", gr->service);
}
