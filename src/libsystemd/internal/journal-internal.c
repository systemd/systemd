/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>

#include "escape.h"
#include "fd-util.h"
#include "journal-internal.h"
#include "socket-util.h"

#define SNDBUF_SIZE (8*1024*1024)

/* We open a single fd, and we'll share it with the current process,
 * all its threads, and all its subprocesses. This means we need to
 * initialize it atomically, and need to operate on it atomically
 * never assuming we are the only user */
static int fd_plus_one = 0;

int journal_send_fd(void) {
        int fd;

retry:
        if (fd_plus_one > 0)
                return fd_plus_one - 1;

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        fd_inc_sndbuf(fd, SNDBUF_SIZE);

        if (!__sync_bool_compare_and_swap(&fd_plus_one, 0, fd+1)) {
                safe_close(fd);
                goto retry;
        }

        return fd;
}

void journal_print_header(sd_journal *j) {
        JournalFile *f;
        bool newline = false;

        assert(j);

        ORDERED_HASHMAP_FOREACH(f, j->files) {
                if (newline)
                        putchar('\n');
                else
                        newline = true;

                journal_file_print_header(f);
        }
}

char* _journal_make_match_string(Match *m) {
        char *p = NULL, *r;
        bool enclose = false;

        if (!m)
                return strdup("none");

        if (m->type == MATCH_DISCRETE)
                return cescape_length(m->data, m->size);

        LIST_FOREACH(matches, i, m->matches) {
                char *t, *k;

                t = _journal_make_match_string(i);
                if (!t)
                        return mfree(p);

                if (p) {
                        k = strjoin(p, m->type == MATCH_OR_TERM ? " OR " : " AND ", t);
                        free(p);
                        free(t);

                        if (!k)
                                return NULL;

                        p = k;

                        enclose = true;
                } else
                        p = t;
        }

        if (enclose) {
                r = strjoin("(", p, ")");
                free(p);
                return r;
        }

        return p;
}
