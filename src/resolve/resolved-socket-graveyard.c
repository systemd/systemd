/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "resolved-socket-graveyard.h"

#define SOCKET_GRAVEYARD_USEC (5 * USEC_PER_SEC)
#define SOCKET_GRAVEYARD_MAX 100

/* This implements a socket "graveyard" for UDP sockets. If a socket fd is added to the graveyard it is kept
 * open for a couple of more seconds, expecting one reply. Once the reply is received the fd is closed
 * immediately, or if none is received it is closed after the timeout. Why all this? So that if we contact a
 * DNS server, and it doesn't reply instantly, and we lose interest in the response and thus close the fd, we
 * don't end up sending back an ICMP error once the server responds but we aren't listening anymore. (See
 * https://github.com/systemd/systemd/issues/17421 for further information.)
 *
 * Note that we don't allocate any timer event source to clear up the graveyard once the socket's timeout is
 * reached. Instead we operate lazily: we close old entries when adding a new fd to the graveyard, or
 * whenever any code runs manager_socket_graveyard_process() — which the DNS transaction code does right
 * before allocating a new UDP socket. */

static SocketGraveyard* socket_graveyard_free(SocketGraveyard *g) {
        if (!g)
                return NULL;

        if (g->manager) {
                assert(g->manager->n_socket_graveyard > 0);
                g->manager->n_socket_graveyard--;

                if (g->manager->socket_graveyard_oldest == g)
                        g->manager->socket_graveyard_oldest = g->graveyard_prev;

                LIST_REMOVE(graveyard, g->manager->socket_graveyard, g);

                assert((g->manager->n_socket_graveyard > 0) == !!g->manager->socket_graveyard);
                assert((g->manager->n_socket_graveyard > 0) == !!g->manager->socket_graveyard_oldest);
        }

        if (g->io_event_source) {
                log_debug("Closing graveyard socket fd %i", sd_event_source_get_io_fd(g->io_event_source));
                sd_event_source_disable_unref(g->io_event_source);
        }

        return mfree(g);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(SocketGraveyard*, socket_graveyard_free);

void manager_socket_graveyard_process(Manager *m) {
        usec_t n = USEC_INFINITY;

        assert(m);

        while (m->socket_graveyard_oldest) {
                SocketGraveyard *g = m->socket_graveyard_oldest;

                if (n == USEC_INFINITY)
                        assert_se(sd_event_now(m->event, CLOCK_BOOTTIME, &n) >= 0);

                if (g->deadline > n)
                        break;

                socket_graveyard_free(g);
        }
}

void manager_socket_graveyard_clear(Manager *m) {
        assert(m);

        while (m->socket_graveyard)
                socket_graveyard_free(m->socket_graveyard);
}

static int on_io_event(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        SocketGraveyard *g = ASSERT_PTR(userdata);

        /* An IO event happened on the graveyard fd. We don't actually care which event that is, and we don't
         * read any incoming packet off the socket. We just close the fd, that's enough to not trigger the
         * ICMP unreachable port event */

        socket_graveyard_free(g);
        return 0;
}

static void manager_socket_graveyard_make_room(Manager *m) {
        assert(m);

        while (m->n_socket_graveyard >= SOCKET_GRAVEYARD_MAX)
                socket_graveyard_free(m->socket_graveyard_oldest);
}

int manager_add_socket_to_graveyard(Manager *m, int fd) {
        _cleanup_(socket_graveyard_freep) SocketGraveyard *g = NULL;
        int r;

        assert(m);
        assert(fd >= 0);

        manager_socket_graveyard_process(m);
        manager_socket_graveyard_make_room(m);

        g = new(SocketGraveyard, 1);
        if (!g)
                return log_oom();

        *g = (SocketGraveyard) {
                .manager = m,
        };

        LIST_PREPEND(graveyard, m->socket_graveyard, g);
        if (!m->socket_graveyard_oldest)
                m->socket_graveyard_oldest = g;

        m->n_socket_graveyard++;

        assert_se(sd_event_now(m->event, CLOCK_BOOTTIME, &g->deadline) >= 0);
        g->deadline += SOCKET_GRAVEYARD_USEC;

        r = sd_event_add_io(m->event, &g->io_event_source, fd, EPOLLIN, on_io_event, g);
        if (r < 0)
                return log_error_errno(r, "Failed to create graveyard IO source: %m");

        r = sd_event_source_set_io_fd_own(g->io_event_source, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable graveyard IO source fd ownership: %m");

        (void) sd_event_source_set_description(g->io_event_source, "graveyard");

        log_debug("Added socket %i to graveyard", fd);

        TAKE_PTR(g);
        return 0;
}
