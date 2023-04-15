/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <systemd/sd-daemon.h>

struct worker {
        pid_t pid;
        struct worker *next, *prev;
};

struct worker *workers;

static int add_worker(pid_t pid) {
        struct worker *worker;

        worker = calloc(1, sizeof(*worker));
        if (!worker)
                return -ENOMEM;

        worker->pid = pid;

        worker->next = workers;
        worker->prev = NULL;

        if (workers)
                workers->prev = worker;

        workers = worker;

        return 0;
}

static void remove_worker(pid_t pid) {
        struct worker *worker = workers;

        while (worker && worker->pid != pid)
                worker = worker->next;

        if (!worker)
                return;

        if (worker->prev)
                worker->prev->next = worker->next;
        else
                workers = worker->next;

        if (worker->next)
                worker->next->prev = worker->prev;

        free(worker);
}

static void terminate_workers(void) {
        struct worker *worker = workers;

        while (worker) {
                (void) kill(worker->pid, SIGKILL);
                worker = worker->next;
        }
}

static void wait_for_workers(void) {
        for (;;) {
                pid_t p;

                p = wait(NULL);
                if (p < 0)
                        break;

                remove_worker(p);
        }
}

static int handle_connection(int fd, const char *id) {
        pid_t pid;
        int r;

        pid = fork();
        if (pid < 0) {
                fprintf(stderr, "error: failed to fork child process: %m\n");
                return -errno;
        }

        if (pid == 0) {
                /* Child */
                FILE *f;

                f = fdopen(fd, "w");
                if (!f) {
                        fprintf(stderr,
                                "error: failed to create FILE* object from connection file descriptor: %m\n");
                        _exit(EXIT_FAILURE);
                }

                for (int i = 0; i < 5; i++) {
                        fprintf(f, "GENERATION_ID=%s\n", id);
                        fflush(f);
                        sleep(1);
                }

                fclose(f);
                close(fd);

                _exit(EXIT_SUCCESS);
        }

        /* We don't need connection file descriptor in the parent. */
        close(fd);

        r = add_worker(pid);
        if (r < 0) {
                fprintf(stderr, "error: failed to allocate worker object, terminating worker process.\n");
                (void) kill(pid, SIGKILL);
                return -ECONNABORTED;
        }

        return 0;
}

static int handle_signal(int signo) {
        pid_t pid;

        if (signo == SIGUSR1)
                return 1;

        if (signo == SIGINT || signo == SIGTERM) {
                (void) terminate_workers();
                return 1;
        }

        pid = wait(NULL);
        remove_worker(pid);
        return 0;
}

int main(void) {
        int r, fd, sfd, efd, flags;
        struct epoll_event ev;
        sigset_t mask;
        char *id;

        id = getenv("GENERATION_ID");
        if (!id) {
                fprintf(stderr, "error: failed to retrieve GENERATION_ID environment variable\n");
                return EXIT_FAILURE;
        }

        r = sd_listen_fds(true);
        if (r != 1) {
                fprintf(stderr, "error: expected systemd to pass in exactly one file descriptor\n");
                return EXIT_FAILURE;
        }

        fd = SD_LISTEN_FDS_START;
        flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0) {
                fprintf(stderr, "error: failed to obtain file descriptor flags: %m\n");
                return EXIT_FAILURE;
        }

        flags |= O_NONBLOCK;

        r = fcntl(fd, F_SETFL, flags);
        if (r < 0) {
                fprintf(stderr, "error: failed to set file descriptor flags: %m\n");
                return EXIT_FAILURE;
        }

        sigemptyset(&mask);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGUSR1);
        sigaddset(&mask, SIGCHLD);

        r = sigprocmask(SIG_BLOCK, &mask, NULL);
        if (r < 0) {
                fprintf(stderr, "error: failed to block reception of signals: %m\n");
                return EXIT_FAILURE;
        }

        sfd = signalfd(-1, &mask, 0);
        if (sfd < 0) {
                fprintf(stderr, "error: failed to create signal file descriptor: %m\n");
                return EXIT_FAILURE;
        }

        efd = epoll_create1(EPOLL_CLOEXEC);
        if (efd < 0) {
                fprintf(stderr, "error: failed to create epoll instance: %m\n");
                return EXIT_FAILURE;
        }

        ev.events = EPOLLIN;
        ev.data.fd = fd;
        r = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
        if (r < 0) {
                fprintf(stderr, "error: failed to add listening file descriptor to epoll instance: %m\n");
                return EXIT_FAILURE;
        }

        ev.events = EPOLLIN;
        ev.data.fd = sfd;
        r = epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &ev);
        if (r < 0) {
                fprintf(stderr,
                        "error: failed to add listening signal file descriptor to epoll instance: %m\n");
                return EXIT_FAILURE;
        }

        for (;;) {
                struct epoll_event event;
                int nfds;

                nfds = epoll_wait(efd, &event, 1, -1);
                if (nfds < 0) {
                        if (errno == EINTR)
                                continue;

                        fprintf(stderr, "error: failed to receive events from epoll instance: %m\n");
                        return EXIT_FAILURE;
                }

                if (event.data.fd == fd) {
                        int cfd;

                        cfd = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
                        if (cfd < 0) {
                                fprintf(stderr, "error: failed to accept the incomming connection: %m\n");
                                continue;
                        }

                        r = handle_connection(cfd, id);
                        if (r < 0) {
                                fprintf(stderr,
                                        "error: failed to handle the incomming connection, closing connection file descriptor\n");
                                continue;
                        }

                } else {
                        struct signalfd_siginfo fdsi;
                        ssize_t s;

                        s = read(sfd, &fdsi, sizeof(fdsi));
                        if (s != sizeof(fdsi)) {
                                fprintf(stderr, "error: failed to read from signal fd: %m\n");
                                continue;
                        }

                        r = handle_signal(fdsi.ssi_signo);
                        if (r > 0)
                                break;
                }
        }

        wait_for_workers();

        return EXIT_SUCCESS;
}
