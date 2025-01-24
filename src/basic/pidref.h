/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct PidRef PidRef;

#include "macro.h"
#include "process-util.h"

/* An embeddable structure carrying a reference to a process. Supposed to be used when tracking processes
 * continuously. This combines a PID, a modern Linux pidfd and the 64bit inode number of the pidfd into one
 * structure. Note that depending on kernel support the pidfd might not be initialized, and if it is
 * initialized then fd_id might still not be initialized (because the concept was added to the kernel much
 * later than pidfds themselves).
 *
 * There are three special states a PidRef can be in:
 *
 * 1. It can be *unset*. Use pidref_is_set() to detect this case. Most operations attempted on such a PidRef
 *    will fail with -ESRCH. Use PIDREF_NULL for initializing a PidRef in this state.
 *
 * 2. It can be marked as *automatic*. This is a special state indicating that a process reference is
 *    supposed to be derived automatically from the current context. This is used by the Varlink/JSON
 *    dispatcher as indication that a PidRef shall be derived from the connection peer, but might be
 *    otherwise used too. When marked *automatic* the PidRef will also be considered *unset*, hence most
 *    operations will fail with -ESRCH, as above.
 *
 * 3. It can be marked as *remote*. This is useful when deserializing a PidRef structure from an IPC message
 *    or similar, and it has been determined that the given PID definitely doesn't refer to a local
 *    process. In this case the PidRef logic will refrain from trying to acquire a pidfd for the
 *    process. Moreover, most operations will fail with -EREMOTE. Only PidRef structures that are not marked
 *    *unset* can be marked *remote*.
 */
struct PidRef {
        pid_t pid;      /* > 0 if the PidRef is set, otherwise set to PID_AUTOMATIC if automatic mode is
                         * desired, or 0 otherwise. */
        int fd;         /* only valid if pidfd are available in the kernel, and we manage to get an fd. If we
                         * know that the PID is not from the local machine we set this to -EREMOTE, otherwise
                         * we use -EBADF as indicator the fd is invalid. */
        uint64_t fd_id; /* the inode number of pidfd. only useful in kernel 6.9+ where pidfds live in
                           their own pidfs and each process comes with a unique inode number */
};

#define PIDREF_NULL (PidRef) { .fd = -EBADF }

/* A special pidref value that we are using when a PID shall be automatically acquired from some surrounding
 * context, for example connection peer. Much like PIDREF_NULL it will be considered unset by
 * pidref_is_set(). */
#define PIDREF_AUTOMATIC (const PidRef) { .pid = PID_AUTOMATIC, .fd = -EBADF }

/* Turns a pid_t into a PidRef structure on-the-fly *without* acquiring a pidfd for it. (As opposed to
 * pidref_set_pid() which does so *with* acquiring one, see below) */
#define PIDREF_MAKE_FROM_PID(x) (PidRef) { .pid = (x), .fd = -EBADF }

static inline bool pidref_is_set(const PidRef *pidref) {
        return pidref && pidref->pid > 0;
}

bool pidref_is_automatic(const PidRef *pidref);

static inline bool pidref_is_remote(const PidRef *pidref) {
        /* If the fd is set to -EREMOTE we assume PidRef does not refer to a local PID, but on another
         * machine (and we just got the PidRef initialized due to deserialization of some RPC message) */
        return pidref_is_set(pidref) && pidref->fd == -EREMOTE;
}

int pidref_acquire_pidfd_id(PidRef *pidref);
bool pidref_equal(PidRef *a, PidRef *b);

/* This turns a pid_t into a PidRef structure, and acquires a pidfd for it, if possible. (As opposed to
 * PIDREF_MAKE_FROM_PID() above, which does not acquire a pidfd.) */
int pidref_set_pid(PidRef *pidref, pid_t pid);
int pidref_set_pidstr(PidRef *pidref, const char *pid);
int pidref_set_pidfd(PidRef *pidref, int fd);
int pidref_set_pidfd_take(PidRef *pidref, int fd); /* takes ownership of the passed pidfd on success */
int pidref_set_pidfd_consume(PidRef *pidref, int fd); /* takes ownership of the passed pidfd in both success and failure */
int pidref_set_parent(PidRef *ret);
static inline int pidref_set_self(PidRef *pidref) {
        return pidref_set_pid(pidref, 0);
}

bool pidref_is_self(PidRef *pidref);

void pidref_done(PidRef *pidref);
PidRef* pidref_free(PidRef *pidref);
DEFINE_TRIVIAL_CLEANUP_FUNC(PidRef*, pidref_free);

int pidref_copy(const PidRef *pidref, PidRef *ret);
int pidref_dup(const PidRef *pidref, PidRef **ret);

int pidref_new_from_pid(pid_t pid, PidRef **ret);

int pidref_kill(const PidRef *pidref, int sig);
int pidref_kill_and_sigcont(const PidRef *pidref, int sig);
int pidref_sigqueue(const PidRef *pidref, int sig, int value);

int pidref_wait(PidRef *pidref, siginfo_t *siginfo, int options);
int pidref_wait_for_terminate(PidRef *pidref, siginfo_t *ret);

static inline void pidref_done_sigkill_wait(PidRef *pidref) {
        if (!pidref_is_set(pidref))
                return;

        (void) pidref_kill(pidref, SIGKILL);
        (void) pidref_wait_for_terminate(pidref, NULL);
        pidref_done(pidref);
}

int pidref_verify(const PidRef *pidref);

#define TAKE_PIDREF(p) TAKE_GENERIC((p), PidRef, PIDREF_NULL)

extern const struct hash_ops pidref_hash_ops;
extern const struct hash_ops pidref_hash_ops_free; /* Has destructor call for pidref_free(), i.e. expects heap allocated PidRef as keys */
