#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2016 Michael Karcher
  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sched.h>
#include <sys/syscall.h>

#include "log.h"
#include "macro.h"

/**
 * raw_clone() - uses clone to create a new process with clone flags
 * @flags: Flags to pass to the clone system call
 *
 * Uses the clone system call to create a new process with the cloning
 * flags and termination signal passed in the flags parameter. Opposed
 * to glibc's clone funtion, using this function does not set up a
 * separate stack for the child, but relies on copy-on-write semantics
 * on the one stack at a common virtual address, just as fork does.
 *
 * To obtain copy-on-write semantics, flags must not contain CLONE_VM,
 * and thus CLONE_THREAD and CLONE_SIGHAND (which require CLONE_VM) are
 * not usabale.
 * Additionally, as this function does not pass the ptid, newtls and ctid
 * parameters to the kernel, flags must not contain CLONE_PARENT_SETTID,
 * CLONE_CHILD_SETTID, CLONE_CHILD_CLEARTID or CLONE_SETTLS.
 *
 * Returns: 0 in the child process and the child process id in the parent.
 */
static inline int raw_clone(unsigned long flags) {
        assert((flags & (CLONE_VM|CLONE_PARENT_SETTID|CLONE_CHILD_SETTID|
                         CLONE_CHILD_CLEARTID|CLONE_SETTLS)) == 0);
#if defined(__s390x__) || defined(__s390__) || defined(__CRIS__)
        /* On s390/s390x and cris the order of the first and second arguments
         * of the raw clone() system call is reversed. */
        return (int) syscall(__NR_clone, NULL, flags);
#elif defined(__sparc__) && defined(__arch64__)
        {
                /**
                 * sparc64 always returns the other process id in %o0, and
                 * a boolean flag whether this is the child or the parent in
                 * %o1. Inline assembly is needed to get the flag returned
                 * in %o1.
                 */
                int in_child;
                int child_pid;
                asm volatile("mov %2, %%g1\n\t"
                             "mov %3, %%o0\n\t"
                             "mov 0 , %%o1\n\t"
                             "t 0x6d\n\t"
                             "mov %%o1, %0\n\t"
                             "mov %%o0, %1" :
                             "=r"(in_child), "=r"(child_pid) :
                             "i"(__NR_clone), "r"(flags) :
                             "%o1", "%o0", "%g1" );
                if (in_child)
                        return 0;
                else
                        return child_pid;
        }
#else
        return (int) syscall(__NR_clone, flags, NULL);
#endif
}
