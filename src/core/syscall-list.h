/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foosyscalllisthfoo
#define foosyscalllisthfoo

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#if defined __x86_64__ && defined __ILP32__
/* The x32 ABI defines all of its syscalls with bit 30 set, which causes
   issues when attempting to use syscalls as simple indices into an array.
   Instead, use the syscall id & ~SYSCALL_MASK as the index, and | the
   internal id with the syscall mask as needed.
*/
#include <asm/unistd.h>
#define SYSCALL_TO_INDEX(x) ((x) & ~__X32_SYSCALL_BIT)
#define INDEX_TO_SYSCALL(x) ((x) | __X32_SYSCALL_BIT)
#else
#define SYSCALL_TO_INDEX(x) (x)
#define INDEX_TO_SYSCALL(x) (x)
#endif

const char *syscall_to_name(int id);
int syscall_from_name(const char *name);

int syscall_max(void);

#endif
