/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Djalal Harouni

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

#include <sys/types.h>
#include <sys/eventfd.h>

enum {
        EVENTFD_INIT,
        EVENTFD_START,
        EVENTFD_PARENT_SUCCEEDED,
        EVENTFD_PARENT_FAILED,
        EVENTFD_CHILD_SUCCEEDED,
        EVENTFD_CHILD_FAILED,
};

pid_t clone_with_eventfd(int flags, int eventfds[2]);

int eventfd_send_state(int efd, eventfd_t s);
int eventfd_recv_state(int efd, eventfd_t *e, eventfd_t s);

int eventfd_recv_start(int efd);
int eventfd_parent_succeeded(int efd);
int eventfd_child_succeeded(int efd);
