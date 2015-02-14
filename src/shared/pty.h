/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2014 David Herrmann <dh.herrmann@gmail.com>

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

#include <stdbool.h>
#include <unistd.h>

#include "barrier.h"
#include "macro.h"
#include "sd-event.h"

typedef struct Pty Pty;

enum {
        PTY_CHILD,
        PTY_HUP,
        PTY_DATA,
};

typedef int (*pty_event_t) (Pty *pty, void *userdata, unsigned int event, const void *ptr, size_t size);

int pty_new(Pty **out);
Pty *pty_ref(Pty *pty);
Pty *pty_unref(Pty *pty);

#define _pty_unref_ _cleanup_(pty_unrefp)
DEFINE_TRIVIAL_CLEANUP_FUNC(Pty*, pty_unref);

Barrier *pty_get_barrier(Pty *pty);

bool pty_is_unknown(Pty *pty);
bool pty_is_parent(Pty *pty);
bool pty_is_child(Pty *pty);
bool pty_has_child(Pty *pty);
pid_t pty_get_child(Pty *pty);

bool pty_is_open(Pty *pty);
int pty_get_fd(Pty *pty);

int pty_make_child(Pty *pty);
int pty_make_parent(Pty *pty, pid_t child);
int pty_unlock(Pty *pty);
int pty_setup_child(Pty *pty);
void pty_close(Pty *pty);

int pty_attach_event(Pty *pty, sd_event *event, pty_event_t event_fn, void *event_fn_userdata);
void pty_detach_event(Pty *pty);

int pty_write(Pty *pty, const void *buf, size_t size);
int pty_signal(Pty *pty, int sig);
int pty_resize(Pty *pty, unsigned short term_width, unsigned short term_height);

pid_t pty_fork(Pty **out, sd_event *event, pty_event_t event_fn, void *event_fn_userdata, unsigned short initial_term_width, unsigned short initial_term_height);
