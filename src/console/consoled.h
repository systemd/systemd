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

#include "grdev.h"
#include "idev.h"
#include "list.h"
#include "macro.h"
#include "pty.h"
#include "sd-bus.h"
#include "sd-event.h"
#include "sysview.h"
#include "term.h"
#include "unifont.h"

typedef struct Manager Manager;
typedef struct Session Session;
typedef struct Display Display;
typedef struct Workspace Workspace;
typedef struct Terminal Terminal;

/*
 * Terminals
 */

struct Terminal {
        Workspace *workspace;
        LIST_FIELDS(Terminal, terminals_by_workspace);

        term_utf8 utf8;
        term_parser *parser;
        term_screen *screen;
        Pty *pty;
};

int terminal_new(Terminal **out, Workspace *w);
Terminal *terminal_free(Terminal *t);

DEFINE_TRIVIAL_CLEANUP_FUNC(Terminal*, terminal_free);

void terminal_resize(Terminal *t);
void terminal_run(Terminal *t);
void terminal_feed(Terminal *t, idev_data *data);
bool terminal_draw(Terminal *t, const grdev_display_target *target);

/*
 * Workspaces
 */

struct Workspace {
        unsigned long ref;
        Manager *manager;
        LIST_FIELDS(Workspace, workspaces_by_manager);

        LIST_HEAD(Terminal, terminal_list);
        Terminal *current;

        LIST_HEAD(Session, session_list);
        uint32_t width;
        uint32_t height;
};

int workspace_new(Workspace **out, Manager *m);
Workspace *workspace_ref(Workspace *w);
Workspace *workspace_unref(Workspace *w);

DEFINE_TRIVIAL_CLEANUP_FUNC(Workspace*, workspace_unref);

Workspace *workspace_attach(Workspace *w, Session *s);
Workspace *workspace_detach(Workspace *w, Session *s);
void workspace_refresh(Workspace *w);

void workspace_dirty(Workspace *w);
void workspace_feed(Workspace *w, idev_data *data);
bool workspace_draw(Workspace *w, const grdev_display_target *target);

/*
 * Displays
 */

struct Display {
        Session *session;
        LIST_FIELDS(Display, displays_by_session);
        grdev_display *grdev;
        uint32_t width;
        uint32_t height;
};

int display_new(Display **out, Session *s, grdev_display *grdev);
Display *display_free(Display *d);

DEFINE_TRIVIAL_CLEANUP_FUNC(Display*, display_free);

void display_refresh(Display *d);
void display_render(Display *d, Workspace *w);

/*
 * Sessions
 */

struct Session {
        Manager *manager;
        sysview_session *sysview;
        grdev_session *grdev;
        idev_session *idev;

        LIST_FIELDS(Session, sessions_by_workspace);
        Workspace *my_ws;
        Workspace *active_ws;

        LIST_HEAD(Display, display_list);
        sd_event_source *redraw_src;
};

int session_new(Session **out, Manager *m, sysview_session *session);
Session *session_free(Session *s);

DEFINE_TRIVIAL_CLEANUP_FUNC(Session*, session_free);

void session_dirty(Session *s);

void session_add_device(Session *s, sysview_device *device);
void session_remove_device(Session *s, sysview_device *device);
void session_refresh_device(Session *s, sysview_device *device, struct udev_device *ud);

/*
 * Managers
 */

struct Manager {
        sd_event *event;
        sd_bus *sysbus;
        unifont *uf;
        sysview_context *sysview;
        grdev_context *grdev;
        idev_context *idev;
        LIST_HEAD(Workspace, workspace_list);
};

int manager_new(Manager **out);
Manager *manager_free(Manager *m);

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

int manager_run(Manager *m);
