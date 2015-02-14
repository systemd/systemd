/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <errno.h>
#include <stdlib.h>
#include "consoled.h"
#include "grdev.h"
#include "idev.h"
#include "list.h"
#include "macro.h"
#include "util.h"

int workspace_new(Workspace **out, Manager *m) {
        _cleanup_(workspace_unrefp) Workspace *w = NULL;
        int r;

        assert(out);

        w = new0(Workspace, 1);
        if (!w)
                return -ENOMEM;

        w->ref = 1;
        w->manager = m;
        LIST_PREPEND(workspaces_by_manager, m->workspace_list, w);

        r = terminal_new(&w->current, w);
        if (r < 0)
                return r;

        *out = w;
        w = NULL;
        return 0;
}

static void workspace_cleanup(Workspace *w) {
        Terminal *t;

        assert(w);
        assert(w->ref == 0);
        assert(w->manager);
        assert(!w->session_list);

        w->current = NULL;
        while ((t = w->terminal_list))
                terminal_free(t);

        LIST_REMOVE(workspaces_by_manager, w->manager->workspace_list, w);
        free(w);
}

Workspace *workspace_ref(Workspace *w) {
        assert(w);

        ++w->ref;
        return w;
}

Workspace *workspace_unref(Workspace *w) {
        if (!w)
                return NULL;

        assert(w->ref > 0);

        if (--w->ref == 0)
                workspace_cleanup(w);

        return NULL;
}

Workspace *workspace_attach(Workspace *w, Session *s) {
        assert(w);
        assert(s);

        LIST_PREPEND(sessions_by_workspace, w->session_list, s);
        workspace_refresh(w);
        return workspace_ref(w);
}

Workspace *workspace_detach(Workspace *w, Session *s) {
        assert(w);
        assert(s);
        assert(s->active_ws == w);

        LIST_REMOVE(sessions_by_workspace, w->session_list, s);
        workspace_refresh(w);
        return workspace_unref(w);
}

void workspace_refresh(Workspace *w) {
        uint32_t width, height;
        Terminal *t;
        Session *s;
        Display *d;

        assert(w);

        width = 0;
        height = 0;

        /* find out minimum dimension of all attached displays */
        LIST_FOREACH(sessions_by_workspace, s, w->session_list) {
                LIST_FOREACH(displays_by_session, d, s->display_list) {
                        assert(d->width > 0 && d->height > 0);

                        if (width == 0 || d->width < width)
                                width = d->width;
                        if (height == 0 || d->height < height)
                                height = d->height;
                }
        }

        /* either both are zero, or none is zero */
        assert(!(!width ^ !height));

        /* update terminal-sizes if dimensions changed */
        if (w->width != width || w->height != height) {
                w->width = width;
                w->height = height;

                LIST_FOREACH(terminals_by_workspace, t, w->terminal_list)
                        terminal_resize(t);

                workspace_dirty(w);
        }
}

void workspace_dirty(Workspace *w) {
        Session *s;

        assert(w);

        LIST_FOREACH(sessions_by_workspace, s, w->session_list)
                session_dirty(s);
}

void workspace_feed(Workspace *w, idev_data *data) {
        assert(w);
        assert(data);

        terminal_feed(w->current, data);
}

bool workspace_draw(Workspace *w, const grdev_display_target *target) {
        assert(w);
        assert(target);

        return terminal_draw(w->current, target);
}
