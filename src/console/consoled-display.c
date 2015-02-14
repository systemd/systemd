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
#include "list.h"
#include "macro.h"
#include "util.h"

int display_new(Display **out, Session *s, grdev_display *display) {
        _cleanup_(display_freep) Display *d = NULL;

        assert(out);
        assert(s);
        assert(display);

        d = new0(Display, 1);
        if (!d)
                return -ENOMEM;

        d->session = s;
        d->grdev = display;
        d->width = grdev_display_get_width(display);
        d->height = grdev_display_get_height(display);
        LIST_PREPEND(displays_by_session, d->session->display_list, d);

        grdev_display_enable(display);

        *out = d;
        d = NULL;
        return 0;
}

Display *display_free(Display *d) {
        if (!d)
                return NULL;

        LIST_REMOVE(displays_by_session, d->session->display_list, d);
        free(d);

        return NULL;
}

void display_refresh(Display *d) {
        assert(d);

        d->width = grdev_display_get_width(d->grdev);
        d->height = grdev_display_get_height(d->grdev);
}

void display_render(Display *d, Workspace *w) {
        const grdev_display_target *target;

        assert(d);
        assert(w);

        GRDEV_DISPLAY_FOREACH_TARGET(d->grdev, target) {
                if (workspace_draw(w, target))
                        grdev_display_flip_target(d->grdev, target);
        }
}
