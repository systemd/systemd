/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2013 Intel Corporation. All rights reserved.
  Copyright (C) 2014 Tom Gundersen

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

#include "sd-dhcp-server.h"
#include "dhcp-server-internal.h"

sd_dhcp_server *sd_dhcp_server_ref(sd_dhcp_server *server) {
        if (server)
                assert_se(REFCNT_INC(server->n_ref) >= 2);

        return server;
}

sd_dhcp_server *sd_dhcp_server_unref(sd_dhcp_server *server) {
        if (server && REFCNT_DEC(server->n_ref) <= 0) {
                log_dhcp_server(server, "UNREF");

                sd_event_unref(server->event);
                free(server);
        }

        return NULL;
}

int sd_dhcp_server_new(sd_dhcp_server **ret) {
        _cleanup_dhcp_server_unref_ sd_dhcp_server *server = NULL;

        assert_return(ret, -EINVAL);

        server = new0(sd_dhcp_server, 1);
        if (!server)
                return -ENOMEM;

        server->n_ref = REFCNT_INIT;

        *ret = server;
        server = NULL;

        return 0;
}

int sd_dhcp_server_attach_event(sd_dhcp_server *server, sd_event *event, int priority) {
        int r;

        assert_return(server, -EINVAL);
        assert_return(!server->event, -EBUSY);

        if (event)
                server->event = sd_event_ref(event);
        else {
                r = sd_event_default(&server->event);
                if (r < 0)
                        return r;
        }

        server->event_priority = priority;

        return 0;
}

int sd_dhcp_server_detach_event(sd_dhcp_server *server) {
        assert_return(server, -EINVAL);

        server->event = sd_event_unref(server->event);

        return 0;
}

sd_event *sd_dhcp_server_get_event(sd_dhcp_server *server) {
        assert_return(server, NULL);

        return server->event;
}
