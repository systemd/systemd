/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

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

#include "networkd.h"
#include "net-util.h"
#include "path-util.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "list.h"

void bridge_free(Bridge *bridge) {
        bridge_join_callback *callback;

        if (!bridge)
                return;

        while ((callback = bridge->callbacks)) {
                LIST_REMOVE(callbacks, bridge->callbacks, callback);
                free(callback);
        }

        if (bridge->name)
                hashmap_remove(bridge->manager->bridges, bridge->name);

        free(bridge->filename);

        free(bridge->description);
        free(bridge->name);

        free(bridge);
}

int bridge_get(Manager *manager, const char *name, Bridge **ret) {
        Bridge *bridge;

        assert(manager);
        assert(name);
        assert(ret);

        if (manager_should_reload(manager))
                manager_load_config(manager);

        bridge = hashmap_get(manager->bridges, name);
        if (!bridge) {
                *ret = NULL;
                return -ENOENT;
        }

        *ret = bridge;

        return 0;
}

static int bridge_enter_failed(Bridge *bridge) {
        bridge->state = BRIDGE_STATE_FAILED;

        return 0;
}

static int bridge_join_ready(Bridge *bridge, Link* link, sd_rtnl_message_handler_t callback) {
        _cleanup_sd_rtnl_message_unref_ sd_rtnl_message *req = NULL;
        int r;

        assert(bridge);
        assert(bridge->state == BRIDGE_STATE_READY);
        assert(link);
        assert(callback);

        r = sd_rtnl_message_link_new(RTM_SETLINK, link->ifindex, &req);
        if (r < 0) {
                log_error("Could not allocate RTM_SETLINK message: %s",
                          strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u32(req, IFLA_MASTER, bridge->link->ifindex);
        if (r < 0) {
                log_error("Could not append IFLA_MASTER attribute: %s",
                          strerror(-r));
                return r;
        }

        r = sd_rtnl_call_async(bridge->manager->rtnl, req, callback, link, 0, NULL);
        if (r < 0) {
                log_error("Could not send rtnetlink message: %s", strerror(-r));
                return r;
        }

        return 0;
}

static int bridge_enter_ready(Bridge *bridge) {
        bridge_join_callback *callback;

        bridge->state = BRIDGE_STATE_READY;

        log_info("Bridge '%s' ready", bridge->name);

        LIST_FOREACH(callbacks, callback, bridge->callbacks) {
                /* join the links that were attempted to be joined befor the
                 * link was ready */
                bridge_join_ready(bridge, callback->link, callback->callback);
        }

        return 0;
}

static int bridge_create_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        Bridge *bridge = userdata;
        int r;

        assert(bridge->state == BRIDGE_STATE_CREATING);

        r = sd_rtnl_message_get_errno(m);
        if (r < 0) {
                log_warning("Bridge '%s' failed: %s", bridge->name, strerror(-r));
                bridge_enter_failed(bridge);

                return 1;
        }

        if (bridge->link)
                bridge_enter_ready(bridge);
        else
                bridge->state = BRIDGE_STATE_CREATED;

        return 1;
}

static int bridge_create(Bridge *bridge) {
        _cleanup_sd_rtnl_message_unref_ sd_rtnl_message *req = NULL;
        int r;

        assert(bridge);
        assert(bridge->state == _BRIDGE_STATE_INVALID);
        assert(bridge->name);
        assert(bridge->manager);
        assert(bridge->manager->rtnl);

        r = sd_rtnl_message_link_new(RTM_NEWLINK, 0, &req);
        if (r < 0) {
                log_error("Could not allocate RTM_NEWLINK message: %s",
                          strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_string(req, IFLA_IFNAME, bridge->name);
        if (r < 0) {
                log_error("Could not append IFLA_IFNAME attribute: %s",
                          strerror(-r));
                return r;
        }

        r = sd_rtnl_message_open_container(req, IFLA_LINKINFO);
        if (r < 0) {
                log_error("Colud not open IFLA_LINKINFO container: %s",
                          strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_string(req, IFLA_INFO_KIND, "bridge");
        if (r < 0) {
                log_error("Could not append IFLA_INFO_KIND attribute: %s",
                          strerror(-r));
                return r;
        }

        r = sd_rtnl_message_close_container(req);
        if (r < 0) {
                log_error("Could not close IFLA_LINKINFO container %s",
                          strerror(-r));
                return r;
        }

        r = sd_rtnl_call_async(bridge->manager->rtnl, req, &bridge_create_handler, bridge, 0, NULL);
        if (r < 0) {
                log_error("Could not send rtnetlink message: %s", strerror(-r));
                return r;
        }

        log_info("Creating bridge '%s'", bridge->name);

        bridge->state = BRIDGE_STATE_CREATING;

        return 0;
}

int bridge_join(Bridge *bridge, Link *link, sd_rtnl_message_handler_t callback) {
        if (bridge->state == BRIDGE_STATE_READY) {
                bridge_join_ready(bridge, link, callback);
        } else {
                /* the bridge is not yet read, save this request for when it is*/
                bridge_join_callback *cb;

                cb = new0(bridge_join_callback, 1);
                if (!cb)
                        return log_oom();

                cb->callback = callback;
                cb->link = link;

                LIST_PREPEND(callbacks, bridge->callbacks, cb);
        }

        return 0;
}

int bridge_set_link(Manager *m, Link *link) {
        Bridge *bridge;

        bridge = hashmap_get(m->bridges, link->ifname);
        if (!bridge)
                return -ENOENT;

        if (bridge->link && bridge->link != link)
                return -EEXIST;

        bridge->link = link;

        if (bridge->state == BRIDGE_STATE_CREATED)
                bridge_enter_ready(bridge);

        return 0;
}

static int bridge_load_one(Manager *manager, const char *filename) {
        _cleanup_bridge_free_ Bridge *bridge = NULL;
        _cleanup_fclose_ FILE *file = NULL;
        int r;

        assert(manager);
        assert(filename);

        file = fopen(filename, "re");
        if (!file) {
                if (errno == ENOENT)
                        return 0;
                else
                        return errno;
        }

        bridge = new0(Bridge, 1);
        if (!bridge)
                return log_oom();

        bridge->manager = manager;
        bridge->state = _BRIDGE_STATE_INVALID;

        r = config_parse(NULL, filename, file, "Bridge\0", config_item_perf_lookup,
                        (void*) network_gperf_lookup, false, false, bridge);
        if (r < 0) {
                log_warning("Could not parse config file %s: %s", filename, strerror(-r));
                return r;
        } else
                log_debug("Parsed configuration file %s", filename);

        if (!bridge->name) {
                log_warning("Bridge without Name configured in %s. Ignoring", filename);
                return 0;
        }

        bridge->filename = strdup(filename);
        if (!bridge->filename)
                return log_oom();

        r = hashmap_put(bridge->manager->bridges, bridge->name, bridge);
        if (r < 0)
                return r;

        LIST_HEAD_INIT(bridge->callbacks);

        r = bridge_create(bridge);
        if (r < 0)
                return r;

        bridge = NULL;

        return 0;
}

int bridge_load(Manager *manager) {
        Bridge *bridge;
        char **files, **f;
        int r;

        assert(manager);

        while ((bridge = hashmap_first(manager->bridges)))
                bridge_free(bridge);

        r = conf_files_list_strv(&files, ".netdev", NULL, (const char **)manager->network_dirs);
        if (r < 0) {
                log_error("Failed to enumerate netdev files: %s", strerror(-r));
                return r;
        }

        STRV_FOREACH_BACKWARDS(f, files) {
                r = bridge_load_one(manager, *f);
                if (r < 0)
                        return r;
        }

        strv_free(files);

        return 0;
}
