/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2014 David Herrmann

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

#include "sd-bus.h"

#include "bus-xml-policy.h"

typedef struct Proxy Proxy;
typedef struct ProxyActivation ProxyActivation;

#define PROXY_ACTIVATIONS_MAX (16) /* max parallel activation requests */

struct Proxy {
        sd_bus *local_bus;
        struct ucred local_creds;
        int local_in;
        int local_out;

        sd_bus *destination_bus;

        Set *owned_names;
        SharedPolicy *policy;

        LIST_HEAD(ProxyActivation, activations);
        size_t n_activations;

        bool got_hello : 1;
        bool queue_overflow : 1;
        bool message_matched : 1;
        bool synthetic_matched : 1;
};

struct ProxyActivation {
        LIST_FIELDS(ProxyActivation, activations_by_proxy);
        Proxy *proxy;
        sd_bus_message *request;
        sd_bus_slot *slot;
};

int proxy_new(Proxy **out, int in_fd, int out_fd, const char *dest);
Proxy *proxy_free(Proxy *p);

int proxy_set_policy(Proxy *p, SharedPolicy *policy, char **configuration);
int proxy_hello_policy(Proxy *p, uid_t original_uid);
int proxy_match(sd_bus_message *m, void *userdata, sd_bus_error *error);
int proxy_run(Proxy *p);

DEFINE_TRIVIAL_CLEANUP_FUNC(Proxy*, proxy_free);
