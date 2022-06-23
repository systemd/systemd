/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdio.h>

#include "sd-bus.h"

int bus_creds_dump(sd_bus_creds *c, FILE *f, bool terse);
int bus_pcap_header(size_t snaplen, const char *os, const char *app, FILE *f);
int bus_message_pcap_frame(sd_bus_message *m, size_t snaplen, FILE *f);

/* Use sd_bus_message_dump() instead, this implementation is split out for convenience. */
int _bus_message_dump(sd_bus_message *m, FILE *f, uint64_t flags);

int bus_message_get_blob(sd_bus_message *m, void **buffer, size_t *sz);
int bus_message_get_arg(sd_bus_message *m, unsigned i, const char **str);
int bus_message_get_arg_strv(sd_bus_message *m, unsigned i, char ***strv);
