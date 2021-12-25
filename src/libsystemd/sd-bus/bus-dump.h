/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdio.h>

#include "sd-bus.h"

int bus_creds_dump(sd_bus_creds *c, FILE *f, bool terse);

int bus_pcap_header(size_t snaplen, const char *os, const char *app, FILE *f);
int bus_message_pcap_frame(sd_bus_message *m, size_t snaplen, FILE *f);
