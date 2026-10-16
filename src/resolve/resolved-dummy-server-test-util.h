/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"

#include "forward.h"

/* A dummy DNS server for testing resolved, serving UDP and TCP on the same address. The names it knows
 * about, and how it replies to them, are documented in resolved-dummy-server-test-util.c. */

typedef struct DummyServer DummyServer;

/* The address all successful lookups of the *.stream.test names resolve to. */
#define DUMMY_SERVER_STREAM_TEST_ADDRESS "10.123.97.1"

int dummy_server_new(sd_event *event, const char *address, DummyServer **ret);
DummyServer* dummy_server_free(DummyServer *s);
DEFINE_TRIVIAL_CLEANUP_FUNC(DummyServer*, dummy_server_free);
