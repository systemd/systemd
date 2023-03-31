/* SPDX-License-Identifier: MIT-0 */

/* This is equivalent to:
 * busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 \
 *       org.freedesktop.systemd1.Manager GetUnitByPID $$
 *
 * Compile with 'cc print-unit-path-call-method.c -lsystemd'
 */

#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <systemd/sd-bus.h>

#define _cleanup_(f) __attribute__((cleanup(f)))
#define DESTINATION "org.freedesktop.systemd1"
#define PATH        "/org/freedesktop/systemd1"
#define INTERFACE   "org.freedesktop.systemd1.Manager"
#define MEMBER      "GetUnitByPID"

static int log_error(int error, const char *message) {
  errno = -error;
  fprintf(stderr, "%s: %m\n", message);
  return error;
}

int main(int argc, char **argv) {
  _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
  _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
  _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
  int r;

  r = sd_bus_open_system(&bus);
  if (r < 0)
    return log_error(r, "Failed to acquire bus");

  r = sd_bus_call_method(bus, DESTINATION, PATH, INTERFACE, MEMBER, &error, &reply, "u", (unsigned) getpid());
  if (r < 0)
    return log_error(r, MEMBER " call failed");

  const char *ans;
  r = sd_bus_message_read(reply, "o", &ans);
  if (r < 0)
    return log_error(r, "Failed to read reply");

  printf("Unit path is \"%s\".\n", ans);

  return 0;
}
