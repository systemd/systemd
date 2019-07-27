#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include <systemd/sd-bus.h>
#define _cleanup_(f) __attribute__((cleanup(f)))

/* This is equivalent to:
 * busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 \
 *       org.freedesktop.systemd1.Manager GetUnitByPID $$
 *
 * Compile with 'cc -lsystemd print-unit-path.c'
 */

#define DESTINATION "org.freedesktop.systemd1"
#define PATH        "/org/freedesktop/systemd1"
#define INTERFACE   "org.freedesktop.systemd1.Manager"
#define MEMBER      "GetUnitByPID"

static int log_error(int error, const char *message) {
  fprintf(stderr, "%s: %s\n", message, strerror(-error));
  return error;
}

static int print_unit_path(sd_bus *bus) {
  _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
  _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
  _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
  int r;

  r = sd_bus_message_new_method_call(bus, &m,
                                     DESTINATION, PATH, INTERFACE, MEMBER);
  if (r < 0)
    return log_error(r, "Failed to create bus message");

  r = sd_bus_message_append(m, "u", (unsigned) getpid());
  if (r < 0)
    return log_error(r, "Failed to append to bus message");

  r = sd_bus_call(bus, m, -1, &error, &reply);
  if (r < 0)
    return log_error(r, "Call failed");

  const char *ans;
  r = sd_bus_message_read(reply, "o", &ans);
  if (r < 0)
    return log_error(r, "Failed to read reply");

  printf("Unit path is \"%s\".\n", ans);

  return 0;
}

int main(int argc, char **argv) {
  _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
  int r;

  r = sd_bus_open_system(&bus);
  if (r < 0)
    return log_error(r, "Failed to acquire bus");

  print_unit_path(bus);
}
