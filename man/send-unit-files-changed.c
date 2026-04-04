/* SPDX-License-Identifier: MIT-0 */

#include <systemd/sd-bus.h>
#define _cleanup_(f) __attribute__((cleanup(f)))
#define _cleanup_unref(x) _cleanup_(x ## _unrefp)

int send_unit_files_changed(sd_bus *bus) {
  _cleanup_unref(sd_bus_message) sd_bus_message *message = NULL;
  int r;

  r = sd_bus_message_new_signal(bus, &message,
                                "/org/freedesktop/systemd1",
                                "org.freedesktop.systemd1.Manager",
                                "UnitFilesChanged");
  if (r < 0)
    return r;

  return sd_bus_send(bus, message, NULL);
}
