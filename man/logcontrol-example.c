/* SPDX-License-Identifier: MIT-0 */

/* Implements the LogControl1 interface as per specification:
 * https://www.freedesktop.org/software/systemd/man/org.freedesktop.LogControl1.html
 *
 * Compile with 'cc logcontrol-example.c $(pkg-config --libs --cflags libsystemd)'
 *
 * To get and set properties via busctl:
 *
 * $ busctl --user get-property org.freedesktop.Example \
 *                              /org/freedesktop/LogControl1 \
 *                              org.freedesktop.LogControl1 \
 *                              SyslogIdentifier
 *   s "example"
 * $ busctl --user get-property org.freedesktop.Example \
 *                              /org/freedesktop/LogControl1 \
 *                              org.freedesktop.LogControl1 \
 *                              LogTarget
 *   s "journal"
 * $ busctl --user get-property org.freedesktop.Example \
 *                              /org/freedesktop/LogControl1 \
 *                              org.freedesktop.LogControl1 \
 *                              LogLevel
 *   s "info"
 * $ busctl --user set-property org.freedesktop.Example \
 *                              /org/freedesktop/LogControl1 \
 *                              org.freedesktop.LogControl1 \
 *                              LogLevel \
 *                              "s" debug
 * $ busctl --user get-property org.freedesktop.Example \
 *                              /org/freedesktop/LogControl1 \
 *                              org.freedesktop.LogControl1 \
 *                              LogLevel
 *   s "debug"
 */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-journal.h>

#define _cleanup_(f) __attribute__((cleanup(f)))

static int log_error(int log_level, int error, const char *str) {
  sd_journal_print(log_level, "%s failed: %s", str, strerror(-error));
  return error;
}

typedef enum LogTarget {
  LOG_TARGET_JOURNAL,
  LOG_TARGET_KMSG,
  LOG_TARGET_SYSLOG,
  LOG_TARGET_CONSOLE,
  _LOG_TARGET_MAX,
} LogTarget;

static const char* const log_target_table[_LOG_TARGET_MAX] = {
  [LOG_TARGET_JOURNAL] = "journal",
  [LOG_TARGET_KMSG]    = "kmsg",
  [LOG_TARGET_SYSLOG]  = "syslog",
  [LOG_TARGET_CONSOLE] = "console",
};

static const char* const log_level_table[LOG_DEBUG + 1] = {
  [LOG_EMERG]   = "emerg",
  [LOG_ALERT]   = "alert",
  [LOG_CRIT]    = "crit",
  [LOG_ERR]     = "err",
  [LOG_WARNING] = "warning",
  [LOG_NOTICE]  = "notice",
  [LOG_INFO]    = "info",
  [LOG_DEBUG]   = "debug",
};

typedef struct object {
  const char *syslog_identifier;
  LogTarget log_target;
  int log_level;
} object;

static int property_get(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

  object *o = userdata;

  if (strcmp(property, "LogLevel") == 0)
    return sd_bus_message_append(reply, "s", log_level_table[o->log_level]);

  if (strcmp(property, "LogTarget") == 0)
    return sd_bus_message_append(reply, "s", log_target_table[o->log_target]);

  if (strcmp(property, "SyslogIdentifier") == 0)
    return sd_bus_message_append(reply, "s", o->syslog_identifier);

  return sd_bus_error_setf(error,
                           SD_BUS_ERROR_UNKNOWN_PROPERTY,
                           "Unknown property '%s'",
                           property);
}

static int property_set(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

  object *o = userdata;
  const char *value;
  int r;

  r = sd_bus_message_read(message, "s", &value);
  if (r < 0)
    return r;

  if (strcmp(property, "LogLevel") == 0) {
    int i;
    for (i = 0; i < LOG_DEBUG + 1; i++)
      if (strcmp(value, log_level_table[i]) == 0) {
        o->log_level = i;
        setlogmask(LOG_UPTO(i));
        return 0;
      }

    return sd_bus_error_setf(error,
                             SD_BUS_ERROR_INVALID_ARGS,
                             "Invalid value for LogLevel: '%s'",
                             value);
  }

  if (strcmp(property, "LogTarget") == 0) {
    LogTarget i;
    for (i = 0; i < _LOG_TARGET_MAX; i++)
      if (strcmp(value, log_target_table[i]) == 0) {
        o->log_target = i;
        return 0;
      }

    return sd_bus_error_setf(error,
                             SD_BUS_ERROR_INVALID_ARGS,
                             "Invalid value for LogTarget: '%s'",
                             value);
  }

  return sd_bus_error_setf(error,
                           SD_BUS_ERROR_UNKNOWN_PROPERTY,
                           "Unknown property '%s'",
                           property);
}

/* https://www.freedesktop.org/software/systemd/man/sd_bus_add_object.html
 */
static const sd_bus_vtable vtable[] = {
  SD_BUS_VTABLE_START(0),
  SD_BUS_WRITABLE_PROPERTY(
    "LogLevel", "s",
    property_get, property_set,
    0,
    0),
  SD_BUS_WRITABLE_PROPERTY(
    "LogTarget", "s",
    property_get, property_set,
    0,
    0),
  SD_BUS_PROPERTY(
    "SyslogIdentifier", "s",
    property_get,
    0,
    SD_BUS_VTABLE_PROPERTY_CONST),
  SD_BUS_VTABLE_END
};

int main(int argc, char **argv) {
  /* The bus should be relinquished before the program terminates. The cleanup
   * attribute allows us to do it nicely and cleanly whenever we exit the
   * block.
   */
  _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;

  object o = {
    .log_level = LOG_INFO,
    .log_target = LOG_TARGET_JOURNAL,
    .syslog_identifier = "example",
  };
  int r;

  /* https://man7.org/linux/man-pages/man3/setlogmask.3.html
   * Programs using syslog() instead of sd_journal can use this API to cut logs
   * emission at the source.
   */
  setlogmask(LOG_UPTO(o.log_level));

  /* Acquire a connection to the bus, letting the library work out the details.
   * https://www.freedesktop.org/software/systemd/man/sd_bus_default.html
   */
  r = sd_bus_default(&bus);
  if (r < 0)
    return log_error(o.log_level, r, "sd_bus_default()");

  /* Publish an interface on the bus, specifying our well-known object access
   * path and public interface name.
   * https://www.freedesktop.org/software/systemd/man/sd_bus_add_object.html
   * https://dbus.freedesktop.org/doc/dbus-tutorial.html
   */
  r = sd_bus_add_object_vtable(bus, NULL,
                               "/org/freedesktop/LogControl1",
                               "org.freedesktop.LogControl1",
                               vtable,
                               &o);
  if (r < 0)
    return log_error(o.log_level, r, "sd_bus_add_object_vtable()");

  /* By default, the service is assigned an ephemeral name. Also add a fixed
   * one, so that clients know whom to call.
   * https://www.freedesktop.org/software/systemd/man/sd_bus_request_name.html
   */
  r = sd_bus_request_name(bus, "org.freedesktop.Example", 0);
  if (r < 0)
    return log_error(o.log_level, r, "sd_bus_request_name()");

  for (;;) {
    /* https://www.freedesktop.org/software/systemd/man/sd_bus_wait.html
     */
    r = sd_bus_wait(bus, UINT64_MAX);
    if (r < 0)
      return log_error(o.log_level, r, "sd_bus_wait()");
    /* https://www.freedesktop.org/software/systemd/man/sd_bus_process.html
     */
    r = sd_bus_process(bus, NULL);
    if (r < 0)
      return log_error(o.log_level, r, "sd_bus_process()");
  }

  /* https://www.freedesktop.org/software/systemd/man/sd_bus_release_name.html
   */
  r = sd_bus_release_name(bus, "org.freedesktop.Example");
  if (r < 0)
    return log_error(o.log_level, r, "sd_bus_release_name()");

  return 0;
}
