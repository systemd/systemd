/* SPDX-License-Identifier: MIT-0 */

/* Implements the LogControl interface as per specification:
 * https://www.freedesktop.org/software/systemd/man/org.freedesktop.LogControl.html
 *
 * Compile with 'cc logcontrol-example-varlink.c $(pkg-config --libs --cflags libsystemd)'
 *
 * To get and set log level via varlinkctl:
 *
 * $ varlinkctl call /run/example/varlink org.freedesktop.LogControl.GetLogLevel '{}'
 *   {"level":"info"}
 * $ varlinkctl call /run/example/varlink org.freedesktop.LogControl.SetLogLevel '{"level":"debug"}'
 *   {}
 * $ varlinkctl call /run/example/varlink org.freedesktop.LogControl.GetLogLevel '{}'
 *   {"level":"debug"}
 * $ varlinkctl call /run/example/varlink org.freedesktop.LogControl.GetSyslogIdentifier '{}'
 *   {"identifier":"example"}
 */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <syslog.h>
#include <systemd/sd-event.h>
#include <systemd/sd-journal.h>
#include <systemd/sd-varlink.h>

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

static int method_get_log_level(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

  object *o = userdata;

  if (sd_json_variant_elements(parameters) > 0)
    return sd_varlink_error_invalid_parameter(link, parameters);

  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_STRING("level", log_level_table[o->log_level]));
}

static int method_set_log_level(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

  object *o = userdata;
  const char *level = NULL;
  int r;

  static const sd_json_dispatch_field dispatch_table[] = {
    { "level", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, 0, 0 },
    {}
  };

  r = sd_varlink_dispatch(link, parameters, dispatch_table, &level);
  if (r != 0)
    return r;

  /* SetLogLevel with NULL level is a no-op */
  if (!level)
    return sd_varlink_reply(link, NULL);

  for (int i = 0; i <= LOG_DEBUG; i++)
    if (strcmp(level, log_level_table[i]) == 0) {
      o->log_level = i;
      setlogmask(LOG_UPTO(i));
      return sd_varlink_reply(link, NULL);
    }

  return sd_varlink_error(link, "org.freedesktop.LogControl.InvalidArgument", NULL);
}

static int method_get_log_target(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

  object *o = userdata;

  if (sd_json_variant_elements(parameters) > 0)
    return sd_varlink_error_invalid_parameter(link, parameters);

  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_STRING("target", log_target_table[o->log_target]));
}

static int method_set_log_target(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

  object *o = userdata;
  const char *target = NULL;
  int r;

  static const sd_json_dispatch_field dispatch_table[] = {
    { "target", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, 0, 0 },
    {}
  };

  r = sd_varlink_dispatch(link, parameters, dispatch_table, &target);
  if (r != 0)
    return r;

  /* SetLogTarget with NULL target is a no-op */
  if (!target)
    return sd_varlink_reply(link, NULL);

  for (LogTarget i = 0; i < _LOG_TARGET_MAX; i++)
    if (strcmp(target, log_target_table[i]) == 0) {
      o->log_target = i;
      return sd_varlink_reply(link, NULL);
    }

  return sd_varlink_error(link, "org.freedesktop.LogControl.InvalidArgument", NULL);
}

static int method_get_syslog_identifier(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

  object *o = userdata;

  if (sd_json_variant_elements(parameters) > 0)
    return sd_varlink_error_invalid_parameter(link, parameters);

  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_STRING("identifier", o->syslog_identifier));
}

int main(int argc, char **argv) {
  _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *server = NULL;
  _cleanup_(sd_event_unrefp) sd_event *event = NULL;

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

  /* Create a new Varlink server. SD_VARLINK_SERVER_INHERIT_USERDATA ensures
   * that connections inherit the server's userdata, so method callbacks
   * receive our object pointer.
   * https://www.freedesktop.org/software/systemd/man/sd_varlink_server_new.html
   */
  r = sd_varlink_server_new(&server, SD_VARLINK_SERVER_INHERIT_USERDATA);
  if (r < 0)
    return log_error(o.log_level, r, "sd_varlink_server_new()");

  /* Set server information for introspection */
  r = sd_varlink_server_set_info(server,
                                 "Example Vendor",
                                 "Example Product",
                                 "1.0",
                                 "https://example.org");
  if (r < 0)
    return log_error(o.log_level, r, "sd_varlink_server_set_info()");

  /* Set userdata that will be passed to method callbacks */
  sd_varlink_server_set_userdata(server, &o);

  /* Bind the org.freedesktop.LogControl methods
   * https://www.freedesktop.org/software/systemd/man/sd_varlink_server_bind_method.html
   */
  r = sd_varlink_server_bind_method_many(
                  server,
                  "org.freedesktop.LogControl.GetLogLevel", method_get_log_level,
                  "org.freedesktop.LogControl.SetLogLevel", method_set_log_level,
                  "org.freedesktop.LogControl.GetLogTarget", method_get_log_target,
                  "org.freedesktop.LogControl.SetLogTarget", method_set_log_target,
                  "org.freedesktop.LogControl.GetSyslogIdentifier", method_get_syslog_identifier);
  if (r < 0)
    return log_error(o.log_level, r, "sd_varlink_server_bind_method_many()");

  /* Listen on a socket path. In a real service activated by systemd, you would
   * use sd_varlink_server_listen_auto() to use the socket passed by systemd.
   * https://www.freedesktop.org/software/systemd/man/sd_varlink_server_listen_address.html
   */
  r = sd_varlink_server_listen_address(server, "/run/example/varlink", 0666);
  if (r < 0)
    return log_error(o.log_level, r, "sd_varlink_server_listen_address()");

  /* Create an event loop and attach the server to it */
  r = sd_event_new(&event);
  if (r < 0)
    return log_error(o.log_level, r, "sd_event_new()");

  r = sd_varlink_server_attach_event(server, event, 0);
  if (r < 0)
    return log_error(o.log_level, r, "sd_varlink_server_attach_event()");

  /* Run the event loop indefinitely, handling connections and method calls */
  r = sd_event_loop(event);
  if (r < 0)
    return log_error(o.log_level, r, "sd_event_loop()");

  return 0;
}
