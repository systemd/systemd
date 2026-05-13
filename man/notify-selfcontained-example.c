/* SPDX-License-Identifier: MIT-0 */

/* Implement the systemd notify protocol without external dependencies.
 * Supports both readiness notification on startup and on reloading,
 * according to the protocol defined at:
 * https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
 * This protocol is guaranteed to be stable as per:
 * https://systemd.io/PORTABILITY_AND_STABILITY/ */

#define _GNU_SOURCE 1
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define _cleanup_(f) __attribute__((cleanup(f)))

static void closep(int *fd) {
  if (!fd || *fd < 0)
    return;

  close(*fd);
  *fd = -1;
}

static int notify(const char *message) {
  union sockaddr_union {
    struct sockaddr sa;
    struct sockaddr_un sun;
  } socket_addr = {
    .sun.sun_family = AF_UNIX,
  };
  size_t path_length, message_length;
  _cleanup_(closep) int fd = -1;
  const char *socket_path;

  /* Verify the argument first */
  if (!message)
    return -EINVAL;

  message_length = strlen(message);
  if (message_length == 0)
    return -EINVAL;

  /* If the variable is not set, the protocol is a noop */
  socket_path = getenv("NOTIFY_SOCKET");
  if (!socket_path)
    return 0; /* Not set? Nothing to do */

  /* Only AF_UNIX is supported, with path or abstract sockets */
  if (socket_path[0] != '/' && socket_path[0] != '@')
    return -EAFNOSUPPORT;

  path_length = strlen(socket_path);
  /* Ensure there is room for NUL byte */
  if (path_length >= sizeof(socket_addr.sun.sun_path))
    return -E2BIG;

  memcpy(socket_addr.sun.sun_path, socket_path, path_length);

  /* Support for abstract socket */
  if (socket_addr.sun.sun_path[0] == '@')
    socket_addr.sun.sun_path[0] = 0;

  fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
  if (fd < 0)
    return -errno;

  if (connect(fd, &socket_addr.sa, offsetof(struct sockaddr_un, sun_path) + path_length) != 0)
    return -errno;

  ssize_t written = write(fd, message, message_length);
  if (written != (ssize_t) message_length)
    return written < 0 ? -errno : -EPROTO;

  return 1; /* Notified! */
}

static int notify_ready(void) {
  return notify("READY=1");
}

static int notify_reloading(void) {
  /* A buffer with length sufficient to format the maximum UINT64 value. */
  char reload_message[sizeof("RELOADING=1\nMONOTONIC_USEC=18446744073709551615")];
  struct timespec ts;
  uint64_t now;

  /* Notify systemd that we are reloading, including a CLOCK_MONOTONIC timestamp in usec
   * so that the program is compatible with a Type=notify-reload service. */

  if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
    return -errno;

  if (ts.tv_sec < 0 || ts.tv_nsec < 0 ||
      (uint64_t) ts.tv_sec > (UINT64_MAX - (ts.tv_nsec / 1000ULL)) / 1000000ULL)
    return -EINVAL;

  now = (uint64_t) ts.tv_sec * 1000000ULL + (uint64_t) ts.tv_nsec / 1000ULL;

  if (snprintf(reload_message, sizeof(reload_message), "RELOADING=1\nMONOTONIC_USEC=%" PRIu64, now) < 0)
    return -EINVAL;

  return notify(reload_message);
}

static int notify_stopping(void) {
  return notify("STOPPING=1");
}

static volatile sig_atomic_t reloading = 0;
static volatile sig_atomic_t terminating = 0;

static void signal_handler(int sig) {
  if (sig == SIGHUP)
    reloading = 1;
  else if (sig == SIGINT || sig == SIGTERM)
    terminating = 1;
}

int main(int argc, char **argv) {
  struct sigaction sa = {
    .sa_handler = signal_handler,
    .sa_flags = SA_RESTART,
  };
  int r;

  /* Setup signal handlers */
  sigemptyset(&sa.sa_mask);
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  /* Do more service initialization work here … */

  /* Now that all the preparations steps are done, signal readiness */

  r = notify_ready();
  if (r < 0) {
    fprintf(stderr, "Failed to notify readiness to $NOTIFY_SOCKET: %s\n", strerror(-r));
    return EXIT_FAILURE;
  }

  while (!terminating) {
    if (reloading) {
      reloading = false;

      /* As a separate but related feature, we can also notify the manager
       * when reloading configuration. This allows accurate state-tracking,
       * and also automated hook-in of 'systemctl reload' without having to
       * specify manually an ExecReload= line in the unit file. */

      r = notify_reloading();
      if (r < 0) {
        fprintf(stderr, "Failed to notify reloading to $NOTIFY_SOCKET: %s\n", strerror(-r));
        return EXIT_FAILURE;
      }

      /* Do some reconfiguration work here … */

      r = notify_ready();
      if (r < 0) {
        fprintf(stderr, "Failed to notify readiness to $NOTIFY_SOCKET: %s\n", strerror(-r));
        return EXIT_FAILURE;
      }
    }

    /* Do some daemon work here … */
    sleep(5);
  }

  r = notify_stopping();
  if (r < 0) {
    fprintf(stderr, "Failed to report termination to $NOTIFY_SOCKET: %s\n", strerror(-r));
    return EXIT_FAILURE;
  }

  /* Do some shutdown work here … */

  return EXIT_SUCCESS;
}
