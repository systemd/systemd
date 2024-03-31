/* SPDX-License-Identifier: MIT-0 */

/* Implement the systemd notify protocol without external dependencies.
 * Supports both readiness notification on startup and on reloading,
 * according to the protocl defined at:
 * https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
 * This protocol is guaranteed to be stable as per:
 * https://systemd.io/PORTABILITY_AND_STABILITY/ */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define _cleanup_(f) __attribute__((cleanup(f)))

bool reloading = 0;
bool terminating = 0;

static void closep(int *fd) {
  if (!fd || *fd < 0)
    return;

  close(*fd);
  *fd = -1;
}

static int notify(const char *message) {
  size_t path_length, message_length;
  struct sockaddr_un socket_addr = {
    .sun_family = AF_UNIX,
  };
  _cleanup_(closep) int fd = -1;
  const char *socket_path;

  assert(message);

  message_length = strlen(message);
  if (message_length == 0) {
    perror("Message to send to $NOTIFY_SOCKET is empty");
    return -EINVAL;
  }

  socket_path = getenv("NOTIFY_SOCKET");
  if (!socket_path)
    return 0; /* Not running under systemd? Nothing to do */

  path_length = strlen(socket_path);
  /* Ensure there is room for NULL byte */
  if (path_length >= sizeof(socket_addr.sun_path)) {
    perror("$NOTIFY_SOCKET contains a path that is too long for AF_UNIX");
    return -E2BIG;
  }

  memcpy(socket_addr.sun_path, socket_path, path_length);

  fd = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (fd < 0) {
    perror("Failed to open $NOTIFY_SOCKET");
    return -errno;
  }

  if (connect(fd, (const struct sockaddr *)&socket_addr, sizeof(socket_addr)) != 0) {
    perror("Failed to connect to $NOTIFY_SOCKET");
    return -errno;
  }

  if (write(fd, message, message_length) != (ssize_t) message_length) {
    perror("Failed to write message to $NOTIFY_SOCKET");
    return -EPROTO;
  }

  return 1; /* Notified! */
}

static int notify_ready() {
  return notify("READY=1");
}

static int notify_reloading() {
  char reload_message[sizeof("RELOADING=1\nMONOTONIC_USEC=") + 20 + 1];
  struct timespec ts;
  uint64_t now;

  /* Notify systemd that we are reloading, including a CLOCK_MONOTONIC timestamp in usec
   * so that the program is compatible with a Type=notify-reload service. */

  if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
    perror("Failed to get current time");
    return -errno;
  }

  now = ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL;

  if (snprintf(reload_message, sizeof(reload_message), "RELOADING=1\nMONOTONIC_USEC=%" PRIu64, now) < 0) {
    perror("Failed to format reload message");
    return -EINVAL;
  }

  return notify(reload_message);
}

void signal_handler(int sig) {
    if (sig == SIGHUP)
        reloading = 1;
    else if (sig == SIGINT || sig == SIGTERM)
        terminating = 1;
}

int main(int argc, char **argv) {
  /* Setup signal handlers */
  struct sigaction sa = {
    .sa_handler = signal_handler,
    .sa_flags = SA_RESTART,
  };
  sigemptyset(&sa.sa_mask);
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  /* Now that all the preparations steps are done, signal readiness... */

  if (notify_ready() < 0) {
    perror("Failed to notify readiness to $NOTIFY_SOCKET");
    return EXIT_FAILURE;
  }

  while (!terminating) {
    if (reloading) {
      reloading = false;

      if (notify_reloading() < 0) {
        perror("Failed to notify reloading to $NOTIFY_SOCKET");
        return EXIT_FAILURE;
      }

      /* Do some reconfiguration work here... */

      if (notify_ready() < 0) {
        perror("Failed to notify readiness to $NOTIFY_SOCKET");
        return EXIT_FAILURE;
      }
    }

    sleep(5);
  }

  return EXIT_SUCCESS;
}
