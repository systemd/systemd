/* SPDX-License-Identifier: MIT-0 */

#define _GNU_SOURCE 1
#include <errno.h>
#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <systemd/sd-journal.h>
#include <systemd/sd-daemon.h>

int main(int argc, char *argv[]) {
  int fd;
  FILE *log;

  fd = sd_journal_stream_fd("test", LOG_INFO, 1);
  if (fd < 0) {
    fprintf(stderr, "Failed to create stream fd: %s\n", strerror(-fd));
    return 1;
  }

  log = fdopen(fd, "w");
  if (!log) {
    fprintf(stderr, "Failed to create file object: %s\n", strerror(errno));
    close(fd);
    return 1;
  }
  fprintf(log, "Hello World!\n");
  fprintf(log, SD_WARNING "This is a warning!\n");
  fclose(log);
  return 0;
}
