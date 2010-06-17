/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foosddaemonhfoo
#define foosddaemonhfoo

/***
  Copyright 2010 Lennart Poettering

  Permission is hereby granted, free of charge, to any person
  obtaining a copy of this software and associated documentation files
  (the "Software"), to deal in the Software without restriction,
  including without limitation the rights to use, copy, modify, merge,
  publish, distribute, sublicense, and/or sell copies of the Software,
  and to permit persons to whom the Software is furnished to do so,
  subject to the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
  ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
***/

#include <sys/types.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Reference implementation of a few systemd related interfaces for
 * writing daemons. These interfaces are trivial to implement. To
 * simplify porting we provide this reference
 * implementation. Applications are welcome to reimplement the
 * algorithms described here, if they do not want to include these two
 * source files. */

/*
  Log levels for usage on stderr:

          fprintf(stderr, SD_NOTICE "Hello World!");

  This is similar to printk() usage in the kernel.
*/

#define SD_EMERG   "<0>"  /* system is unusable */
#define SD_ALERT   "<1>"  /* action must be taken immediately */
#define SD_CRIT    "<2>"  /* critical conditions */
#define SD_ERR     "<3>"  /* error conditions */
#define SD_WARNING "<4>"  /* warning conditions */
#define SD_NOTICE  "<5>"  /* normal but significant condition */
#define SD_INFO    "<6>"  /* informational */
#define SD_DEBUG   "<7>"  /* debug-level messages */

/* The first passed file descriptor is fd 3 */
#define SD_LISTEN_FDS_START 3

/* Returns how many file descriptors have been passed, or a negative
 * errno code on failure. Optionally, removes the $LISTEN_FDS and
 * $LISTEN_PID file descriptors from the environment (recommended, but
 * problematic in threaded environments). If r is the return value of
 * this function you'll find the file descriptors passed as fds
 * SD_LISTEN_FDS_START to SD_LISTEN_FDS_START+r-1. Returns a negative
 * errno style error code on failure. This function call ensures that
 * the FD_CLOEXEC flag is set for the passed file descriptors, to make
 * sure they are not passed on to child processes. If FD_CLOEXEC shall
 * not be set, the caller needs to unset it after this call for all file
 * descriptors that are used.*/
int sd_listen_fds(int unset_environment);

/* Helper call for identifying a passed file descriptor. Returns 1 if
 * the file descriptor is a FIFO in the file system stored under the
 * specified path, 0 otherwise. If path is NULL a path name check will
 * not be done and the call only verifies if the file descriptor
 * refers to a FIFO. Returns a negative errno style error code on
 * failure. */
int sd_is_fifo(int fd, const char *path);

/* Helper call for identifying a passed file descriptor. Returns 1 if
 * the file descriptor is a socket of the specified family (AF_INET,
 * ...) and type (SOCK_DGRAM, SOCK_STREAM, ...), 0 otherwise. If
 * family is 0 a socket family check will not be done. If type is 0 a
 * socket type check will not be done and the call only verifies if
 * the file descriptor refers to a socket. If listening is > 0 it is
 * verified that the socket is in listening mode. (i.e. listen() has
 * been called) If listening is == 0 it is verified that the socket is
 * not in listening mode. If listening is < 0 no listening mode check
 * is done. Returns a negative errno style error code on failure. */
int sd_is_socket(int fd, int family, int type, int listening);

/* Helper call for identifying a passed file descriptor. Returns 1 if
 * the file descriptor is an Internet socket, of the specified family
 * (either AF_INET or AF_INET6) and the specified type (SOCK_DGRAM,
 * SOCK_STREAM, ...), 0 otherwise. If version is 0 a protocol version
 * check is not done. If type is 0 a socket type check will not be
 * done. If port is 0 a socket port check will not be done. The
 * listening flag is used the same way as in sd_is_socket(). Returns a
 * negative errno style error code on failure. */
int sd_is_socket_inet(int fd, int family, int type, int listening, uint16_t port);

/* Helper call for identifying a passed file descriptor. Returns 1 if
 * the file descriptor is an AF_UNIX socket of the specified type
 * (SOCK_DGRAM, SOCK_STREAM, ...) and path, 0 otherwise. If type is 0
 * a socket type check will not be done. If path is NULL a socket path
 * check will not be done. For normal AF_UNIX sockets set length to
 * 0. For abstract namespace sockets set length to the length of the
 * socket name (including the initial 0 byte), and pass the full
 * socket path in path (including the initial 0 byte). The listening
 * flag is used the same way as in sd_is_socket(). Returns a negative
 * errno style error code on failure. */
int sd_is_socket_unix(int fd, int type, int listening, const char *path, size_t length);

/* Informs systemd about changed daemon state. This takes a numeber of
 * newline seperated environment-style variable assignments in a
 * string. The following strings are known:
 *
 *    READY=1      Tells systemd that daemon startup is finished (only
 *                 relevant for services of Type=notify). The passed
 *                 argument is a boolean "1" or "0". Since there is
 *                 little value in signalling non-readiness the only
 *                 value daemons should send is "READY=1".
 *
 *    STATUS=...   Passes a single-line status string back to systemd
 *                 that describes the daemon state. This is free-from
 *                 and can be used for various purposes: general state
 *                 feedback, fsck-like programs could pass completion
 *                 percentages and failing programs could pass a human
 *                 readable error message. Example: "STATUS=Completed
 *                 66% of file system check..."
 *
 *    ERRNO=...    If a daemon fails, the errno-style error code,
 *                 formatted as string. Example: "ERRNO=2" for ENOENT.
 *
 *    BUSERROR=... If a daemon fails, the D-Bus error-style error
 *                 code. Example: "BUSERROR=org.freedesktop.DBus.Error.TimedOut"
 *
 *    MAINPID=...  The main pid of a daemon, in case systemd did not
 *                 fork off the process itself. Example: "MAINPID=4711"
 *
 * Daemons can choose to send additional variables.
 *
 * Returns a negative errno-style error code on failure. Returns > 0
 * if systemd could be notified, 0 if it couldn't possibly because
 * systemd is not running.
 *
 * See sd_notifyf() for more complete examples.
 */
int sd_notify(int unset_environment, const char *state);

/* Similar to sd_send_state() but takes a format string.
 *
 * Example 1: A daemon could send the following after initialization:
 *
 * sd_notifyf(0, "READY=1\n"
 *               "STATUS=Processing requests...\n"
 *               "MAINPID=%lu",
 *               (unsigned long) getpid());
 *
 * Example 2: A daemon could send the following shortly before
 * exiting, on failure:
 *
 * sd_notifyf(0, "STATUS=Failed to start up: %s\n"
 *               "ERRNO=%i",
 *               strerror(errno),
 *               errno);
 */
int sd_notifyf(int unset_environment, const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif
