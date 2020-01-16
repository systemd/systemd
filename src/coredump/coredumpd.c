#include <getopt.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "alloc-util.h"
#include "coredump.h"
#include "fd-util.h"
#include "io-util.h"
#include "log.h"
#include "main-func.h"
#include "pretty-print.h"
#include "socket-util.h"

static int process_socket(int fd) {
        _cleanup_iovw_free_free_ struct iovec_wrapper *iovw = NULL;
        _cleanup_close_ int input_fd = -1;
        Context context = {};
        struct iovec iovec;
        int r;

        assert(fd >= 0);

        log_debug("Processing coredump received on stdin...");

        iovw = iovw_new();
        if (!iovw)
                return log_oom();

        for (;;) {
                union {
                        struct cmsghdr cmsghdr;
                        uint8_t buf[CMSG_SPACE(sizeof(int))];
                } control = {};
                struct msghdr mh = {
                        .msg_control = &control,
                        .msg_controllen = sizeof(control),
                        .msg_iovlen = 1,
                };
                ssize_t n;
                ssize_t l;

                l = next_datagram_size_fd(fd);
                if (l < 0)
                        return log_error_errno(l, "Failed to determine datagram size to read: %m");

                iovec.iov_len = l;
                iovec.iov_base = malloc(l + 1);
                if (!iovec.iov_base)
                        return log_oom();

                mh.msg_iov = &iovec;

                n = recvmsg(fd, &mh, MSG_CMSG_CLOEXEC);
                if (n < 0)  {
                        free(iovec.iov_base);
                        return log_error_errno(errno, "Failed to receive datagram: %m");
                }

                /* The final zero-length datagram carries the file descriptor and tells us
                 * that we're done. */
                if (n == 0) {
                        struct cmsghdr *cmsg, *found = NULL;

                        free(iovec.iov_base);

                        CMSG_FOREACH(cmsg, &mh) {
                                if (cmsg->cmsg_level == SOL_SOCKET &&
                                    cmsg->cmsg_type == SCM_RIGHTS &&
                                    cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
                                        assert(!found);
                                        found = cmsg;
                                }
                        }

                        if (!found)
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "Coredump file descriptor missing.");

                        assert(input_fd < 0);
                        input_fd = *(int*) CMSG_DATA(found);
                        break;
                }

                /* Add trailing NUL byte, in case these are strings */
                ((char*) iovec.iov_base)[n] = 0;
                iovec.iov_len = (size_t) n;

                r = iovw_put(iovw, iovec.iov_base, iovec.iov_len);
                if (r < 0)
                        return r;

                cmsg_close_all(&mh);
        }

        /* Make sure we got all data we really need */
        assert(input_fd >= 0);

        r = coredump_save_context(&context, iovw);
        if (r < 0)
                return r;
#if 0
        /* Make sure we received at least all fields we need. */
        for (int i = 0; i < _META_MANDATORY_MAX; i++)
                if (!context.meta[i])
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Field '%s' has not been sent, aborting.",
                                               meta_field_names[i]);
#endif
        return coredump_submit(&context, iovw, input_fd);
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-coredump", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] [FORMAT FIELDS...]\n\n"
               "Find overridden configuration files.\n\n"
               "  -h --help           Show this help\n"
               "     --version        Show package version\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , link
        );

        return 0;
}

static int parse_argv(int argc, char **argv) {

        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                  },
                { "version",         no_argument,       NULL, ARG_VERSION          },
                {}
        };

        int c;

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case ARG_VERSION:
                        return version();

                case 'h':
                        return help();

                default:
                        assert_not_reached("Unhandled option");
                }

        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        /* When running as coredumpd mode, we know that neither PID1 nor
         * journald is the crashing process. Therefore it's safe to log as
         * usual. */
        log_setup_service();

        /* Ignore all parse errors */
        (void) coredump_parse_config();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = sd_listen_fds(false);
        if (r < 0)
                return log_error_errno(r, "Failed to determine the number of file descriptors: %m");
        if (r != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Received unexpected number of file descriptors.");

        return process_socket(SD_LISTEN_FDS_START);
}

DEFINE_MAIN_FUNCTION(run);
