#define _GNU_SOURCE
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <grp.h>

#define errExit(msg) do { perror(msg); exit(EXIT_FAILURE); } while (0)

struct child_args {
   int    pipe_fd[2];  /* Pipe used to synchronize parent and child */
};

static void usage(char *pname) {
        fprintf(stderr, "Options can be:\n");
        fprintf(stderr, "\t-M uid_map  Specify UID map for user namespace\n");
        fprintf(stderr, "\t-G gid_map  Specify GID map for user namespace\n");

        exit(EXIT_FAILURE);
}

static void update_map(char *mapping, char *map_file) {
        int fd, j;
        size_t map_len;

        map_len = strlen(mapping);

        fd = open(map_file, O_RDWR);
        if (fd == -1) {
                fprintf(stderr, "ERROR: open %s: %s\n", map_file, strerror(errno));
                exit(EXIT_FAILURE);
        }

        if (write(fd, mapping, map_len) != map_len) {
                fprintf(stderr, "ERROR: write %s: %s\n", map_file, strerror(errno));
                exit(EXIT_FAILURE);
        }

        close(fd);
}

static void proc_setgroups_write(pid_t child_pid, char *str) {
        char setgroups_path[PATH_MAX];
        int fd;

        snprintf(setgroups_path, PATH_MAX, "/proc/%ld/setgroups", (long) child_pid);

        fd = open(setgroups_path, O_RDWR);
        if (fd == -1) {
                if (errno != ENOENT)
                        fprintf(stderr, "ERROR: open %s: %s\n", setgroups_path, strerror(errno));
                return;
        }

        if (write(fd, str, strlen(str)) == -1)
                fprintf(stderr, "ERROR: write %s: %s\n", setgroups_path, strerror(errno));

        close(fd);
}

static int child_func(void *arg) {
        struct child_args *args = (struct child_args *) arg;
        char ch;

        close(args->pipe_fd[1]);
        if (read(args->pipe_fd[0], &ch, 1) != 0) {
                fprintf(stderr, "Failure in child: read from pipe returned != 0\n");
                exit(EXIT_FAILURE);
        }

        mount("tmpfs", "/tmp", "tmpfs", MS_MGC_VAL, "mode=777,uid=0,gid=0");
        if (mkdir("/tmp/hey", 0777) < 0)
                exit(EXIT_FAILURE);

        exit(EXIT_SUCCESS);
}

#define STACK_SIZE (1024 * 1024)

static char child_stack[STACK_SIZE];

int main(int argc, char *argv[]) {
        int flags, opt;
        pid_t child_pid;
        struct child_args args;
        char *uid_map, *gid_map;
        const int MAP_BUF_SIZE = 100;
        char map_buf[MAP_BUF_SIZE];
        char map_path[PATH_MAX];
        int status;

        flags = 0;
        gid_map = NULL;
        uid_map = NULL;
        while ((opt = getopt(argc, argv, "+M:G:")) != -1) {
                switch (opt) {
                        case 'M':
                                uid_map = optarg;
                                break;
                        case 'G':
                                gid_map = optarg;
                                break;
                        default:
                                  usage(argv[0]);
                }
        }

        if (!uid_map || !gid_map)
                usage(argv[0]);

        flags |= CLONE_NEWNS;
        flags |= CLONE_NEWUSER;

        if (pipe(args.pipe_fd) == -1)
                errExit("pipe");

        child_pid = clone(child_func, child_stack + STACK_SIZE, flags | SIGCHLD, &args);
        if (child_pid == -1)
                errExit("clone");

        snprintf(map_path, PATH_MAX, "/proc/%ld/uid_map", (long) child_pid);
        update_map(uid_map, map_path);

        proc_setgroups_write(child_pid, "allow");
        snprintf(map_path, PATH_MAX, "/proc/%ld/gid_map", (long) child_pid);
        update_map(gid_map, map_path);

        close(args.pipe_fd[1]);

        if (waitpid(child_pid, &status, 0) == -1)
                errExit("waitpid");

        exit(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS ? EXIT_FAILURE : EXIT_SUCCESS);
}
