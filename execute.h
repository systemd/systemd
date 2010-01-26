/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef fooexecutehfoo
#define fooexecutehfoo

typedef struct ExecStatus ExecStatus;
typedef struct ExecCommand ExecCommand;
typedef struct ExecContext ExecContext;

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/capability.h>
#include <stdbool.h>
#include <stdio.h>

#include "list.h"
#include "util.h"

struct ExecStatus {
        pid_t pid;
        usec_t timestamp;
        int code;     /* as in siginfo_t::si_code */
        int status;   /* as in sigingo_t::si_status */
};

struct ExecCommand {
        char *path;
        char **argv;
        ExecStatus exec_status;
        LIST_FIELDS(ExecCommand, command); /* useful for chaining commands */
};

struct ExecContext {
        char **environment;
        mode_t umask;
        struct rlimit *rlimit[RLIMIT_NLIMITS];
        int oom_adjust;
        int nice;
        char *directory;

        cap_t capabilities;
        bool capabilities_set:1;

        /* since resolving these names might might involve socket
         * connections and we don't want to deadlock ourselves these
         * names are resolved on execution only. */
        char *user;
        char *group;
        char **supplementary_groups;
};

typedef enum ExitStatus {
        /* EXIT_SUCCESS defined by libc */
        /* EXIT_FAILURE defined by libc */
        EXIT_INVALIDARGUMENT = 2,
        EXIT_NOTIMPLEMENTED = 3,
        EXIT_NOPERMISSION = 4,
        EXIT_NOTINSTALLED = 5,
        EXIT_NOTCONFIGURED = 6,
        EXIT_NOTRUNNING = 7,

        /* The LSB suggests that error codes >= 200 are "reserved". We
         * use them here under the assumption that they hence are
         * unused by init scripts.
         *
         * http://refspecs.freestandards.org/LSB_3.1.0/LSB-Core-generic/LSB-Core-generic/iniscrptact.html */

        EXIT_CHDIR = 200,
        EXIT_NICE,
        EXIT_FDS,
        EXIT_EXEC,
        EXIT_MEMORY,
        EXIT_LIMITS,
        EXIT_OOM_ADJUST
} ExitStatus;

int exec_spawn(const ExecCommand *command, const ExecContext *context, int *fds, unsigned n_fds, pid_t *ret);

void exec_command_free_list(ExecCommand *c);
void exec_command_free_array(ExecCommand **c, unsigned n);

char *exec_command_line(ExecCommand *c);
void exec_command_dump(ExecCommand *c, FILE *f, const char *prefix);
void exec_command_dump_list(ExecCommand *c, FILE *f, const char *prefix);

void exec_context_init(ExecContext *c);
void exec_context_done(ExecContext *c);
void exec_context_dump(ExecContext *c, FILE* f, const char *prefix);

void exec_status_fill(ExecStatus *s, pid_t pid, int code, int status);

#endif
