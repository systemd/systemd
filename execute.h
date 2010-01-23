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

struct ExecStatus {
        pid_t pid;
        time_t timestamp;
        int status; /* as in wait() */
};

struct ExecCommand {
        char *path;
        char **argv;
        ExecStatus last_exec_status;
        LIST_FIELDS(ExecCommand);
};

struct ExecContext {
        char **environment;
        mode_t umask;
        struct rlimit *rlimit[RLIMIT_NLIMITS];
        cap_t capabilities;
        bool capabilities_set:1;
        bool dumpable:1;
        int oom_adjust;
        int nice;
        char *chdir;

        /* since resolving these names might might involve socket
         * connections and we don't want to deadlock ourselves these
         * names are resolved on execution only. */
        char *user;
        char *group;
        char **supplementary_groups;
};

int exec_spawn(const ExecCommand *command, const ExecContext *context, pid_t *ret);

void exec_context_free(ExecContext *c);
void exec_command_free_list(ExecCommand *c);

void exec_context_dump(ExecContext *c, FILE* f, const char *prefix);

void exec_context_defaults(ExecContext *c);

#endif
