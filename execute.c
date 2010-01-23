/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <assert.h>

#include "execute.h"
#include "strv.h"
#include "macro.h"
#include "util.h"

int exec_spawn(const ExecCommand *command, const ExecContext *context, pid_t *ret) {
        assert(command);
        assert(context);
        assert(ret);

        return 0;
}

void exec_context_free(ExecContext *c) {
        unsigned l;

        assert(c);

        strv_free(c->environment);

        for (l = 0; l < ELEMENTSOF(c->rlimit); l++)
                free(c->rlimit[l]);

        free(c->chdir);
        free(c->user);
        free(c->group);
        free(c->supplementary_groups);
}

void exec_command_free_list(ExecCommand *c) {
        ExecCommand *i;

        while ((i = c)) {
                LIST_REMOVE(ExecCommand, c, i);

                free(i->path);
                free(i->argv);
                free(i);
        }
}

void exec_context_dump(ExecContext *c, FILE* f, const char *prefix) {
        assert(c);
        assert(f);

        if (!prefix)
                prefix = "";

        fprintf(f,
                "%sUmask: %04o\n"
                "%sDumpable: %s\n"
                "%sDirectory: %s\n",
                prefix, c->umask,
                prefix, yes_no(c->dumpable),
                prefix, c->chdir ? c->chdir : "/");
}

void exec_context_defaults(ExecContext *c) {
        assert(c);

        c->umask = 0002;
        cap_clear(c->capabilities);
        c->dumpable = true;
}
