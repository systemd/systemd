/* SPDX-License-Identifier: LGPL-2.1+ */

#include <dwarf.h>
#include <elfutils/libdwfl.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fileio.h"
#include "fd-util.h"
#include "format-util.h"
#include "macro.h"
#include "stacktrace.h"
#include "string-util.h"
#include "util.h"

#define FRAMES_MAX 64
#define THREADS_MAX 64

struct stack_context {
        FILE *f;
        Dwfl *dwfl;
        Elf *elf;
        unsigned n_thread;
        unsigned n_frame;
};

static int frame_callback(Dwfl_Frame *frame, void *userdata) {
        struct stack_context *c = userdata;
        Dwarf_Addr pc, pc_adjusted, bias = 0;
        _cleanup_free_ Dwarf_Die *scopes = NULL;
        const char *fname = NULL, *symbol = NULL;
        Dwfl_Module *module;
        bool is_activation;

        assert(frame);
        assert(c);

        if (c->n_frame >= FRAMES_MAX)
                return DWARF_CB_ABORT;

        if (!dwfl_frame_pc(frame, &pc, &is_activation))
                return DWARF_CB_ABORT;

        pc_adjusted = pc - (is_activation ? 0 : 1);

        module = dwfl_addrmodule(c->dwfl, pc_adjusted);
        if (module) {
                Dwarf_Die *s, *cudie;
                int n;

                cudie = dwfl_module_addrdie(module, pc_adjusted, &bias);
                if (cudie) {
                        n = dwarf_getscopes(cudie, pc_adjusted - bias, &scopes);
                        for (s = scopes; s < scopes + n; s++) {
                                if (IN_SET(dwarf_tag(s), DW_TAG_subprogram, DW_TAG_inlined_subroutine, DW_TAG_entry_point)) {
                                        Dwarf_Attribute *a, space;

                                        a = dwarf_attr_integrate(s, DW_AT_MIPS_linkage_name, &space);
                                        if (!a)
                                                a = dwarf_attr_integrate(s, DW_AT_linkage_name, &space);
                                        if (a)
                                                symbol = dwarf_formstring(a);
                                        if (!symbol)
                                                symbol = dwarf_diename(s);

                                        if (symbol)
                                                break;
                                }
                        }
                }

                if (!symbol)
                        symbol = dwfl_module_addrname(module, pc_adjusted);

                fname = dwfl_module_info(module, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        }

        fprintf(c->f, "#%-2u 0x%016" PRIx64 " %s (%s)\n", c->n_frame, (uint64_t) pc, strna(symbol), strna(fname));
        c->n_frame++;

        return DWARF_CB_OK;
}

static int thread_callback(Dwfl_Thread *thread, void *userdata) {
        struct stack_context *c = userdata;
        pid_t tid;

        assert(thread);
        assert(c);

        if (c->n_thread >= THREADS_MAX)
                return DWARF_CB_ABORT;

        if (c->n_thread != 0)
                fputc('\n', c->f);

        c->n_frame = 0;

        tid = dwfl_thread_tid(thread);
        fprintf(c->f, "Stack trace of thread " PID_FMT ":\n", tid);

        if (dwfl_thread_getframes(thread, frame_callback, c) < 0)
                return DWARF_CB_ABORT;

        c->n_thread++;

        return DWARF_CB_OK;
}

static int make_stack_trace(int fd, const char *executable, char **ret) {

        static const Dwfl_Callbacks callbacks = {
                .find_elf = dwfl_build_id_find_elf,
                .find_debuginfo = dwfl_standard_find_debuginfo,
        };

        struct stack_context c = {};
        char *buf = NULL;
        size_t sz = 0;
        int r;

        assert(fd >= 0);
        assert(ret);

        if (lseek(fd, 0, SEEK_SET) == (off_t) -1)
                return -errno;

        c.f = open_memstream_unlocked(&buf, &sz);
        if (!c.f)
                return -ENOMEM;

        elf_version(EV_CURRENT);

        c.elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
        if (!c.elf) {
                r = -EINVAL;
                goto finish;
        }

        c.dwfl = dwfl_begin(&callbacks);
        if (!c.dwfl) {
                r = -EINVAL;
                goto finish;
        }

        if (dwfl_core_file_report(c.dwfl, c.elf, executable) < 0) {
                r = -EINVAL;
                goto finish;
        }

        if (dwfl_report_end(c.dwfl, NULL, NULL) != 0) {
                r = -EINVAL;
                goto finish;
        }

        if (dwfl_core_file_attach(c.dwfl, c.elf) < 0) {
                r = -EINVAL;
                goto finish;
        }

        if (dwfl_getthreads(c.dwfl, thread_callback, &c) < 0) {
                r = -EINVAL;
                goto finish;
        }

        c.f = safe_fclose(c.f);

        *ret = TAKE_PTR(buf);

        r = 0;

finish:
        if (c.dwfl)
                dwfl_end(c.dwfl);

        if (c.elf)
                elf_end(c.elf);

        safe_fclose(c.f);

        free(buf);

        return r;
}

void coredump_make_stack_trace(int fd, const char *executable, char **ret) {
        int r;

        r = make_stack_trace(fd, executable, ret);
        if (r == -EINVAL)
                log_warning("Failed to generate stack trace: %s", dwfl_errmsg(dwfl_errno()));
        else if (r < 0)
                log_warning_errno(r, "Failed to generate stack trace: %m");
}
