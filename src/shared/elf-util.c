/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_ELFUTILS

#include <dwarf.h>
#include <elfutils/libdwelf.h>
#include <elfutils/libdwfl.h>
#include <libelf.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "dlfcn-util.h"
#include "elf-util.h"
#include "errno-util.h"
#include "escape.h"
#include "fileio.h"
#include "fd-util.h"
#include "format-util.h"
#include "hexdecoct.h"
#include "io-util.h"
#include "macro.h"
#include "memstream-util.h"
#include "path-util.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "string-util.h"

#define FRAMES_MAX 64
#define THREADS_MAX 64
#define ELF_PACKAGE_METADATA_ID 0xcafe1a7e

/* The amount of data we're willing to write to each of the output pipes. */
#define COREDUMP_PIPE_MAX (1024*1024U)

static void *dw_dl = NULL;
static void *elf_dl = NULL;

/* libdw symbols */
static DLSYM_PROTOTYPE(dwarf_attr_integrate) = NULL;
static DLSYM_PROTOTYPE(dwarf_diename) = NULL;
static DLSYM_PROTOTYPE(dwarf_formstring) = NULL;
static DLSYM_PROTOTYPE(dwarf_getscopes) = NULL;
static DLSYM_PROTOTYPE(dwarf_getscopes_die) = NULL;
static DLSYM_PROTOTYPE(dwelf_elf_begin) = NULL;
#if HAVE_DWELF_ELF_E_MACHINE_STRING
static DLSYM_PROTOTYPE(dwelf_elf_e_machine_string) = NULL;
#endif
static DLSYM_PROTOTYPE(dwelf_elf_gnu_build_id) = NULL;
static DLSYM_PROTOTYPE(dwarf_tag) = NULL;
static DLSYM_PROTOTYPE(dwfl_addrmodule) = NULL;
static DLSYM_PROTOTYPE(dwfl_begin) = NULL;
static DLSYM_PROTOTYPE(dwfl_build_id_find_elf) = NULL;
static DLSYM_PROTOTYPE(dwfl_core_file_attach) = NULL;
static DLSYM_PROTOTYPE(dwfl_core_file_report) = NULL;
#if HAVE_DWFL_SET_SYSROOT
static DLSYM_PROTOTYPE(dwfl_set_sysroot) = NULL;
#endif
static DLSYM_PROTOTYPE(dwfl_end) = NULL;
static DLSYM_PROTOTYPE(dwfl_errmsg) = NULL;
static DLSYM_PROTOTYPE(dwfl_errno) = NULL;
static DLSYM_PROTOTYPE(dwfl_frame_pc) = NULL;
static DLSYM_PROTOTYPE(dwfl_getmodules) = NULL;
static DLSYM_PROTOTYPE(dwfl_getthreads) = NULL;
static DLSYM_PROTOTYPE(dwfl_module_addrdie) = NULL;
static DLSYM_PROTOTYPE(dwfl_module_addrname) = NULL;
static DLSYM_PROTOTYPE(dwfl_module_build_id) = NULL;
static DLSYM_PROTOTYPE(dwfl_module_getelf) = NULL;
static DLSYM_PROTOTYPE(dwfl_module_info) = NULL;
static DLSYM_PROTOTYPE(dwfl_offline_section_address) = NULL;
static DLSYM_PROTOTYPE(dwfl_report_end) = NULL;
static DLSYM_PROTOTYPE(dwfl_standard_find_debuginfo) = NULL;
static DLSYM_PROTOTYPE(dwfl_thread_getframes) = NULL;
static DLSYM_PROTOTYPE(dwfl_thread_tid) = NULL;

/* libelf symbols */
static DLSYM_PROTOTYPE(elf_begin) = NULL;
static DLSYM_PROTOTYPE(elf_end) = NULL;
static DLSYM_PROTOTYPE(elf_getdata_rawchunk) = NULL;
static DLSYM_PROTOTYPE(gelf_getehdr) = NULL;
static DLSYM_PROTOTYPE(elf_getphdrnum) = NULL;
static DLSYM_PROTOTYPE(elf_errmsg) = NULL;
static DLSYM_PROTOTYPE(elf_errno) = NULL;
static DLSYM_PROTOTYPE(elf_memory) = NULL;
static DLSYM_PROTOTYPE(elf_version) = NULL;
static DLSYM_PROTOTYPE(gelf_getphdr) = NULL;
static DLSYM_PROTOTYPE(gelf_getnote) = NULL;

int dlopen_dw(void) {
        int r;

        ELF_NOTE_DLOPEN("dw",
                        "Support for backtrace and ELF package metadata decoding from core files",
                        ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED,
                        "libdw.so.1");

        r = dlopen_many_sym_or_warn(
                        &dw_dl, "libdw.so.1", LOG_DEBUG,
                        DLSYM_ARG(dwarf_getscopes),
                        DLSYM_ARG(dwarf_getscopes_die),
                        DLSYM_ARG(dwarf_tag),
                        DLSYM_ARG(dwarf_attr_integrate),
                        DLSYM_ARG(dwarf_formstring),
                        DLSYM_ARG(dwarf_diename),
                        DLSYM_ARG(dwelf_elf_gnu_build_id),
                        DLSYM_ARG(dwelf_elf_begin),
#if HAVE_DWELF_ELF_E_MACHINE_STRING
                        DLSYM_ARG(dwelf_elf_e_machine_string),
#endif
                        DLSYM_ARG(dwfl_addrmodule),
                        DLSYM_ARG(dwfl_frame_pc),
                        DLSYM_ARG(dwfl_module_addrdie),
                        DLSYM_ARG(dwfl_module_addrname),
                        DLSYM_ARG(dwfl_module_info),
                        DLSYM_ARG(dwfl_module_build_id),
                        DLSYM_ARG(dwfl_module_getelf),
                        DLSYM_ARG(dwfl_begin),
                        DLSYM_ARG(dwfl_core_file_report),
#if HAVE_DWFL_SET_SYSROOT
                        DLSYM_ARG(dwfl_set_sysroot),
#endif
                        DLSYM_ARG(dwfl_report_end),
                        DLSYM_ARG(dwfl_getmodules),
                        DLSYM_ARG(dwfl_core_file_attach),
                        DLSYM_ARG(dwfl_end),
                        DLSYM_ARG(dwfl_errmsg),
                        DLSYM_ARG(dwfl_errno),
                        DLSYM_ARG(dwfl_build_id_find_elf),
                        DLSYM_ARG(dwfl_standard_find_debuginfo),
                        DLSYM_ARG(dwfl_thread_tid),
                        DLSYM_ARG(dwfl_thread_getframes),
                        DLSYM_ARG(dwfl_getthreads),
                        DLSYM_ARG(dwfl_offline_section_address));
        if (r <= 0)
                return r;

        return 1;
}

int dlopen_elf(void) {
        int r;

        ELF_NOTE_DLOPEN("elf",
                        "Support for backtraces and reading ELF package metadata from core files",
                        ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED,
                        "libelf.so.1");

        r = dlopen_many_sym_or_warn(
                        &elf_dl, "libelf.so.1", LOG_DEBUG,
                        DLSYM_ARG(elf_begin),
                        DLSYM_ARG(elf_end),
                        DLSYM_ARG(elf_getphdrnum),
                        DLSYM_ARG(elf_getdata_rawchunk),
                        DLSYM_ARG(elf_errmsg),
                        DLSYM_ARG(elf_errno),
                        DLSYM_ARG(elf_memory),
                        DLSYM_ARG(elf_version),
                        DLSYM_ARG(gelf_getehdr),
                        DLSYM_ARG(gelf_getphdr),
                        DLSYM_ARG(gelf_getnote));
        if (r <= 0)
                return r;

        return 1;
}

typedef struct StackContext {
        MemStream m;
        Dwfl *dwfl;
        Elf *elf;
        unsigned n_thread;
        unsigned n_frame;
        sd_json_variant **package_metadata;
        Set **modules;
} StackContext;

static void stack_context_done(StackContext *c) {
        assert(c);

        memstream_done(&c->m);

        if (c->dwfl) {
                sym_dwfl_end(c->dwfl);
                c->dwfl = NULL;
        }

        if (c->elf) {
                sym_elf_end(c->elf);
                c->elf = NULL;
        }
}

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(Elf *, sym_elf_end, NULL);

static int frame_callback(Dwfl_Frame *frame, void *userdata) {
        StackContext *c = ASSERT_PTR(userdata);
        Dwarf_Addr pc, pc_adjusted;
        const char *fname = NULL, *symbol = NULL;
        Dwfl_Module *module;
        bool is_activation;
        uint64_t module_offset = 0;

        assert(frame);

        if (c->n_frame >= FRAMES_MAX)
                return DWARF_CB_ABORT;

        if (!sym_dwfl_frame_pc(frame, &pc, &is_activation))
                return DWARF_CB_ABORT;

        pc_adjusted = pc - (is_activation ? 0 : 1);

        module = sym_dwfl_addrmodule(c->dwfl, pc_adjusted);
        if (module) {
                Dwarf_Addr start, bias = 0;
                Dwarf_Die *cudie;

                cudie = sym_dwfl_module_addrdie(module, pc_adjusted, &bias);
                if (cudie) {
                        _cleanup_free_ Dwarf_Die *scopes = NULL;
                        int n;

                        n = sym_dwarf_getscopes(cudie, pc_adjusted - bias, &scopes);
                        if (n > 0)
                                for (Dwarf_Die *s = scopes; s && s < scopes + n; s++) {
                                        Dwarf_Attribute *a, space;

                                        if (!IN_SET(sym_dwarf_tag(s), DW_TAG_subprogram, DW_TAG_inlined_subroutine, DW_TAG_entry_point))
                                                continue;

                                        a = sym_dwarf_attr_integrate(s, DW_AT_MIPS_linkage_name, &space);
                                        if (!a)
                                                a = sym_dwarf_attr_integrate(s, DW_AT_linkage_name, &space);
                                        if (a)
                                                symbol = sym_dwarf_formstring(a);
                                        if (!symbol)
                                                symbol = sym_dwarf_diename(s);

                                        if (symbol)
                                                break;
                                }
                }

                if (!symbol)
                        symbol = sym_dwfl_module_addrname(module, pc_adjusted);

                fname = sym_dwfl_module_info(module, NULL, &start, NULL, NULL, NULL, NULL, NULL);
                module_offset = pc - start;
        }

        if (c->m.f)
                fprintf(c->m.f, "#%-2u 0x%016" PRIx64 " %s (%s + 0x%" PRIx64 ")\n", c->n_frame, (uint64_t) pc, strna(symbol), strna(fname), module_offset);
        c->n_frame++;

        return DWARF_CB_OK;
}

static int thread_callback(Dwfl_Thread *thread, void *userdata) {
        StackContext *c = ASSERT_PTR(userdata);
        pid_t tid;

        assert(thread);

        if (c->n_thread >= THREADS_MAX)
                return DWARF_CB_ABORT;

        if (c->n_thread != 0 && c->m.f)
                fputc('\n', c->m.f);

        c->n_frame = 0;

        if (c->m.f) {
                tid = sym_dwfl_thread_tid(thread);
                fprintf(c->m.f, "Stack trace of thread " PID_FMT ":\n", tid);
        }

        if (sym_dwfl_thread_getframes(thread, frame_callback, c) < 0)
                return DWARF_CB_ABORT;

        c->n_thread++;

        return DWARF_CB_OK;
}

static char* build_package_reference(
                const char *type,
                const char *name,
                const char *version,
                const char *arch) {

        /* Construct an identifier for a specific version of the package. The syntax is most suitable for
         * rpm: the resulting string can be used directly in queries and rpm/dnf/yum commands. For dpkg and
         * other systems, it might not be usable directly, but users should still be able to figure out the
         * meaning.
         */

        return strjoin(type ?: "package",
                       " ",
                       name,

                       version ? "-" : "",
                       strempty(version),

                       /* arch is meaningful even without version, so always print it */
                       arch ? "." : "",
                       strempty(arch));
}

static void report_module_metadata(StackContext *c, const char *name, sd_json_variant *metadata) {
        assert(c);
        assert(name);

        if (!c->m.f)
                return;

        fprintf(c->m.f, "Module %s", name);

        if (metadata) {
                const char
                        *build_id = sd_json_variant_string(sd_json_variant_by_key(metadata, "buildId")),
                        *type = sd_json_variant_string(sd_json_variant_by_key(metadata, "type")),
                        *package = sd_json_variant_string(sd_json_variant_by_key(metadata, "name")),
                        *version = sd_json_variant_string(sd_json_variant_by_key(metadata, "version")),
                        *arch = sd_json_variant_string(sd_json_variant_by_key(metadata, "architecture"));

                if (package) {
                        /* Version/architecture is only meaningful with a package name.
                         * Skip the detailed fields if package is unknown. */
                        _cleanup_free_ char *id = build_package_reference(type, package, version, arch);
                        fprintf(c->m.f, " from %s", strnull(id));
                }

                if (build_id && !(package && version))
                        fprintf(c->m.f, ", build-id=%s", build_id);
        }

        fputs("\n", c->m.f);
}

static int parse_package_metadata(const char *name, sd_json_variant *id_json, Elf *elf, bool *ret_interpreter_found, StackContext *c) {
        bool interpreter_found = false;
        size_t n_program_headers;
        int r;

        assert(name);
        assert(elf);
        assert(c);

        /* When iterating over PT_LOAD we will visit modules more than once */
        if (set_contains(*c->modules, name))
                return 0;

        r = sym_elf_getphdrnum(elf, &n_program_headers);
        if (r < 0) /* Not the handle we are looking for - that's ok, skip it */
                return 0;

        /* Iterate over all program headers in that ELF object. These will have been copied by
         * the kernel verbatim when the core file is generated. */
        for (size_t i = 0; i < n_program_headers; ++i) {
                GElf_Phdr mem, *program_header;
                GElf_Nhdr note_header;
                Elf_Data *data;

                /* Package metadata is in PT_NOTE headers. */
                program_header = sym_gelf_getphdr(elf, i, &mem);
                if (!program_header || !IN_SET(program_header->p_type, PT_NOTE, PT_INTERP))
                        continue;

                if (program_header->p_type == PT_INTERP) {
                        interpreter_found = true;
                        continue;
                }

                /* Fortunately there is an iterator we can use to walk over the
                 * elements of a PT_NOTE program header. We are interested in the
                 * note with type. */
                data = sym_elf_getdata_rawchunk(elf,
                                                program_header->p_offset,
                                                program_header->p_filesz,
                                                ELF_T_NHDR);
                if (!data)
                        continue;

                for (size_t note_offset = 0, name_offset, desc_offset;
                     note_offset < data->d_size &&
                     (note_offset = sym_gelf_getnote(data, note_offset, &note_header, &name_offset, &desc_offset)) > 0;) {

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *w = NULL;
                        const char *payload = (const char *)data->d_buf + desc_offset;

                        if (note_header.n_namesz == 0 || note_header.n_descsz == 0)
                                continue;

                        /* Package metadata might have different owners, but the
                         * magic ID is always the same. */
                        if (note_header.n_type != ELF_PACKAGE_METADATA_ID)
                                continue;

                        _cleanup_free_ char *payload_0suffixed = NULL;
                        assert(note_offset > desc_offset);
                        size_t payload_len = note_offset - desc_offset;

                        /* If we are lucky and the payload is NUL-padded, we don't need to copy the string.
                         * But if happens to go all the way until the end of the buffer, make a copy. */
                        if (payload[payload_len-1] != '\0') {
                                payload_0suffixed = memdup_suffix0(payload, payload_len);
                                if (!payload_0suffixed)
                                        return log_oom();
                                payload = payload_0suffixed;
                        }

                        r = sd_json_parse(payload, 0, &v, NULL, NULL);
                        if (r < 0) {
                                _cleanup_free_ char *esc = cescape(payload);
                                return log_error_errno(r, "json_parse on \"%s\" failed: %m", strnull(esc));
                        }

                        /* If we have a build-id, merge it in the same JSON object so that it appears all
                         * nicely together in the logs/metadata. */
                        if (id_json) {
                                r = sd_json_variant_merge_object(&v, id_json);
                                if (r < 0)
                                        return log_error_errno(r, "sd_json_variant_merge of package meta with buildId failed: %m");
                        }

                        /* Pretty-print to the buffer, so that the metadata goes as plaintext in the
                         * journal. */
                        report_module_metadata(c, name, v);

                        /* Then we build a new object using the module name as the key, and merge it
                         * with the previous parses, so that in the end it all fits together in a single
                         * JSON blob. */
                        r = sd_json_buildo(&w, SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_VARIANT(v)));
                        if (r < 0)
                                return log_error_errno(r, "Failed to build JSON object: %m");

                        r = sd_json_variant_merge_object(c->package_metadata, w);
                        if (r < 0)
                                return log_error_errno(r, "sd_json_variant_merge of package meta with buildId failed: %m");

                        /* Finally stash the name, so we avoid double visits. */
                        r = set_put_strdup(c->modules, name);
                        if (r < 0)
                                return log_error_errno(r, "set_put_strdup failed: %m");

                        if (ret_interpreter_found)
                                *ret_interpreter_found = interpreter_found;

                        return 1;
                }
        }

        if (ret_interpreter_found)
                *ret_interpreter_found = interpreter_found;

        /* Didn't find package metadata for this module - that's ok, just go to the next. */
        return 0;
}

/* Get the build-id out of an ELF object or a dwarf core module. */
static int parse_buildid(Dwfl_Module *mod, Elf *elf, const char *name, StackContext *c, sd_json_variant **ret_id_json) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *id_json = NULL;
        const unsigned char *id;
        GElf_Addr id_vaddr;
        ssize_t id_len;
        int r;

        assert(mod || elf);
        assert(name);
        assert(c);

        if (mod)
                id_len = sym_dwfl_module_build_id(mod, &id, &id_vaddr);
        else
                id_len = sym_dwelf_elf_gnu_build_id(elf, (const void **)&id);
        if (id_len <= 0) {
                /* If we don't find a build-id, note it in the journal message, and try
                 * anyway to find the package metadata. It's unlikely to have the latter
                 * without the former, but there's no hard rule. */
                if (c->m.f)
                        fprintf(c->m.f, "Module %s without build-id.\n", name);
        } else {
                /* We will later parse package metadata json and pass it to our caller. Prepare the
                * build-id in json format too, so that it can be appended and parsed cleanly. It
                * will then be added as metadata to the journal message with the stack trace. */
                r = sd_json_buildo(&id_json, SD_JSON_BUILD_PAIR("buildId", SD_JSON_BUILD_HEX(id, id_len)));
                if (r < 0)
                        return log_error_errno(r, "json_build on buildId failed: %m");
        }

        if (ret_id_json)
                *ret_id_json = TAKE_PTR(id_json);

        return 0;
}

static int module_callback(Dwfl_Module *mod, void **userdata, const char *name, Dwarf_Addr start, void *arg) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *id_json = NULL;
        StackContext *c = ASSERT_PTR(arg);
        size_t n_program_headers;
        GElf_Addr bias;
        int r;
        Elf *elf;

        assert(mod);

        if (!name)
                name = "(unnamed)"; /* For logging purposes */

        /* We are iterating on each "module", which is what dwfl calls ELF objects contained in the
         * core file, and extracting the build-id first and then the package metadata.
         * We proceed in a best-effort fashion - not all ELF objects might contain both or either.
         * The build-id is easy, as libdwfl parses it during the sym_dwfl_core_file_report() call and
         * stores it separately in an internal library struct. */
        r = parse_buildid(mod, NULL, name, c, &id_json);
        if (r < 0)
                return DWARF_CB_ABORT;

        /* The .note.package metadata is more difficult. From the module, we need to get a reference
         * to the ELF object first. We might be lucky and just get it from elfutils. */
        elf = sym_dwfl_module_getelf(mod, &bias);
        if (elf) {
                r = parse_package_metadata(name, id_json, elf, NULL, c);
                if (r < 0)
                        return DWARF_CB_ABORT;
                if (r > 0)
                        return DWARF_CB_OK;
        } else
                elf = c->elf;

        /* We did not get the ELF object, or it's just a reference to the core. That is likely
         * because we didn't get direct access to the executable, and the version of elfutils does
         * not yet support parsing it out of the core file directly.
         * So fallback to manual extraction - get the PT_LOAD section from the core,
         * and if it's the right one we can interpret it as an Elf object, and parse
         * its notes manually. */

        r = sym_elf_getphdrnum(elf, &n_program_headers);
        if (r < 0) {
                log_warning("Could not parse number of program headers from core file: %s",
                            sym_elf_errmsg(-1)); /* -1 retrieves the most recent error */
                report_module_metadata(c, name, id_json);

                return DWARF_CB_OK;
        }

        for (size_t i = 0; i < n_program_headers; ++i) {
                GElf_Phdr mem, *program_header;
                Elf_Data *data;
                GElf_Addr end_of_segment;

                /* The core file stores the ELF files in the PT_LOAD segment. */
                program_header = sym_gelf_getphdr(elf, i, &mem);
                if (!program_header || program_header->p_type != PT_LOAD)
                        continue;

                /* Check that the end of segment is a valid address. */
                if (!ADD_SAFE(&end_of_segment, program_header->p_vaddr, program_header->p_memsz)) {
                        log_error("Abort due to corrupted core dump, end of segment address %#zx + %#zx overflows", (size_t)program_header->p_vaddr, (size_t)program_header->p_memsz);
                        return DWARF_CB_ABORT;
                }

                /* This PT_LOAD segment doesn't contain the start address, so it can't be the module we are looking for. */
                if (start < program_header->p_vaddr || start >= end_of_segment)
                        continue;

                /* Now get a usable Elf reference, and parse the notes from it. */
                data = sym_elf_getdata_rawchunk(elf,
                                                program_header->p_offset,
                                                program_header->p_filesz,
                                                ELF_T_NHDR);
                if (!data)
                        continue;

                _cleanup_(sym_elf_endp) Elf *memelf = sym_elf_memory(data->d_buf, data->d_size);
                if (!memelf)
                        continue;
                r = parse_package_metadata(name, id_json, memelf, NULL, c);
                if (r < 0)
                        return DWARF_CB_ABORT;
                if (r > 0)
                        break;
        }

        return DWARF_CB_OK;
}

static int parse_core(int fd, const char *root, char **ret, sd_json_variant **ret_package_metadata) {

        const Dwfl_Callbacks callbacks = {
                .find_elf = sym_dwfl_build_id_find_elf,
                .section_address = sym_dwfl_offline_section_address,
                .find_debuginfo = sym_dwfl_standard_find_debuginfo,
        };

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *package_metadata = NULL;
        _cleanup_set_free_ Set *modules = NULL;
        _cleanup_(stack_context_done) StackContext c = {
                .package_metadata = &package_metadata,
                .modules = &modules,
        };
        int r;

        assert(fd >= 0);

        if (lseek(fd, 0, SEEK_SET) < 0)
                return log_warning_errno(errno, "Failed to seek to beginning of the core file: %m");

        if (ret && !memstream_init(&c.m))
                return log_oom();

        sym_elf_version(EV_CURRENT);

        c.elf = sym_elf_begin(fd, ELF_C_READ_MMAP, NULL);
        if (!c.elf)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Could not parse core file, elf_begin() failed: %s", sym_elf_errmsg(sym_elf_errno()));

        c.dwfl = sym_dwfl_begin(&callbacks);
        if (!c.dwfl)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Could not parse core file, dwfl_begin() failed: %s", sym_dwfl_errmsg(sym_dwfl_errno()));

        if (empty_or_root(root))
                root = NULL;
#if HAVE_DWFL_SET_SYSROOT
        if (root && sym_dwfl_set_sysroot(c.dwfl, root) < 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Could not set root directory, dwfl_set_sysroot() failed: %s", sym_dwfl_errmsg(sym_dwfl_errno()));
#else
        if (root)
                log_warning("Compiled without dwfl_set_sysroot() support, ignoring provided root directory.");
#endif

        if (sym_dwfl_core_file_report(c.dwfl, c.elf, NULL) < 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Could not parse core file, dwfl_core_file_report() failed: %s", sym_dwfl_errmsg(sym_dwfl_errno()));

        if (sym_dwfl_report_end(c.dwfl, NULL, NULL) != 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Could not parse core file, dwfl_report_end() failed: %s", sym_dwfl_errmsg(sym_dwfl_errno()));

        if (sym_dwfl_getmodules(c.dwfl, &module_callback, &c, 0) < 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Could not parse core file, dwfl_getmodules() failed: %s", sym_dwfl_errmsg(sym_dwfl_errno()));

        if (sym_dwfl_core_file_attach(c.dwfl, c.elf) < 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Could not parse core file, dwfl_core_file_attach() failed: %s", sym_dwfl_errmsg(sym_dwfl_errno()));

        if (sym_dwfl_getthreads(c.dwfl, thread_callback, &c) < 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Could not parse core file, dwfl_getthreads() failed: %s", sym_dwfl_errmsg(sym_dwfl_errno()));

        if (ret) {
                r = memstream_finalize(&c.m, ret, NULL);
                if (r < 0)
                        return log_warning_errno(r, "Could not parse core file, flushing file buffer failed: %m");
        }

        if (ret_package_metadata)
                *ret_package_metadata = TAKE_PTR(package_metadata);

        return 0;
}

static int parse_elf(int fd, const char *executable, const char *root, char **ret, sd_json_variant **ret_package_metadata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *package_metadata = NULL, *elf_metadata = NULL;
        _cleanup_set_free_ Set *modules = NULL;
        _cleanup_(stack_context_done) StackContext c = {
                .package_metadata = &package_metadata,
                .modules = &modules,
        };
        const char *elf_type;
        GElf_Ehdr elf_header;
        int r;

        assert(fd >= 0);

        if (lseek(fd, 0, SEEK_SET) < 0)
                return log_warning_errno(errno, "Failed to seek to beginning of the ELF file: %m");

        if (ret && !memstream_init(&c.m))
                return log_oom();

        sym_elf_version(EV_CURRENT);

        c.elf = sym_elf_begin(fd, ELF_C_READ_MMAP, NULL);
        if (!c.elf)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Could not parse ELF file, elf_begin() failed: %s", sym_elf_errmsg(sym_elf_errno()));

        if (!sym_gelf_getehdr(c.elf, &elf_header))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Could not parse ELF file, gelf_getehdr() failed: %s", sym_elf_errmsg(sym_elf_errno()));

        if (elf_header.e_type == ET_CORE) {
                _cleanup_free_ char *out = NULL;

                r = parse_core(fd, root, ret ? &out : NULL, &package_metadata);
                if (r < 0)
                        return log_warning_errno(r, "Failed to inspect core file: %m");

                if (out)
                        fprintf(c.m.f, "%s", out);

                elf_type = "coredump";
        } else {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *id_json = NULL;
                const char *e = executable ?: "(unnamed)";
                bool interpreter_found = false;

                r = parse_buildid(NULL, c.elf, e, &c, &id_json);
                if (r < 0)
                        return log_warning_errno(r, "Failed to parse build-id of ELF file: %m");

                r = parse_package_metadata(e, id_json, c.elf, &interpreter_found, &c);
                if (r < 0)
                        return log_warning_errno(r, "Failed to parse package metadata of ELF file: %m");

                /* If we found a build-id and nothing else, return at least that. */
                if (!package_metadata && id_json) {
                        r = sd_json_buildo(&package_metadata, SD_JSON_BUILD_PAIR(e, SD_JSON_BUILD_VARIANT(id_json)));
                        if (r < 0)
                                return log_warning_errno(r, "Failed to build JSON object: %m");
                }

                if (interpreter_found)
                        elf_type = "executable";
                else
                        elf_type = "library";
        }

        /* Note that e_type is always DYN for both executables and libraries, so we can't tell them apart from the header,
         * but we will search for the PT_INTERP section when parsing the metadata. */
        r = sd_json_buildo(&elf_metadata, SD_JSON_BUILD_PAIR("elfType", SD_JSON_BUILD_STRING(elf_type)));
        if (r < 0)
                return log_warning_errno(r, "Failed to build JSON object: %m");

#if HAVE_DWELF_ELF_E_MACHINE_STRING
        const char *elf_architecture = sym_dwelf_elf_e_machine_string(elf_header.e_machine);
        if (elf_architecture) {
                r = sd_json_variant_merge_objectbo(
                                &elf_metadata,
                                SD_JSON_BUILD_PAIR("elfArchitecture", SD_JSON_BUILD_STRING(elf_architecture)));
                if (r < 0)
                        return log_warning_errno(r, "Failed to add elfArchitecture field: %m");

                if (ret)
                        fprintf(c.m.f, "ELF object binary architecture: %s\n", elf_architecture);
        }
#endif

        /* We always at least have the ELF type, so merge that (and possibly the arch). */
        r = sd_json_variant_merge_object(&elf_metadata, package_metadata);
        if (r < 0)
                return log_warning_errno(r, "Failed to merge JSON objects: %m");

        if (ret) {
                r = memstream_finalize(&c.m, ret, NULL);
                if (r < 0)
                        return log_warning_errno(r, "Could not parse ELF file, flushing file buffer failed: %m");
        }

        if (ret_package_metadata)
                *ret_package_metadata = TAKE_PTR(elf_metadata);

        return 0;
}

int parse_elf_object(int fd, const char *executable, const char *root, bool fork_disable_dump, char **ret, sd_json_variant **ret_package_metadata) {
        _cleanup_close_pair_ int error_pipe[2] = EBADF_PAIR,
                                 return_pipe[2] = EBADF_PAIR,
                                 json_pipe[2] = EBADF_PAIR;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *package_metadata = NULL;
        _cleanup_free_ char *buf = NULL;
        int r;

        assert(fd >= 0);

        r = dlopen_dw();
        if (r < 0)
                return r;

        r = dlopen_elf();
        if (r < 0)
                return r;

        r = RET_NERRNO(pipe2(error_pipe, O_CLOEXEC|O_NONBLOCK));
        if (r < 0)
                return r;

        if (ret) {
                r = RET_NERRNO(pipe2(return_pipe, O_CLOEXEC|O_NONBLOCK));
                if (r < 0)
                        return r;
        }

        if (ret_package_metadata) {
                r = RET_NERRNO(pipe2(json_pipe, O_CLOEXEC|O_NONBLOCK));
                if (r < 0)
                        return r;
        }

        /* Parsing possibly malformed data is crash-happy, so fork. In case we crash,
         * the core file will not be lost, and the messages will still be attached to
         * the journal. Reading the elf object might be slow, but it still has an upper
         * bound since the core files have an upper size limit. It's also not doing any
         * system call or interacting with the system in any way, besides reading from
         * the file descriptor and writing into these four pipes. */
        r = safe_fork_full("(sd-parse-elf)",
                           NULL,
                           (int[]){ fd, error_pipe[1], return_pipe[1], json_pipe[1] },
                           4,
                           FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE|FORK_NEW_USERNS|FORK_WAIT|FORK_REOPEN_LOG,
                           NULL);
        if (r < 0) {
                if (r == -EPROTO) { /* We should have the errno from the child, but don't clobber original error */
                        ssize_t k;
                        int e;

                        k = read(error_pipe[0], &e, sizeof(e));
                        if (k < 0 && errno != EAGAIN) /* Pipe is non-blocking, EAGAIN means there's nothing */
                                return -errno;
                        if (k == sizeof(e))
                                return e; /* propagate error sent to us from child */
                        if (k != 0)
                                return -EIO;
                }

                return r;
        }
        if (r == 0) {
                /* We want to avoid loops, given this can be called from systemd-coredump */
                if (fork_disable_dump) {
                        r = RET_NERRNO(prctl(PR_SET_DUMPABLE, 0));
                        if (r < 0)
                                report_errno_and_exit(error_pipe[1], r);
                }

                r = parse_elf(fd, executable, root, ret ? &buf : NULL, ret_package_metadata ? &package_metadata : NULL);
                if (r < 0)
                        report_errno_and_exit(error_pipe[1], r);

                if (buf) {
                        size_t len = strlen(buf);

                        if (len > COREDUMP_PIPE_MAX) {
                                /* This is iffy. A backtrace can be a few hundred kilobytes, but too much is
                                 * too much. Let's log a warning and ignore the rest. */
                                log_warning("Generated backtrace is %zu bytes (more than the limit of %u bytes), backtrace will be truncated.",
                                            len, COREDUMP_PIPE_MAX);
                                len = COREDUMP_PIPE_MAX;
                        }

                        /* Bump the space for the returned string.
                         * Failure is ignored, because partial output is still useful. */
                        (void) fcntl(return_pipe[1], F_SETPIPE_SZ, len);

                        r = loop_write(return_pipe[1], buf, len);
                        if (r == -EAGAIN)
                                log_warning("Write failed, backtrace will be truncated.");
                        else if (r < 0)
                                report_errno_and_exit(error_pipe[1], r);

                        return_pipe[1] = safe_close(return_pipe[1]);
                }

                if (package_metadata) {
                        _cleanup_fclose_ FILE *json_out = NULL;

                        /* Bump the space for the returned string. We don't know how much space we'll need in
                         * advance, so we'll just try to write as much as possible and maybe fail later. */
                        (void) fcntl(json_pipe[1], F_SETPIPE_SZ, COREDUMP_PIPE_MAX);

                        json_out = take_fdopen(&json_pipe[1], "w");
                        if (!json_out)
                                report_errno_and_exit(error_pipe[1], -errno);

                        r = sd_json_variant_dump(package_metadata, SD_JSON_FORMAT_FLUSH, json_out, NULL);
                        if (r < 0)
                                log_warning_errno(r, "Failed to write JSON package metadata, ignoring: %m");
                }

                _exit(EXIT_SUCCESS);
        }

        error_pipe[1] = safe_close(error_pipe[1]);
        return_pipe[1] = safe_close(return_pipe[1]);
        json_pipe[1] = safe_close(json_pipe[1]);

        if (ret) {
                _cleanup_fclose_ FILE *in = NULL;

                in = take_fdopen(&return_pipe[0], "r");
                if (!in)
                        return -errno;

                r = read_full_stream(in, &buf, NULL);
                if (r < 0)
                        return r;
        }

        if (ret_package_metadata) {
                _cleanup_fclose_ FILE *json_in = NULL;

                json_in = take_fdopen(&json_pipe[0], "r");
                if (!json_in)
                        return -errno;

                r = sd_json_parse_file(json_in, NULL, 0, &package_metadata, NULL, NULL);
                if (r < 0 && r != -ENODATA) /* ENODATA: json was empty, so we got nothing, but that's ok */
                        log_warning_errno(r, "Failed to read or parse json metadata, ignoring: %m");
        }

        if (ret)
                *ret = TAKE_PTR(buf);
        if (ret_package_metadata)
                *ret_package_metadata = TAKE_PTR(package_metadata);

        return 0;
}

#endif
