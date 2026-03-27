/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

#if HAVE_XENCTRL
#include <sys/ioctl.h>
#include <sys/mman.h>

#define __XEN_INTERFACE_VERSION__ 0x00040900
#include <xen/kexec.h>
#include <xen/sys/privcmd.h>
#include <xen/xen.h>

#include "errno-util.h"
#include "fd-util.h"
#endif

#include "alloc-util.h"
#include "compress.h"
#include "copy.h"
#include "fd-util.h"
#include "fileio.h"
#include "io-util.h"
#include "log.h"
#include "memfd-util.h"
#include "pe-binary.h"
#include "proc-cmdline.h"
#include "reboot-util.h"
#include "string-util.h"
#include "umask-util.h"
#include "unaligned.h"
#include "utf8.h"
#include "virt.h"

int raw_reboot(int cmd, const void *arg) {
        return syscall(SYS_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, cmd, arg);
}

bool reboot_parameter_is_valid(const char *parameter) {
        assert(parameter);

        return ascii_is_valid(parameter) && strlen(parameter) <= NAME_MAX;
}

int update_reboot_parameter_and_warn(const char *parameter, bool keep) {
        int r;

        if (isempty(parameter)) {
                if (keep)
                        return 0;

                if (unlink("/run/systemd/reboot-param") < 0) {
                        if (errno == ENOENT)
                                return 0;

                        return log_warning_errno(errno, "Failed to unlink reboot parameter file: %m");
                }

                return 0;
        }

        if (!reboot_parameter_is_valid(parameter))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid reboot parameter '%s'.", parameter);

        WITH_UMASK(0022) {
                r = write_string_file("/run/systemd/reboot-param", parameter,
                                      WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC);
                if (r < 0)
                        return log_warning_errno(r, "Failed to write reboot parameter file: %m");
        }

        return 0;
}

int read_reboot_parameter(char **parameter) {
        int r;

        assert(parameter);

        r = read_one_line_file("/run/systemd/reboot-param", parameter);
        if (r < 0 && r != -ENOENT)
                return log_debug_errno(r, "Failed to read /run/systemd/reboot-param: %m");

        return 0;
}

int reboot_with_parameter(RebootFlags flags) {
        int r;

        /* Reboots the system with a parameter that is read from /run/systemd/reboot-param. Returns 0 if
         * REBOOT_DRY_RUN was set and the actual reboot operation was hence skipped. If REBOOT_FALLBACK is
         * set and the reboot with parameter doesn't work out a fallback to classic reboot() is attempted. If
         * REBOOT_FALLBACK is not set, 0 is returned instead, which should be considered indication for the
         * caller to fall back to reboot() on its own, or somehow else deal with this. If REBOOT_LOG is
         * specified will log about what it is going to do, as well as all errors. */

        if (detect_container() == 0) {
                _cleanup_free_ char *parameter = NULL;

                r = read_one_line_file("/run/systemd/reboot-param", &parameter);
                if (r < 0 && r != -ENOENT)
                        log_full_errno(flags & REBOOT_LOG ? LOG_WARNING : LOG_DEBUG, r,
                                       "Failed to read reboot parameter file, ignoring: %m");

                if (!isempty(parameter)) {
                        log_full(flags & REBOOT_LOG ? LOG_INFO : LOG_DEBUG,
                                 "Rebooting with argument '%s'.", parameter);

                        if (flags & REBOOT_DRY_RUN)
                                return 0;

                        (void) raw_reboot(LINUX_REBOOT_CMD_RESTART2, parameter);

                        log_full_errno(flags & REBOOT_LOG ? LOG_WARNING : LOG_DEBUG, errno,
                                       "Failed to reboot with parameter, retrying without: %m");
                }
        }

        if (!(flags & REBOOT_FALLBACK))
                return 0;

        log_full(flags & REBOOT_LOG ? LOG_INFO : LOG_DEBUG, "Rebooting.");

        if (flags & REBOOT_DRY_RUN)
                return 0;

        (void) reboot(RB_AUTOBOOT);

        return log_full_errno(flags & REBOOT_LOG ? LOG_ERR : LOG_DEBUG, errno, "Failed to reboot: %m");
}

bool shall_restore_state(void) {
        static int cached = -1;
        bool b = true; /* If nothing specified or the check fails, then defaults to true. */
        int r;

        if (cached >= 0)
                return cached;

        r = proc_cmdline_get_bool("systemd.restore_state", PROC_CMDLINE_TRUE_WHEN_MISSING, &b);
        if (r < 0)
                log_debug_errno(r, "Failed to parse systemd.restore_state= kernel command line option, ignoring: %m");

        return (cached = b);
}

#if HAVE_XENCTRL
static int xen_kexec_command(uint64_t cmd) {
        _cleanup_close_ int privcmd_fd = -EBADF, buf_fd = -EBADF;
        void *buffer;
        size_t size;
        int r;

        assert(IN_SET(cmd, KEXEC_CMD_kexec, KEXEC_CMD_kexec_status));

        if (access("/proc/xen", F_OK) < 0) {
                if (errno == ENOENT)
                        return -EOPNOTSUPP;
                return log_debug_errno(errno, "Unable to test whether /proc/xen exists: %m");
        }

        size = page_size();
        if ((cmd == KEXEC_CMD_kexec_status && sizeof(xen_kexec_status_t) > size) ||
            (cmd == KEXEC_CMD_kexec && sizeof(xen_kexec_exec_t) > size))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "page_size is too small for hypercall");

        privcmd_fd = open("/dev/xen/privcmd", O_RDWR|O_CLOEXEC);
        if (privcmd_fd < 0)
                return log_debug_errno(errno, "Cannot access /dev/xen/privcmd: %m");

        buf_fd = open("/dev/xen/hypercall", O_RDWR|O_CLOEXEC);
        if (buf_fd < 0)
                return log_debug_errno(errno, "Cannot access /dev/xen/hypercall: %m");

        buffer = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, buf_fd, 0);
        if (buffer == MAP_FAILED)
                return log_debug_errno(errno, "Cannot allocate buffer for hypercall: %m");

        if (cmd == KEXEC_CMD_kexec_status)
                *(xen_kexec_status_t *)buffer = (xen_kexec_status_t) {
                        .type = KEXEC_TYPE_DEFAULT,
                };
        else
                *(xen_kexec_exec_t *)buffer = (xen_kexec_exec_t) {
                        .type = KEXEC_TYPE_DEFAULT,
                };

        privcmd_hypercall_t call = {
                .op = __HYPERVISOR_kexec_op,
                .arg = {
                        cmd,
                        PTR_TO_UINT64(buffer),
                },
        };

        r = RET_NERRNO(ioctl(privcmd_fd, IOCTL_PRIVCMD_HYPERCALL, &call));
        if (r < 0)
                log_debug_errno(r, "kexec%s failed: %m", cmd == KEXEC_CMD_kexec_status ? "_status" : "");

        munmap(buffer, size);

        return r;
}
#endif

static int xen_kexec(void) {
#if HAVE_XENCTRL
        return xen_kexec_command(KEXEC_CMD_kexec);
#else
        return -EOPNOTSUPP;
#endif
}

static int xen_kexec_loaded(void) {
#if HAVE_XENCTRL
        return xen_kexec_command(KEXEC_CMD_kexec_status);
#else
        return -EOPNOTSUPP;
#endif
}

bool kexec_loaded(void) {
       _cleanup_free_ char *s = NULL;
       int r;

       r = xen_kexec_loaded();
       if (r >= 0)
               return r;

       r = read_one_line_file("/sys/kernel/kexec_loaded", &s);
       if (r < 0) {
               if (r != -ENOENT)
                       log_debug_errno(r, "Unable to read /sys/kernel/kexec_loaded, ignoring: %m");
               return false;
       }

       return s[0] == '1';
}

int kexec(void) {
        int r;

        r = xen_kexec();
        if (r < 0 && r != -EOPNOTSUPP)
                return log_error_errno(r, "Failed to call xen kexec: %m");

        r = reboot(LINUX_REBOOT_CMD_KEXEC);
        if (r < 0)
                return log_error_errno(errno, "Failed to kexec: %m");

        return 0;
}

static int decompress_to_memfd(int fd, int (*decompress_fn)(int fdf, int fdt, uint64_t max_bytes)) {
        _cleanup_close_ int memfd = -EBADF;
        int r;

        memfd = memfd_new("kexec-kernel");
        if (memfd < 0)
                return log_error_errno(memfd, "Failed to create memfd: %m");

        r = decompress_fn(fd, memfd, UINT64_MAX);
        if (r < 0)
                return log_error_errno(r, "Failed to decompress kernel: %m");

        if (lseek(memfd, 0, SEEK_SET) < 0)
                return log_error_errno(errno, "Failed to seek memfd: %m");

        return TAKE_FD(memfd);
}

static int decompress_zboot_to_memfd(int fd, uint32_t payload_offset, uint32_t payload_size, const char *comp_type) {
        _cleanup_close_ int compressed_memfd = -EBADF;
        ssize_t n;
        int r;

        int (*decompress_fn)(int fdf, int fdt, uint64_t max_bytes) = NULL;

        if (startswith(comp_type, "gzip"))
                decompress_fn = decompress_stream_gzip;
        else if (startswith(comp_type, "xz") || startswith(comp_type, "xzkern"))
                decompress_fn = decompress_stream_xz;
        else if (startswith(comp_type, "lz4"))
                decompress_fn = decompress_stream_lz4;
        else if (startswith(comp_type, "zstd"))
                decompress_fn = decompress_stream_zstd;
        else
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Unsupported ZBOOT compression type '%s'.", comp_type);

        /* Copy the compressed payload into a memfd so the stream decompressor can read it sequentially */
        _cleanup_free_ void *payload = malloc(payload_size);
        if (!payload)
                return log_oom();

        n = pread(fd, payload, payload_size, payload_offset);
        if (n < 0)
                return log_error_errno(errno, "Failed to read ZBOOT payload: %m");
        if ((uint32_t) n < payload_size)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Short read of ZBOOT payload.");

        compressed_memfd = memfd_new("kexec-zboot-payload");
        if (compressed_memfd < 0)
                return log_error_errno(compressed_memfd, "Failed to create memfd: %m");

        r = loop_write(compressed_memfd, payload, payload_size);
        if (r < 0)
                return log_error_errno(r, "Failed to write ZBOOT payload to memfd: %m");

        payload = mfree(payload);

        if (lseek(compressed_memfd, 0, SEEK_SET) < 0)
                return log_error_errno(errno, "Failed to seek compressed memfd: %m");

        return decompress_to_memfd(compressed_memfd, decompress_fn);
}

static int pe_section_to_memfd(int fd, const IMAGE_SECTION_HEADER *section, const char *name) {
        _cleanup_close_ int memfd = -EBADF;
        uint32_t offset, size;
        int r;

        assert(fd >= 0);
        assert(section);

        offset = le32toh(section->PointerToRawData);
        size = le32toh(section->VirtualSize);

        memfd = memfd_new(name);
        if (memfd < 0)
                return log_error_errno(memfd, "Failed to create memfd for PE section '%s': %m", name);

        if (lseek(fd, offset, SEEK_SET) < 0)
                return log_error_errno(errno, "Failed to seek to PE section '%s': %m", name);

        r = copy_bytes(fd, memfd, size, /* copy_flags= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to copy PE section '%s': %m", name);

        if (lseek(memfd, 0, SEEK_SET) < 0)
                return log_error_errno(errno, "Failed to seek memfd: %m");

        return TAKE_FD(memfd);
}

static int extract_uki(const char *path, int fd, int *ret_kernel_fd, int *ret_initrd_fd) {
        _cleanup_free_ IMAGE_DOS_HEADER *dos_header = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;
        _cleanup_free_ PeHeader *pe_header = NULL;
        const IMAGE_SECTION_HEADER *linux_section, *initrd_section;
        int r;

        assert(fd >= 0);
        assert(ret_kernel_fd);

        r = pe_load_headers(fd, &dos_header, &pe_header);
        if (r < 0)
                return log_debug_errno(r, "Not a valid PE file '%s': %m", path);

        r = pe_load_sections(fd, dos_header, pe_header, &sections);
        if (r < 0)
                return log_debug_errno(r, "Failed to load PE sections from '%s': %m", path);

        if (!pe_is_uki(pe_header, sections))
                return 0; /* Not a UKI */

        linux_section = pe_header_find_section(pe_header, sections, ".linux");
        if (!linux_section)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "UKI '%s' has no .linux section.", path);

        log_debug("Detected UKI image '%s', extracting .linux section.", path);

        r = pe_section_to_memfd(fd, linux_section, "kexec-uki-kernel");
        if (r < 0)
                return r;

        *ret_kernel_fd = r;

        if (ret_initrd_fd) {
                initrd_section = pe_header_find_section(pe_header, sections, ".initrd");
                if (initrd_section) {
                        log_debug("Extracting .initrd section from UKI '%s'.", path);

                        r = pe_section_to_memfd(fd, initrd_section, "kexec-uki-initrd");
                        if (r < 0)
                                return r;

                        *ret_initrd_fd = r;
                }
        }

        return 1;
}

int kexec_maybe_decompress_kernel(const char *path, int fd, int *ret_kernel_fd, int *ret_initrd_fd) {
        uint8_t magic[8];
        ssize_t n;
        int r;

        assert(fd >= 0);
        assert(ret_kernel_fd);

        n = pread(fd, magic, sizeof(magic), 0);
        if (n < 0)
                return log_error_errno(errno, "Failed to read kernel magic from '%s': %m", path);
        if ((size_t) n < sizeof(magic))
                /* Too small to detect, pass through as-is */
                return 0;

        if (magic[0] == 'M' && magic[1] == 'Z') {

                /* Check for ZBOOT PE image: "MZ" DOS signature at offset 0, "zimg" identifier at offset 4.
                 * See linux/drivers/firmware/efi/libstub/zboot-header.S for the header layout:
                 *   0x00: MZ signature
                 *   0x04: "zimg" magic
                 *   0x08: LE32 payload offset
                 *   0x0C: LE32 payload size
                 *   0x18: NUL-terminated compression type string (e.g. "gzip", "zstd") */
                if (magic[4] == 'z' && magic[5] == 'i' && magic[6] == 'm' && magic[7] == 'g') {
                        uint8_t header[0x20];
                        char comp_type[7] = {};
                        uint32_t payload_offset, payload_size;

                        n = pread(fd, header, sizeof(header), 0);
                        if (n < (ssize_t) sizeof(header))
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "Short read of ZBOOT header from '%s'.", path);

                        payload_offset = unaligned_read_le32(header + 0x08); /* .Ldoshdr + 0x08: payload offset */
                        payload_size = unaligned_read_le32(header + 0x0C);   /* .Ldoshdr + 0x0C: payload size */
                        memcpy(comp_type, header + 0x18, 6);                 /* .Ldoshdr + 0x18: compression type */

                        log_debug("Detected ZBOOT image '%s' (compression=%s, offset=%"PRIu32", size=%"PRIu32")",
                                  path, comp_type, payload_offset, payload_size);

                        r = decompress_zboot_to_memfd(fd, payload_offset, payload_size, comp_type);
                        if (r < 0)
                                return r;

                        *ret_kernel_fd = r;
                        return 1;
                }

                /* MZ but not ZBOOT — check if it's a UKI */
                r = extract_uki(path, fd, ret_kernel_fd, ret_initrd_fd);
                if (r != 0)
                        return r; /* Either extracted successfully (1) or error (< 0) */

                /* Not a UKI either — pass through as-is (plain PE kernel) */
                return 0;
        }

        int (*decompress_fn)(int fdf, int fdt, uint64_t max_bytes) = NULL;
        const char *format = NULL;

        /* Magic signatures per RFC 1952 (gzip), tukaani.org/xz/xz-file-format.txt (xz),
         * RFC 8878 (zstd), and lz4/doc/lz4_Frame_format.md (lz4). */
        if (magic[0] == 0x1f && magic[1] == 0x8b) {
                format = "gzip";
                decompress_fn = decompress_stream_gzip;
        } else if (magic[0] == 0xfd && magic[1] == '7' && magic[2] == 'z' &&
                   magic[3] == 'X' && magic[4] == 'Z' && magic[5] == 0x00) {
                format = "xz";
                decompress_fn = decompress_stream_xz;
        } else if (magic[0] == 0x28 && magic[1] == 0xb5 && magic[2] == 0x2f && magic[3] == 0xfd) {
                format = "zstd";
                decompress_fn = decompress_stream_zstd;
        } else if (magic[0] == 0x04 && magic[1] == 0x22 && magic[2] == 0x4d && magic[3] == 0x18) {
                format = "lz4";
                decompress_fn = decompress_stream_lz4;
        }

        if (!decompress_fn)
                /* Not a recognized compressed format, pass through as-is */
                return 0;

        log_debug("Detected %s-compressed kernel '%s', decompressing.", format, path);

        /* Seek back to start before decompression */
        if (lseek(fd, 0, SEEK_SET) < 0)
                return log_error_errno(errno, "Failed to seek kernel fd: %m");

        r = decompress_to_memfd(fd, decompress_fn);
        if (r < 0)
                return r;

        *ret_kernel_fd = r;
        return 1;
}

int create_shutdown_run_nologin_or_warn(void) {
        int r;

        /* This is used twice: once in systemd-user-sessions.service, in order to block logins when we
         * actually go down, and once in systemd-logind.service when shutdowns are scheduled, and logins are
         * to be turned off a bit in advance. We use the same wording of the message in both cases.
         *
         * Traditionally, there was only /etc/nologin, and we managed that. Then, in PAM 1.1
         * support for /run/nologin was added as alternative
         * (https://github.com/linux-pam/linux-pam/commit/e9e593f6ddeaf975b7fe8446d184e6bc387d450b).
         * 13 years later we stopped managing /etc/nologin, leaving it for the administrator to manage.
         */

        r = write_string_file("/run/nologin",
                              "System is going down. Unprivileged users are not permitted to log in anymore. "
                              "For technical details, see pam_nologin(8).",
                              WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_LABEL);
        if (r < 0)
                return log_error_errno(r, "Failed to create /run/nologin: %m");

        return 0;
}
