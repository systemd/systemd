/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "sysctl-write-event.h"

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256 * 1024);
} written_sysctls SEC(".maps");

static bool my_streq(const char *s1, const char *s2, size_t l) {
        for (size_t i = 0; i < l; i++) {
                if (s1[i] != s2[i])
                        return false;
                if (s1[i] == 0)
                        return true;
        }
        return true;
}

struct str {
        char *s;
        size_t l;
};

static long cut_last(u32 i, struct str *str) {
        char *s;

        i = str->l - i - 1;
        s = str->s + i;

        /* Sanity check for the preverifier */
        if (i >= str->l)
                return 1;

        if (*s == 0)
                return 0;

        if (*s == '\n' || *s == '\r' || *s == ' ' || *s == '\t') {
                *s = 0;

                return 0;
        }

        return 1;
}

/* Cut off trailing whitespace and newlines */
static void chop(char *s, size_t l) {
        struct str str = { s, l };

        bpf_loop(l, cut_last, &str, 0);
}

SEC("cgroup/sysctl")
int sysctl_monitor(struct bpf_sysctl *ctx) {
        struct sysctl_write_event we = { };

        /* Allow reads */
        if (!ctx->write)
                return 1;

        /* Only monitor net/ */
        bpf_sysctl_get_name(ctx, we.name, sizeof(we.name), 0);
        if (bpf_strncmp(we.name, 4, "net/") != 0)
                return 1;

        we.cgroup_id = bpf_get_current_cgroup_id();
        bpf_get_current_comm(we.comm, sizeof(we.comm));
        bpf_sysctl_get_current_value(ctx, we.current, sizeof(we.current));
        bpf_sysctl_get_new_value(ctx, we.newvalue, sizeof(we.newvalue));

        /* Both the kernel and userspace applications add a newline at the end,
         * remove it from both strings */
        chop(we.current, sizeof(we.current));
        chop(we.newvalue, sizeof(we.newvalue));

        /* If new value differs, send the event */
        if (!my_streq(we.current, we.newvalue, sizeof(we.current)))
                bpf_ringbuf_output(&written_sysctls, &we, sizeof(we), 0);

        return 1;
}

char _license[] SEC("license") = "GPL";
