# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('BPF_FRAMEWORK') != 1 || conf.get('HAVE_VMLINUX_H') != 1
        subdir_done()
endif

notify_ratelimit_o_unstripped = custom_target(
        'notify-ratelimit.bpf.unstripped.o',
        input : 'notify-ratelimit.bpf.c',
        output : 'notify-ratelimit.bpf.unstripped.o',
        command : bpf_o_unstripped_cmd,
        depends : vmlinux_h_dependency)

notify_ratelimit_o = custom_target(
        'notify-ratelimit.bpf.o',
        input : notify_ratelimit_o_unstripped,
        output : 'notify-ratelimit.bpf.o',
        command : bpf_o_cmd)

notify_ratelimit_skel_h = custom_target(
        'notify-ratelimit.skel.h',
        input : notify_ratelimit_o,
        output : 'notify-ratelimit.skel.h',
        command : skel_h_cmd,
        capture : true)
