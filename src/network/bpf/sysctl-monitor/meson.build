# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_SYSCTL_BPF') != 1
        subdir_done()
endif

sysctl_monitor_bpf_o_unstripped = custom_target(
        input : 'sysctl-monitor.bpf.c',
        output : 'sysctl-monitor.bpf.unstripped.o',
        command : bpf_o_unstripped_cmd,
        depends : vmlinux_h_dependency)

sysctl_monitor_bpf_o = custom_target(
        input : sysctl_monitor_bpf_o_unstripped,
        output : 'sysctl-monitor.bpf.o',
        command : bpf_o_cmd)

sysctl_monitor_skel_h = custom_target(
        input : sysctl_monitor_bpf_o,
        output : 'sysctl-monitor.skel.h',
        command : skel_h_cmd,
        capture : true)

generated_sources += sysctl_monitor_skel_h
