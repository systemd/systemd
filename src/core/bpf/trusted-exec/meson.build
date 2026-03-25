# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('BPF_FRAMEWORK') != 1
        subdir_done()
endif

trusted_exec_bpf_o_unstripped = custom_target(
        input : 'trusted-exec.bpf.c',
        output : 'trusted-exec.bpf.unstripped.o',
        command : bpf_o_unstripped_cmd)

trusted_exec_bpf_o = custom_target(
        input : trusted_exec_bpf_o_unstripped,
        output : 'trusted-exec.bpf.o',
        command : bpf_o_cmd)

trusted_exec_skel_h = custom_target(
        input : trusted_exec_bpf_o,
        output : 'trusted-exec.skel.h',
        command : skel_h_cmd,
        capture : true)

generated_sources += trusted_exec_skel_h
