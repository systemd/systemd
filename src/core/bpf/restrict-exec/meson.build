# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('BPF_FRAMEWORK') != 1
        subdir_done()
endif

restrict_exec_bpf_o_unstripped = custom_target(
        input : 'restrict-exec.bpf.c',
        output : 'restrict-exec.bpf.unstripped.o',
        command : bpf_o_unstripped_cmd)

restrict_exec_bpf_o = custom_target(
        input : restrict_exec_bpf_o_unstripped,
        output : 'restrict-exec.bpf.o',
        command : bpf_o_cmd)

restrict_exec_skel_h = custom_target(
        input : restrict_exec_bpf_o,
        output : 'restrict-exec.skel.h',
        command : skel_h_cmd,
        capture : true)

generated_sources += restrict_exec_skel_h
