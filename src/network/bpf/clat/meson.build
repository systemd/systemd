# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_CLAT_BPF') != 1
        subdir_done()
endif

clat_bpf_o_unstripped = custom_target(
        input : 'clat.bpf.c',
        output : 'clat.bpf.unstripped.o',
        command : bpf_o_unstripped_cmd,
        depends : vmlinux_h_dependency)

clat_bpf_o = custom_target(
        input : clat_bpf_o_unstripped,
        output : 'clat.bpf.o',
        command : bpf_o_cmd)

clat_skel_h = custom_target(
        input : clat_bpf_o,
        output : 'clat.skel.h',
        command : skel_h_cmd,
        capture : true)

generated_sources += clat_skel_h
