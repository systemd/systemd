# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('BPF_FRAMEWORK') != 1
        subdir_done()
endif

restrict_fs_bpf_o_unstripped = custom_target(
        'restrict-fs.bpf.unstripped.o',
        input : 'restrict-fs.bpf.c',
        output : 'restrict-fs.bpf.unstripped.o',
        command : bpf_o_unstripped_cmd)

restrict_fs_bpf_o = custom_target(
        'restrict-fs.bpf.o',
        input : restrict_fs_bpf_o_unstripped,
        output : 'restrict-fs.bpf.o',
        command : bpf_o_cmd)

restrict_fs_skel_h = custom_target(
        'restrict-fs.skel.h',
        input : restrict_fs_bpf_o,
        output : 'restrict-fs.skel.h',
        command : skel_h_cmd,
        capture : true)
