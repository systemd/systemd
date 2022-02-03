# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('BPF_FRAMEWORK') != 1
        subdir_done()
endif

restrict_ifaces_bpf_o_unstripped = custom_target(
        'restrict-ifaces.bpf.unstripped.o',
        input : 'restrict-ifaces.bpf.c',
        output : 'restrict-ifaces.bpf.unstripped.o',
        command : bpf_o_unstripped_cmd)

restrict_ifaces_bpf_o = custom_target(
        'restrict-ifaces.bpf.o',
        input : restrict_ifaces_bpf_o_unstripped,
        output : 'restrict-ifaces.bpf.o',
        command : bpf_o_cmd)

restrict_ifaces_skel_h = custom_target(
        'restrict-ifaces.skel.h',
        input : restrict_ifaces_bpf_o,
        output : 'restrict-ifaces.skel.h',
        command : skel_h_cmd,
        capture : true)
