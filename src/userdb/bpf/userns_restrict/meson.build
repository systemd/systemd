# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('BPF_FRAMEWORK') != 1
        subdir_done()
endif

userns_restrict_bpf_o_unstripped = custom_target(
        'userns-restrict.bpf.unstripped.o',
        input : 'userns-restrict.bpf.c',
        output : 'userns-restrict.bpf.unstripped.o',
        command : bpf_o_unstripped_cmd)

userns_restrict_bpf_o = custom_target(
        'userns-restrict.bpf.o',
        input : userns_restrict_bpf_o_unstripped,
        output : 'userns-restrict.bpf.o',
        command : bpf_o_cmd)

userns_restrict_skel_h = custom_target(
        'userns-restrict.skel.h',
        input : userns_restrict_bpf_o,
        output : 'userns-restrict.skel.h',
        command : skel_h_cmd,
        capture : true)
