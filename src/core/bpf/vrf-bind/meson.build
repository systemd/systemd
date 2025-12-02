# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('BPF_FRAMEWORK') != 1
        subdir_done()
endif

vrf_bind_bpf_o_unstripped = custom_target(
        input : 'vrf-bind.bpf.c',
        output : 'vrf-bind.bpf.unstripped.o',
        command : bpf_o_unstripped_cmd)

vrf_bind_bpf_o = custom_target(
        input : vrf_bind_bpf_o_unstripped,
        output : 'vrf-bind.bpf.o',
        command : bpf_o_cmd)

vrf_bind_skel_h = custom_target(
        input : vrf_bind_bpf_o,
        output : 'vrf-bind.skel.h',
        command : skel_h_cmd,
        capture : true)

generated_sources += brf_bind_skel_h
