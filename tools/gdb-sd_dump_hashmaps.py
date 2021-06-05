#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import gdb

class sd_dump_hashmaps(gdb.Command):
    "dump systemd's hashmaps"

    def __init__(self):
        super().__init__("sd_dump_hashmaps", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        d = gdb.parse_and_eval("hashmap_debug_list")
        hashmap_type_info = gdb.parse_and_eval("hashmap_type_info")
        uchar_t = gdb.lookup_type("unsigned char")
        ulong_t = gdb.lookup_type("unsigned long")
        debug_offset = gdb.parse_and_eval("(unsigned long)&((HashmapBase*)0)->debug")

        print("type, hash, indirect, entries, max_entries, buckets, creator")
        while d:
            h = gdb.parse_and_eval(f"(HashmapBase*)((char*){int(d.cast(ulong_t))} - {debug_offset})")

            if h["has_indirect"]:
                storage_ptr = h["indirect"]["storage"].cast(uchar_t.pointer())
                n_entries = h["indirect"]["n_entries"]
                n_buckets = h["indirect"]["n_buckets"]
            else:
                storage_ptr = h["direct"]["storage"].cast(uchar_t.pointer())
                n_entries = h["n_direct_entries"]
                n_buckets = hashmap_type_info[h["type"]]["n_direct_buckets"]

            t = ["plain", "ordered", "set"][int(h["type"])]

            print(f'{t}, {h["hash_ops"]}, {bool(h["has_indirect"])}, {n_entries}, {d["max_entries"]}, {n_buckets}, {d["func"].string()}, {d["file"].string()}:{d["line"]}')

            if arg != "" and n_entries > 0:
                dib_raw_addr = storage_ptr + hashmap_type_info[h["type"]]["entry_size"] * n_buckets

                histogram = {}
                for i in range(0, n_buckets):
                    dib = int(dib_raw_addr[i])
                    histogram[dib] = histogram.get(dib, 0) + 1

                for dib in sorted(histogram):
                    if dib != 255:
                        print(f"{dib:>3} {histogram[dib]:>8} {float(histogram[dib]/n_entries):.0%} of entries")
                    else:
                        print(f"{dib:>3} {histogram[dib]:>8} {float(histogram[dib]/n_buckets):.0%} of slots")
                        s = sum(dib*count for (dib, count) in histogram.items() if dib != 255) / n_entries
                        print(f"mean DIB of entries: {s}")

                blocks = []
                current_len = 1
                prev = int(dib_raw_addr[0])
                for i in range(1, n_buckets):
                    dib = int(dib_raw_addr[i])
                    if (dib == 255) != (prev == 255):
                        if prev != 255:
                            blocks += [[i, current_len]]
                            current_len = 1
                    else:
                        current_len += 1

                    prev = dib
                if prev != 255:
                    blocks += [[i, current_len]]
                    # a block may be wrapped around
                if len(blocks) > 1 and blocks[0][0] == blocks[0][1] and blocks[-1][0] == n_buckets - 1:
                    blocks[0][1] += blocks[-1][1]
                    blocks = blocks[0:-1]
                    print("max block: {}".format(max(blocks, key=lambda a: a[1])))
                    print("sum block lens: {}".format(sum(b[1] for b in blocks)))
                    print("mean block len: {}".format(sum(b[1] for b in blocks) / len(blocks)))

            d = d["debug_list_next"]

sd_dump_hashmaps()
