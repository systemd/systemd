#  -*- Mode: python; coding: utf-8; indent-tabs-mode: nil -*- */
#
#  This file is part of systemd.
#
#  Copyright 2014 Michal Schmidt
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
#  systemd is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with systemd; If not, see <http://www.gnu.org/licenses/>.

import gdb

class sd_dump_hashmaps(gdb.Command):
        "dump systemd's hashmaps"

        def __init__(self):
                super(sd_dump_hashmaps, self).__init__("sd_dump_hashmaps", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

        def invoke(self, arg, from_tty):
                d = gdb.parse_and_eval("hashmap_debug_list")
                all_entry_sizes = gdb.parse_and_eval("all_entry_sizes")
                all_direct_buckets = gdb.parse_and_eval("all_direct_buckets")
                hashmap_base_t = gdb.lookup_type("HashmapBase")
                uchar_t = gdb.lookup_type("unsigned char")
                ulong_t = gdb.lookup_type("unsigned long")
                debug_offset = gdb.parse_and_eval("(unsigned long)&((HashmapBase*)0)->debug")

                print "type, hash, indirect, entries, max_entries, buckets, creator"
                while d:
                        h = gdb.parse_and_eval("(HashmapBase*)((char*)%d - %d)" % (int(d.cast(ulong_t)), debug_offset))

                        if h["has_indirect"]:
                                storage_ptr = h["indirect"]["storage"].cast(uchar_t.pointer())
                                n_entries = h["indirect"]["n_entries"]
                                n_buckets = h["indirect"]["n_buckets"]
                        else:
                                storage_ptr = h["direct"]["storage"].cast(uchar_t.pointer())
                                n_entries = h["n_direct_entries"]
                                n_buckets = all_direct_buckets[int(h["type"])];

                        t = ["plain", "ordered", "set"][int(h["type"])]

                        print "%s, %s, %s, %d, %d, %d, %s (%s:%d)" % (t, h["hash_ops"], bool(h["has_indirect"]), n_entries, d["max_entries"], n_buckets, d["func"], d["file"], d["line"])

                        if arg != "" and n_entries > 0:
                                dib_raw_addr = storage_ptr + (all_entry_sizes[h["type"]] * n_buckets)

                                histogram = {}
                                for i in xrange(0, n_buckets):
                                        dib = int(dib_raw_addr[i])
                                        histogram[dib] = histogram.get(dib, 0) + 1

                                for dib in sorted(iter(histogram)):
                                        if dib != 255:
                                                print "%3d %8d %f%% of entries" % (dib, histogram[dib], 100.0*histogram[dib]/n_entries)
                                        else:
                                                print "%3d %8d %f%% of slots" % (dib, histogram[dib], 100.0*histogram[dib]/n_buckets)
                                print "mean DIB of entries: %f" % (sum([dib*histogram[dib] for dib in iter(histogram) if dib != 255])*1.0/n_entries)

                                blocks = []
                                current_len = 1
                                prev = int(dib_raw_addr[0])
                                for i in xrange(1, n_buckets):
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
                                print "max block: %s" % max(blocks, key=lambda a: a[1])
                                print "sum block lens: %d" % sum(b[1] for b in blocks)
                                print "mean block len: %f" % (1.0 * sum(b[1] for b in blocks) / len(blocks))

                        d = d["debug_list_next"]

sd_dump_hashmaps()
