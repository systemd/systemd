# keymap is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# keymap is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with keymap; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.

include $(top_srcdir)/Makefile.am.inc

# rules and keymaps
dist_udevrules_DATA = 95-keymap.rules

udevkeymapdir = $(libexecdir)/keymaps
udevkeymap_DATA = \
 keymaps/acer \
 keymaps/acer-aspire_5920g \
 keymaps/acer-extensa_5xxx \
 keymaps/acer-travelmate_6292 \
 keymaps/acer-travelmate_c300 \
 keymaps/asus \
 keymaps/benq-joybook_r22 \
 keymaps/compaq-e_evo \
 keymaps/dell \
 keymaps/fujitsu-amilo_pa_2548 \
 keymaps/fujitsu-amilo_pro_edition_v3505 \
 keymaps/fujitsu-amilo_pro_v3205 \
 keymaps/fujitsu-amilo_si_1520 \
 keymaps/fujitsu-esprimo_mobile_v5 \
 keymaps/fujitsu-esprimo_mobile_v6 \
 keymaps/hewlett-packard \
 keymaps/hewlett-packard-2510p_2530p \
 keymaps/hewlett-packard-compaq_elitebook \
 keymaps/hewlett-packard-pavilion \
 keymaps/hewlett-packard-tablet \
 keymaps/hewlett-packard-tx2 \
 keymaps/inventec-symphony_6.0_7.0 \
 keymaps/lenovo-3000 \
 keymaps/lenovo-thinkpad_x6_tablet \
 keymaps/lenovo-thinkpad_x200_tablet \
 keymaps/maxdata-pro_7000 \
 keymaps/medion-fid2060 \
 keymaps/medionnb-a555 \
 keymaps/micro-star \
 keymaps/module-asus-w3j \
 keymaps/module-ibm \
 keymaps/module-lenovo \
 keymaps/module-sony \
 keymaps/module-sony-old \
 keymaps/oqo-model2 \
 keymaps/samsung-other \
 keymaps/samsung-sq1us \
 keymaps/samsung-sx20s \
 keymaps/toshiba-satellite_a100 \
 keymaps/toshiba-satellite_a110

dist_pkgdata_SCRIPTS = findkeyboards

# keymap program

libexec_PROGRAMS = keymap

keymap_SOURCES = keymap.c
nodist_keymap_SOURCES = keys-from-name.h keys-to-name.h
keymap_CPPFLAGS = $(AM_CPPFLAGS)

dist_doc_DATA = README.keymap.txt

EXTRA_DIST=keymaps check-keymaps.sh
BUILT_SOURCES = keys-from-name.h keys-to-name.h
CLEANFILES = keys.txt keys-from-name.gperf keys-from-name.h keys-to-name.h
TESTS = check-keymaps.sh

#
# generation of keys-{from,to}-name.h from linux/input.h and gperf
#

keys.txt: /usr/include/linux/input.h
	$(AWK) '/^#define.*KEY_/ { if ($$2 != "KEY_MAX" && $$2 != "KEY_CNT") { print $$2 } }' < $< > $@

keys-from-name.gperf: keys.txt
	$(AWK) 'BEGIN{ print "struct key { const char* name; unsigned short id; };"; print "%null-strings"; print "%%";} { print $$1 ", " $$1 }' < $< > $@

keys-from-name.h: keys-from-name.gperf Makefile
	$(GPERF) -t --ignore-case -N lookup_key -H hash_key_name -p -C < $< > $@

keys-to-name.h: keys.txt Makefile
	$(AWK) 'BEGIN{ print "const char* const key_names[KEY_CNT] = { "} { print "[" $$1 "] = \"" $$1 "\"," } END{print "};"}' < $< > $@
