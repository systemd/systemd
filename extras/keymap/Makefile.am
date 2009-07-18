include $(top_srcdir)/Makefile.am.inc

dist_udevrules_DATA = 95-keymap.rules

udevkeymapdir = $(libexecdir)/keymaps
udevkeymap_DATA = \
keymaps/acer \
	keymaps/acer-aspire_5920g \
	keymaps/acer-travelmate_c300 \
	keymaps/asus \
	keymaps/compaq-e_evo \
	keymaps/dell \
	keymaps/everex-xt5000 \
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
	keymaps/hewlett-packard-presario-2100 \
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
	keymaps/toshiba-satellite_a110 \
	keymaps/zepto-znote

dist_libexec_SCRIPTS = findkeyboards

libexec_PROGRAMS = keymap

keymap_SOURCES = keymap.c
nodist_keymap_SOURCES = keys-from-name.h keys-to-name.h
keymap_CPPFLAGS = $(AM_CPPFLAGS)

dist_doc_DATA = README.keymap.txt

EXTRA_DIST = \
	keymaps \
	check-keymaps.sh

BUILT_SOURCES = \
	keys-from-name.h \
	keys-to-name.h

CLEANFILES = \
	keys.txt keys-from-name.gperf \
	keys-from-name.h keys-to-name.h

TESTS = check-keymaps.sh

keys.txt: /usr/include/linux/input.h
	$(AWK) '/^#define.*KEY_/ { if ($$2 != "KEY_MAX" && $$2 != "KEY_CNT") { print $$2 } }' < $< > $@

keys-from-name.gperf: keys.txt
	$(AWK) 'BEGIN{ print "struct key { const char* name; unsigned short id; };"; print "%null-strings"; print "%%";} { print $$1 ", " $$1 }' < $< > $@

keys-from-name.h: keys-from-name.gperf Makefile
	$(GPERF) -t --ignore-case -N lookup_key -H hash_key_name -p -C < $< > $@

keys-to-name.h: keys.txt Makefile
	$(AWK) 'BEGIN{ print "const char* const key_names[KEY_CNT] = { "} { print "[" $$1 "] = \"" $$1 "\"," } END{print "};"}' < $< > $@
