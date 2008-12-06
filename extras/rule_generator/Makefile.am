include $(top_srcdir)/Makefile.am.inc

udevhomedir = $(udev_prefix)/lib/udev
dist_udevhome_SCRIPTS = \
	write_cd_rules \
	write_net_rules

dist_udevhome_DATA = \
	rule_generator.functions

udevrulesdir = $(udev_prefix)/lib/udev/rules.d
dist_udevrules_DATA = \
	75-cd-aliases-generator.rules \
	75-persistent-net-generator.rules

