VERSION := $(shell cat version)
SUBDIRS = klibc ash ipconfig nfsmount utils kinit gzip

all:

rpmbuild = $(shell which rpmbuild 2>/dev/null || which rpm)

klibc.spec: klibc.spec.in version
	sed -e 's/@@VERSION@@/$(VERSION)/g' < $< > $@

.PHONY: rpm
rpm: klibc.spec
	+$(rpmbuild) -bb klibc.spec --target=$(ARCH)

%:
	@set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d $@; done

clean:
	@set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d $@; done

spotless:
	@set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d $@; done
	rm -f klibc.spec *~ tags
