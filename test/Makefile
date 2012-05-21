# Just a little hook script to easy building when in this directory
.PHONY: all check clean

all:
	$(MAKE) -C ..

clean:
	@for i in TEST-[0-9]*; do \
		[ -d $$i ] || continue ; \
		[ -f $$i/Makefile ] || continue ; \
		make -C $$i clean ; \
	done

check:
	$(MAKE) -C .. all
	@for i in TEST-[0-9]*; do \
		[ -d $$i ] || continue ; \
		[ -f $$i/Makefile ] || continue ; \
		make -C $$i all ; \
	done
