ifeq (${MKTERMCAP},ncurses)
TERMCAP_CFLAGS:=	$(shell ${PKG_CONFIG} ncurses --cflags 2> /dev/null)
LTERMCAP:=			$(shell ${PKG_CONFIG} ncurses --libs 2> /dev/null)
ifeq ($(LTERMCAP),)
LIBTERMCAP?=	-lncurses
else
LIBTERMCAP?= $(LTERMCAP)
endif
CPPFLAGS+=	-DHAVE_TERMCAP ${TERMCAP_CFLAGS}
LDADD+=		${LIBTERMCAP}
else ifeq (${MKTERMCAP},termcap)
LIBTERMCAP?=	-ltermcap
CPPFLAGS+=	-DHAVE_TERMCAP
LDADD+=		${LIBTERMCAP}
else ifneq (${MKTERMCAP},)
$(error If MKTERMCAP is defined, it must be ncurses or termcap)
endif
