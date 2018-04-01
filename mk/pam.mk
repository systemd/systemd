ifeq (${MKPAM},pam)
LIBPAM?=	-lpam
CPPFLAGS+=	-DHAVE_PAM
LDADD+=		${LIBPAM}

ifeq (${MKSELINUX},yes)
# with selinux, pam_misc is needed too
LIBPAM_MISC?=	-lpam_misc
LDADD+=		${LIBPAM_MISC}
endif

PAMDIR?=	/etc/pam.d
PAMMODE?=	0644
else ifneq (${MKPAM},)
$(error if MKPAM is defined, it must be "pam")
endif
