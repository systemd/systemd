_GITVER_SH=	if git rev-parse --short HEAD >/dev/null 2>&1; then \
			printf "."; \
			git rev-parse --short HEAD; \
		else \
			echo ""; \
		fi
_GITVER:=	$(shell ${_GITVER_SH})
GITVER=		${_GITVER}
