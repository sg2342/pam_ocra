SRCDIR=		${.CURDIR}/..
.PATH:		${SRCDIR}

SHLIB=		pam_ocra
SHLIB_NAME=	${SHLIB}.so.${SHLIB_MAJOR}
SHLIB_MAJOR=	0
SRCS=		pam_ocra.c ocra.c rfc6287.c
LIBDIR=		${PREFIX}/lib

LDADD=		-lcrypto

WARNS=		6
.include <bsd.lib.mk>
