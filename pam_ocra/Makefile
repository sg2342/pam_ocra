SRCDIR=		${.CURDIR}/../common
.PATH:		${SRCDIR} ${.CURDIR}

CFLAGS+=	-I${.CURDIR}/../common
SHLIB=		pam_ocra
SHLIB_NAME=	${SHLIB}.so.${SHLIB_MAJOR}
SHLIB_MAJOR=	0
SRCS=		pam_ocra.c ocra.c rfc6287.c
MAN=		pam_ocra.8
LIBDIR=		${PREFIX}/lib
MANDIR=		${PREFIX}/man/man

LDADD=		-lcrypto

WARNS=		6
.include <bsd.lib.mk>
