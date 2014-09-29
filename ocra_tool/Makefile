SRCDIR=		${.CURDIR}/../common
.PATH:		${.CURDIR} ${SRCDIR}

CFLAGS+=	-I${.CURDIR}/../common
PROG=		ocra_tool
SRCS=		ocra_tool.c rfc6287.c
LDADD=		-lcrypto
MAN=		${PROG}.8
BINDIR=		${PREFIX}/sbin
WARNS=		6
.include <bsd.prog.mk>
