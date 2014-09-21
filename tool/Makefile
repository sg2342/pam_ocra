SRCDIR=		${.CURDIR}/..
.PATH:		${SRCDIR}

PROG=		ocra_tool
SRCS=		ocra_tool.c rfc6287.c
LDADD=		-lcrypto
MK_MAN=		no
BINDIR=		${PREFIX}/bin
WARNS=		6
.include <bsd.prog.mk>
