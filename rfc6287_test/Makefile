SRCDIR=		${.CURDIR}/../common
.PATH:		${.CURDIR} ${SRCDIR}

CFLAGS+=	-I${.CURDIR}/../common
PROG=		rfc6287_test
SRCS=		rfc6287_test.c rfc6287.c
LDADD=		-lcrypto
MK_MAN=		no
BINDIR=		${PREFIX}/bin
WARNS=		6

install:

.include <bsd.prog.mk>
