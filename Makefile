CFLAGS+=-Wall -Werror -fPIC -DHAVE_SHADOW -O2

all: ocra_tool pam_ocra.so

pam_ocra.so: pam_ocra.o ocra.o rfc6287.o
	${CC} -o pam_ocra.so -s --shared -lpam -lcrypto pam_ocra.o rfc6287.o ocra.o

ocra_tool: rfc6287.o ocra_tool.o
	${CC} -lcrypto -o ocra_tool rfc6287.o ocra_tool.o

rfc6287.o: rfc6287.c rfc6287.h
	${CC} -c ${CFLAGS} rfc6287.c

ocra.o: ocra.c ocra.h
	${CC} -c ${CFLAGS} ocra.c

pam_ocra.o: pam_ocra.c
	${CC} -c ${CFLAGS} pam_ocra.c


clean:
	rm -f ocra_tool.o ocra_tool ocra.o pam_ocra.o ocra.o rfc6287.o pam_ocra.so
