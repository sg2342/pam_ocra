CFLAGS+=-fPIC -std=gnu99 -O2 -pipe -Icommon -fstack-protector-strong
CFLAGS+=-W -Wall -Werror -pedantic -Wno-unused-parameter \
	-Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith \
	-Wreturn-type -Wcast-qual -Wwrite-strings -Wswitch -Wshadow \
	-Wunused-parameter -Wcast-align -Wchar-subscripts -Winline \
	-Wnested-externs -Wredundant-decls -Wold-style-definition \
	-Wno-pointer-sign -Wno-empty-body
TEST_LDFLAGS=-lcrypto
TOOL_LDFLAGS=-lcrypto -ldb
LIB_LDFLAGS=-shared -lcrypto -ldb -lpam

prefix = /usr/local
bindir = $(prefix)/bin
sharedir = $(prefix)/share
mandir = $(sharedir)/man
man8dir = $(mandir)/man8
pamdir = $(prefix)/lib/security

all: ocra_tool/ocra_tool pam_ocra/pam_ocra.so

test: rfc6287_test/rfc6287_test
	$^

install: all
	mkdir -p $(DESTDIR)$(bindir) $(DESTDIR)$(man8dir) $(DESTDIR)$(pamdir)
	install -m 644 ocra_tool/ocra_tool.8 pam_ocra/pam_ocra.8 \
		$(DESTDIR)$(man8dir)
	install -s ocra_tool/ocra_tool $(DESTDIR)$(bindir)
	install -s pam_ocra/pam_ocra.so $(DESTDIR)$(pamdir)

clean:
	rm -rf 	ocra_tool/ocra_tool pam_ocra/pam_ocra.so \
		rfc6287_test/rfc6287_test common/rfc6287.o \
		rfc6287_test/rfc6287_test.o ocra_tool/ocra_tool.o \
		pam_ocra/ocra.o pam_ocra/pam_ocra.o

rfc6287_test/rfc6287_test: common/rfc6287.o rfc6287_test/rfc6287_test.o
	${CC} ${TEST_LDFLAGS} -o $@ $^

ocra_tool/ocra_tool: common/rfc6287.o ocra_tool/ocra_tool.o
	${CC} ${TOOL_LDFLAGS} -o $@ $^

pam_ocra/pam_ocra.so: common/rfc6287.o pam_ocra/ocra.o pam_ocra/pam_ocra.o
	${CC} ${LIB_LDFLAGS} -o $@ $^
