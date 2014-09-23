SUBDIR= pam_ocra \
	ocra_tool

.if defined(TEST)
SUBDIR+= rfc6287_test
.endif

.include <bsd.subdir.mk>
