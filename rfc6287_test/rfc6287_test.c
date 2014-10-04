/*-
 * Copyright (c) 2014 Stefan Grundmann
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/*
 * test vectors from "Appendix C. Test Vectors" of OCRA RFC
 * http://tools.ietf.org/html/rfc6287
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <err.h>
#include <errno.h>
#include <sysexits.h>

#include <openssl/evp.h>

#include "rfc6287.h"

static int failed = 0;

void	C1_1(void);
void	C1_2(void);
void	C1_3(void);
void	C1_4(void);
void	C1_5(void);
void	C2_1(void);
void	C2_2(void);
void	C2_3(void);
void	C3_1(void);
void	C3_2(void);
void	V_1(void);
void	V_2(void);
void	V_3(void);
void	V_4(void);

static const uint8_t Key20[] = {
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30
};

static const uint8_t Key32[] = {
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	0x31, 0x32
};

static const uint8_t Key64[] = {
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	0x31, 0x32, 0x33, 0x34
};

static const uint8_t pinhash[] = {
	0x71, 0x10, 0xed, 0xa4, 0xd0, 0x9e, 0x06, 0x2a, 0xa5, 0xe4,
	0xa3, 0x90, 0xb0, 0xa5, 0x72, 0xac, 0x0d, 0x2c, 0x02, 0x20
};

void
C1_1(void)
{
	const char suite[] = "OCRA-1:HOTP-SHA1-6:QN08";
	char tv[10][2][9] = {
		{"00000000", "237653"},
		{"11111111", "243178"},
		{"22222222", "653583"},
		{"33333333", "740991"},
		{"44444444", "608993"},
		{"55555555", "388898"},
		{"66666666", "816933"},
		{"77777777", "224598"},
		{"88888888", "750600"},
		{"99999999", "294470"}
	};
	int i, ret;
	ocra_suite ocra;

	if (RFC6287_SUCCESS != (ret = rfc6287_parse_suite(&ocra, suite)))
		errx(EX_SOFTWARE, "in C1_1: rfc6287_parse_suite() failed: %d",
		    ret);

	for (i = 0; 10 > i; i++) {
		const char *Q = tv[i][0];
		const char *R = tv[i][1];
		char *RR;

		if (RFC6287_SUCCESS != (ret = rfc6287_ocra(&ocra, suite,
		    Key20, 20, 0, Q, NULL, 0, NULL, 0, 0, &RR)))
			errx(EX_SOFTWARE, "in C1_1: rfc6287_ocra() failed: %d",
			    ret);
		if (0 != strcmp(R, RR))
			printf(" fail (%d)\t%s (Q=%s, R=%s)\n", ++failed,
			    suite, Q, R);
		free(RR);
	}
}

void
C1_2(void)
{
	const char suite[] = "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1";
	char tv[10][9] = {
		"65347737",
		"86775851",
		"78192410",
		"71565254",
		"10104329",
		"65983500",
		"70069104",
		"91771096",
		"75011558",
		"08522129"
	};
	int ret;
	ocra_suite ocra;
	const char Q[] = "12345678";
	uint64_t C;


	if (RFC6287_SUCCESS != (ret = rfc6287_parse_suite(&ocra, suite)))
		errx(EX_SOFTWARE, "in C1_2: rfc6287_parse_suite() failed: %d",
		    ret);

	for (C = 0; 10 > C; C++) {
		const char *R = tv[C];
		char *RR;

		if (RFC6287_SUCCESS != (ret = rfc6287_ocra(&ocra, suite,
		    Key32, 32, C, Q, pinhash, 20, NULL, 0, 0, &RR)))
			errx(EX_SOFTWARE, "in C1_2: rfc6287_ocra() failed: %d",
			    ret);
		if (0 != strcmp(R, RR))
			printf(" fail (%d)\t%s (C=%" PRIu64 ", Q=%s, R=%s)\n",
			    ++failed, suite, C, Q, R);
		free(RR);
	}
}

void
C1_3(void)
{
	const char suite[] = "OCRA-1:HOTP-SHA256-8:QN08-PSHA1";
	char tv[5][2][9] = {
		{"00000000", "83238735"},
		{"11111111", "01501458"},
		{"22222222", "17957585"},
		{"33333333", "86776967"},
		{"44444444", "86807031"},
	};
	int i, ret;
	ocra_suite ocra;

	if (RFC6287_SUCCESS != (ret = rfc6287_parse_suite(&ocra, suite)))
		errx(EX_SOFTWARE, "in C1_3: rfc6287_parse_suite() failed: %d",
		    ret);

	for (i = 0; 5 > i; i++) {
		const char *Q = tv[i][0];
		const char *R = tv[i][1];
		char *RR;

		if (RFC6287_SUCCESS != (ret = rfc6287_ocra(&ocra, suite,
		    Key32, 32, 0, Q, pinhash, 20, NULL, 0, 0, &RR)))
			errx(EX_SOFTWARE, "in C1_3: rfc6287_ocra() failed: %d",
			    ret);
		if (0 != strcmp(R, RR))
			printf(" fail (%d)\t%s (Q=%s, R=%s)\n", ++failed,
			    suite, Q, R);
		free(RR);
	}
}

void
C1_4(void)
{
	const char suite[] = "OCRA-1:HOTP-SHA512-8:C-QN08";
	char tv[10][2][9] = {
		{"00000000", "07016083"},
		{"11111111", "63947962"},
		{"22222222", "70123924"},
		{"33333333", "25341727"},
		{"44444444", "33203315"},
		{"55555555", "34205738"},
		{"66666666", "44343969"},
		{"77777777", "51946085"},
		{"88888888", "20403879"},
		{"99999999", "31409299"}
	};
	int ret;
	uint64_t C;
	ocra_suite ocra;

	if (RFC6287_SUCCESS != (ret = rfc6287_parse_suite(&ocra, suite)))
		errx(EX_SOFTWARE, "in C1_4: rfc6287_parse_suite() failed: %d",
		    ret);

	for (C = 0; 10 > C; C++) {
		const char *Q = tv[C][0];
		const char *R = tv[C][1];
		char *RR;

		if (RFC6287_SUCCESS != (ret = rfc6287_ocra(&ocra, suite,
		    Key64, 64, C, Q, NULL, 0, NULL, 0, 0, &RR)))
			errx(EX_SOFTWARE, "in C1_4: rfc6287_ocra() failed: %d",
			    ret);
		if (0 != strcmp(R, RR))
			printf(" fail (%d)\t%s (C=%" PRIu64 ", Q=%s, R=%s)\n",
			    ++failed, suite, C, Q, R);
		free(RR);
	}
}

void
C1_5(void)
{
	const char suite[] = "OCRA-1:HOTP-SHA512-8:QN08-T1M";
	char tv[5][2][9] = {
		{"00000000", "95209754"},
		{"11111111", "55907591"},
		{"22222222", "22048402"},
		{"33333333", "24218844"},
		{"44444444", "36209546"}
	};
	int i, ret;
	uint64_t T = 0x132d0b6;
	ocra_suite ocra;

	if (RFC6287_SUCCESS != (ret = rfc6287_parse_suite(&ocra, suite)))
		errx(EX_SOFTWARE, "in C1_5: rfc6287_parse_suite() failed: %d",
		    ret);

	for (i = 0; 5 > i; i++) {
		const char *Q = tv[i][0];
		const char *R = tv[i][1];
		char *RR;

		if (RFC6287_SUCCESS != (ret = rfc6287_ocra(&ocra, suite, Key64,
		    64, 0, Q, NULL, 0, NULL, 0, T, &RR)))
			errx(EX_SOFTWARE, "in C1_5: rfc6287_ocra() failed: %d",
			    ret);
		if (0 != strcmp(R, RR))
			printf(" fail (%d)\t%s (Q=%s, R=%s)\n", ++failed,
			    suite, Q, R);
		free(RR);
	}
}

void
C2_1(void)
{
	const char suite[] = "OCRA-1:HOTP-SHA256-8:QA08";
	char tv[10][2][17] = {
		{"CLI22220SRV11110", "28247970"},
		{"CLI22221SRV11111", "01984843"},
		{"CLI22222SRV11112", "65387857"},
		{"CLI22223SRV11113", "03351211"},
		{"CLI22224SRV11114", "83412541"},
		{"SRV11110CLI22220", "15510767"},
		{"SRV11111CLI22221", "90175646"},
		{"SRV11112CLI22222", "33777207"},
		{"SRV11113CLI22223", "95285278"},
		{"SRV11114CLI22224", "28934924"}
	};
	int i, ret;
	ocra_suite ocra;

	if (RFC6287_SUCCESS != (ret = rfc6287_parse_suite(&ocra, suite)))
		errx(EX_SOFTWARE, "in C2_1: rfc6287_parse_suite() failed: %d",
		    ret);

	for (i = 0; 10 > i; i++) {
		const char *Q = tv[i][0];
		const char *R = tv[i][1];
		char *RR;

		if (RFC6287_SUCCESS != (ret = rfc6287_ocra(&ocra, suite,
		    Key32, 32, 0, Q, NULL, 0, NULL, 0, 0, &RR)))
			errx(EX_SOFTWARE, "in C2_1: rfc6287_ocra() failed: %d",
			    ret);
		if (0 != strcmp(R, RR))
			printf(" fail (%d)\t%s (Q=%s, R=%s)\n", ++failed,
			    suite, Q, R);
		free(RR);
	}
}

void
C2_2(void)
{
	const char suite[] = "OCRA-1:HOTP-SHA512-8:QA08";
	char tv[5][2][17] = {
		{"CLI22220SRV11110", "79496648"},
		{"CLI22221SRV11111", "76831980"},
		{"CLI22222SRV11112", "12250499"},
		{"CLI22223SRV11113", "90856481"},
		{"CLI22224SRV11114", "12761449"},
	};
	int i, ret;
	ocra_suite ocra;

	if (RFC6287_SUCCESS != (ret = rfc6287_parse_suite(&ocra, suite)))
		errx(EX_SOFTWARE, "in C2_2: rfc6287_parse_suite() failed: %d",
		    ret);

	for (i = 0; 5 > i; i++) {
		const char *Q = tv[i][0];
		const char *R = tv[i][1];
		char *RR;

		if (RFC6287_SUCCESS != (ret = rfc6287_ocra(&ocra, suite,
		    Key64, 64, 0, Q, NULL, 0, NULL, 0, 0, &RR)))
			errx(EX_SOFTWARE, "in C2_2: rfc6287_ocra() failed: %d",
			    ret);
		if (0 != strcmp(R, RR))
			printf(" fail (%d)\t%s (Q=%s, R=%s)\n", ++failed,
			    suite, Q, R);
		free(RR);
	}
}

void
C2_3(void)
{
	const char suite[] = "OCRA-1:HOTP-SHA512-8:QA08-PSHA1";
	char tv[5][2][17] = {
		{"SRV11110CLI22220", "18806276"},
		{"SRV11111CLI22221", "70020315"},
		{"SRV11112CLI22222", "01600026"},
		{"SRV11113CLI22223", "18951020"},
		{"SRV11114CLI22224", "32528969"},
	};
	int i, ret;
	ocra_suite ocra;

	if (RFC6287_SUCCESS != (ret = rfc6287_parse_suite(&ocra, suite)))
		errx(EX_SOFTWARE, "in C2_3: rfc6287_parse_suite() failed: %d",
		    ret);

	for (i = 0; 5 > i; i++) {
		const char *Q = tv[i][0];
		const char *R = tv[i][1];
		char *RR;

		if (0 != (ret = rfc6287_ocra(&ocra, suite, Key64, 64, 0, Q,
		    pinhash, 20, NULL, 0, 0, &RR)))
			errx(EX_SOFTWARE, "in C2_3: rfc6287_ocra() failed: %d",
			    ret);
		if (0 != strcmp(R, RR))
			printf(" fail (%d)\t%s (Q=%s, R=%s)\n", ++failed,
			    suite, Q, R);
		free(RR);
	}
}

void
C3_1(void)
{
	const char suite[] = "OCRA-1:HOTP-SHA256-8:QA08";
	char tv[5][2][9] = {
		{"SIG10000", "53095496"},
		{"SIG11000", "04110475"},
		{"SIG12000", "31331128"},
		{"SIG13000", "76028668"},
		{"SIG14000", "46554205"},
	};
	int i, ret;
	ocra_suite ocra;

	if (RFC6287_SUCCESS != (ret = rfc6287_parse_suite(&ocra, suite)))
		errx(EX_SOFTWARE, "in C3_1 rfc6287_parse_suite() failed: %d",
		    ret);

	for (i = 0; 5 > i; i++) {
		const char *Q = tv[i][0];
		const char *R = tv[i][1];
		char *RR;

		if (0 != (ret = rfc6287_ocra(&ocra, suite, Key32, 32, 0, Q,
		    NULL, 0, NULL, 0, 0, &RR)))
			errx(EX_SOFTWARE, "in C2_2: rfc6287_ocra() failed: %d",
			    ret);
		if (0 != strcmp(R, RR))
			printf(" fail (%d)\t%s (Q=%s, R=%s)\n", ++failed,
			    suite, Q, R);
		free(RR);
	}
}

void
C3_2(void)
{
	const char suite[] = "OCRA-1:HOTP-SHA512-8:QA10-T1M";
	char tv[5][2][11] = {
		{"SIG1000000", "77537423"},
		{"SIG1100000", "31970405"},
		{"SIG1200000", "10235557"},
		{"SIG1300000", "95213541"},
		{"SIG1400000", "65360607"},
	};
	int i, ret;
	ocra_suite ocra;
	uint64_t T = 0x132d0b6;

	if (RFC6287_SUCCESS != (ret = rfc6287_parse_suite(&ocra, suite)))
		errx(EX_SOFTWARE, "in C3_2 rfc6287_parse_suite() failed: %d",
		    ret);

	for (i = 0; 5 > i; i++) {
		const char *Q = tv[i][0];
		const char *R = tv[i][1];
		char *RR;

		if (0 != (ret = rfc6287_ocra(&ocra, suite, Key64, 64,
		    0, Q, NULL, 0, NULL, 0, T, &RR)))
			errx(EX_SOFTWARE, "in C3_2: rfc6287_ocra() failed: %d",
			    ret);
		if (0 != strcmp(R, RR))
			printf(" fail (%d)\t%s (Q=%s, R=%s)\n", ++failed,
			    suite, Q, R);
		free(RR);
	}
}

void
V_1(void)
{
	const char suite[] = "OCRA-1:HOTP-SHA256-8:QA08";
	char *Q;
	char *R;
	ocra_suite ocra;
	uint64_t NC;
	int ret;

	if (RFC6287_SUCCESS != (ret = rfc6287_parse_suite(&ocra, suite)))
		errx(EX_SOFTWARE, "in V_1: rfc6287_parse_suite() failed: %d",
		    ret);

	if (RFC6287_SUCCESS != (ret = rfc6287_challenge(&ocra, &Q)))
		errx(EX_SOFTWARE, "in V_1: rfc6287_challenge() failed: %d", ret);
	if (RFC6287_SUCCESS != (ret = rfc6287_ocra(&ocra, suite, Key32, 32,
	    0, Q, NULL, 0, NULL, 0, 0, &R)))
		errx(EX_SOFTWARE, "in V_1: rfc6287_ocra() failed: %d", ret);
	if (0 > (ret = rfc6287_verify(&ocra, suite, Key32, 32, 0, Q, NULL, 0,
	    NULL, 0, 0, R, 0, &NC, 0)))
		errx(EX_SOFTWARE, "in V_1: rfc6287_verify() failed: %d", ret);
	if (RFC6287_VERIFY_FAILED == ret)
		printf(" V_1 failed (%d)\t%s\n", ++failed, suite);
	free(Q);
	free(R);
}

void
V_2(void)
{
	const char suite[] = "OCRA-1:HOTP-SHA512-0:QA08-T1S";
	char *Q;
	char *R;
	ocra_suite ocra;
	uint64_t NC;
	uint64_t T;
	int ret;

	if (RFC6287_SUCCESS != (ret = rfc6287_parse_suite(&ocra, suite)))
		errx(EX_SOFTWARE, "in V_2: rfc6287_parse_suite() failed: %d",
		    ret);

	if (RFC6287_SUCCESS != (ret = rfc6287_challenge(&ocra, &Q)))
		errx(EX_SOFTWARE, "in V_2: rfc6287_challenge() failed: %d",
		    ret);
	if (RFC6287_SUCCESS != (ret = rfc6287_timestamp(&ocra, &T)))
		errx(EX_SOFTWARE, "in V_2: rfc6287_timestamp() failed: %d",
		    ret);
	if (RFC6287_SUCCESS != (ret = rfc6287_ocra(&ocra, suite, Key64, 64,
	    0, Q, NULL, 0, NULL, 0, T, &R)))
		errx(EX_SOFTWARE, "in V_2: rfc6287_ocra() failed: %d", ret);
	/* no timestamp_offset */
	if (0 > (ret = rfc6287_verify(&ocra, suite, Key64, 64, 0, Q, NULL,
	    0, NULL, 0, T + 100, R, 0, &NC, 0)))
		errx(EX_SOFTWARE, "in V_2: rfc6287_verify() failed: %d", ret);
	if (RFC6287_VERIFY_FAILED != ret)
		printf(" V_2 failed(A) (%d)\t%s\n", ++failed, suite);
	/* timestamp_offset */
	if (0 > (ret = rfc6287_verify(&ocra, suite, Key64, 64, 0, Q, NULL,
	    0, NULL, 0, T - 100, R, 0, &NC, 120)))
		errx(EX_SOFTWARE, "in V_2: rfc6287_verify() failed: %d", ret);
	if (RFC6287_VERIFY_FAILED == ret)
		printf(" V_2 failed(B) (%d)\t%s\n", ++failed, suite);
	free(Q);
	free(R);
}

void
V_3(void)
{
	const char suite[] = "OCRA-1:HOTP-SHA1-0:C-QH18";
	char *Q;
	char *R;
	ocra_suite ocra;
	uint64_t NC;
	int ret;

	if (RFC6287_SUCCESS != (ret = rfc6287_parse_suite(&ocra, suite)))
		errx(EX_SOFTWARE, "in V_3: rfc6287_parse_suite() failed: %d",
		    ret);

	if (RFC6287_SUCCESS != (ret = rfc6287_challenge(&ocra, &Q)))
		errx(EX_SOFTWARE, "in V_3: rfc6287_challenge() failed: %d",
		    ret);
	if (RFC6287_SUCCESS != (ret = rfc6287_ocra(&ocra, suite, Key20, 20,
	    23, Q, NULL, 0, NULL, 0, 0, &R)))
		errx(EX_SOFTWARE, "in V_3: rfc6287_ocra() failed: %d", ret);
	/* no counter_window */
	if (0 > (ret = rfc6287_verify(&ocra, suite, Key20, 20, 1, Q, NULL,
	    0, NULL, 0, 0, R, 0, &NC, 0)))
		errx(EX_SOFTWARE, "in V_3: rfc6287_verify() failed: %d", ret);
	if (RFC6287_VERIFY_FAILED != ret)
		printf(" V_3 failed(A) (%d)\t%s\n", ++failed, suite);
	/* counter_window */
	if (0 > (ret = rfc6287_verify(&ocra, suite, Key20, 20, 1, Q, NULL,
	    0, NULL, 0, 0, R, 100, &NC, 0)))
		errx(EX_SOFTWARE, "in V_3: rfc6287_verify() failed: %d", ret);
	if (RFC6287_VERIFY_FAILED == ret || 24 != NC)
		printf(" V_3 failed(B) (%d)\t%s\n", ++failed, suite);
	free(Q);
	free(R);
}

void
V_4(void)
{
	const char suite[] = "OCRA-1:HOTP-SHA1-0:C-QN13-T1M";
	char *Q;
	char *R;
	ocra_suite ocra;
	uint64_t NC;
	uint64_t T;
	int ret;

	if (RFC6287_SUCCESS != (ret = rfc6287_parse_suite(&ocra, suite)))
		errx(EX_SOFTWARE, "in V_4: rfc6287_parse_suite() failed: %d",
		    ret);

	if (RFC6287_SUCCESS != (ret = rfc6287_challenge(&ocra, &Q)))
		errx(EX_SOFTWARE, "in V_4: rfc6287_challenge() failed: %d",
		    ret);
	if (RFC6287_SUCCESS != (ret = rfc6287_timestamp(&ocra, &T)))
		errx(EX_SOFTWARE, "in V_2: rfc6287_timestamp() failed: %d",
		    ret);
	if (RFC6287_SUCCESS != (ret = rfc6287_ocra(&ocra, suite, Key20, 20,
	    23, Q, NULL, 0, NULL, 0, T, &R)))
		errx(EX_SOFTWARE, "in V_4: rfc6287_ocra() failed: %d", ret);
	/* no counter_window, no timestamp_offset */
	if (0 > (ret = rfc6287_verify(&ocra, suite, Key20, 20, 1, Q, NULL, 0,
	    NULL, 0, T + 5, R, 0, &NC, 0)))
		errx(EX_SOFTWARE, "in V_4: rfc6287_verify() failed: %d", ret);
	if (RFC6287_VERIFY_FAILED != ret)
		printf(" V_4 failed(A) (%d)\t%s\n", ++failed, suite);
	/* counter_window, no timestamp_offset */
	if (0 > (ret = rfc6287_verify(&ocra, suite, Key20, 20, 1, Q, NULL, 0,
	    NULL, 0, T + 5, R, 120, &NC, 0)))
		errx(EX_SOFTWARE, "in V_4: rfc6287_verify() failed: %d", ret);
	if (RFC6287_VERIFY_FAILED != ret)
		printf(" V_4 failed(B) (%d)\t%s\n", ++failed, suite);
	/* no counter_window, timestamp_offset */
	if (0 > (ret = rfc6287_verify(&ocra, suite, Key20, 20, 1, Q, NULL, 0,
	    NULL, 0, T + 5, R, 0, &NC, 10)))
		errx(EX_SOFTWARE, "in V_4: rfc6287_verify() failed: %d", ret);
	if (RFC6287_VERIFY_FAILED != ret)
		printf(" V_4 failed(C) (%d)\t%s\n", ++failed, suite);
	/* counter_window and timestamp_offset */
	if (0 > (ret = rfc6287_verify(&ocra, suite, Key20, 20, 1, Q, NULL, 0,
	    NULL, 0, T + 5, R, 120, &NC, 10)))
		errx(EX_SOFTWARE, "in V_4: rfc6287_verify() failed: %d", ret);
	if (RFC6287_VERIFY_FAILED == ret || 24 != NC)
		printf(" V_4 failed(D) (%d)\t%s\n", ++failed, suite);
	free(Q);
	free(R);
}


int
main(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	C1_1();
	C1_2();
	C1_3();
	C1_4();
	C1_5();
	C2_1();
	C2_2();
	C2_3();
	C3_1();
	C3_2();
	V_1();
	V_2();
	V_3();
	V_4();
	if (0 == failed)
		printf("passed\n");
	return failed;
}
