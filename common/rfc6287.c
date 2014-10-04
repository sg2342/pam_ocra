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

#include <sys/types.h>
#include <sys/endian.h>
#include <sys/time.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include "rfc6287.h"

size_t
mdlen(enum alg A)
{
	switch (A) {
	case sha1:
		return 20;
	case sha256:
		return 32;
	case sha512:
		return 64;
	default:
		return 0;
	}
}

const EVP_MD *
evp_md(enum alg A)
{
	switch (A) {
	case sha1:
		return EVP_sha1();
	case sha256:
		return EVP_sha256();
	case sha512:
		return EVP_sha512();
	default:
		return NULL;
	}
}

static enum alg
parse_alg(const char *in)
{
	if (0 == strcmp(in, "SHA1"))
		return sha1;
	else if (0 == strcmp(in, "SHA256"))
		return sha256;
	else if (0 == strcmp(in, "SHA512"))
		return sha512;
	return none;
}

static int
parse_num(const char *in)
{
	char *stopped;
	int x = (int)strtol(in, &stopped, 10);

	if (*stopped || (x < 0))
		return -1;
	return x;
}

static int
parse_cryptofunction(ocra_suite * ocra, const char *in)
{
	int ret, l;
	char *token, *string, *tofree;

	if (NULL == (tofree = string = strdup(in)))
		return RFC6287_ERR_POSIX;

	if ((NULL == (token = strsep(&string, "-"))) ||
	    (0 != strcmp(token, "HOTP")) ||
	    (NULL == (token = strsep(&string, "-"))) ||
	    (none == (ocra->hotp_alg = parse_alg(token))) ||
	    (NULL == (token = strsep(&string, "-"))) ||
	    (2 < (l = strlen(token))) ||
	    (-1 == (ocra->hotp_trunc = parse_num(token))) ||
	    ((0 != ocra->hotp_trunc) &&
	    ((4 > ocra->hotp_trunc) || (11 < ocra->hotp_trunc))) ||
	    ((10 > ocra->hotp_trunc) && (2 == l)))
		ret = RFC6287_INVALID_SUITE;
	else
		ret = 0;
	free(tofree);
	return ret;
}

static int
parse_datainput(ocra_suite * ocra, const char *in)
{
	int ret = RFC6287_INVALID_SUITE;
	char *token, *string, *tofree;

	if (NULL == (tofree = string = strdup(in)))
		return RFC6287_ERR_POSIX;

	if ((NULL == (token = strsep(&string, "-"))))
		goto err;

	/* C: optional */
	if (0 == strcmp(token, "C")) {
		ocra->flags |= FL_C;
		if (NULL == (token = strsep(&string, "-")))
			goto err;
	}
	/* QFxx: mandatory */
	if (4 != strlen(token))
		goto err;
	if (0 == strncmp(token, "QA", 2))
		ocra->Q_fmt = a;
	else if (0 == strncmp(token, "QN", 2))
		ocra->Q_fmt = n;
	else if (0 == strncmp(token, "QH", 2))
		ocra->Q_fmt = h;
	else
		goto err;
	if ((-1 == (ocra->Q_l = parse_num(token + 2))) ||
	    ((4 > ocra->Q_l) || 65 < (ocra->Q_l)))
		goto err;
	if (NULL == (token = strsep(&string, "-")))
		goto done;
	/* PH: optional */
	if ('P' == token[0]) {
		ocra->flags |= FL_P;
		if (none == (ocra->P_alg = parse_alg(token + 1)))
			goto err;
		if (NULL == (token = strsep(&string, "-")))
			goto done;
	}
	/* Snnn: optional */
	if ('S' == token[0]) {
		int tmp;

		ocra->flags |= FL_S;
		if ((4 != strlen(token)) ||
		    (-1 == (tmp = parse_num(token + 1))) ||
		    ((-1 > tmp) || (1000 < tmp)))
			goto err;
		ocra->S_l = tmp;
		if (NULL == (token = strsep(&string, "-")))
			goto done;
	}
	/* TG: optional */
	if ('T' == token[0]) {
		int y;
		int l = strlen(token);
		char c;

		ocra->flags |= FL_T;
		if (3 > l || 4 < l)
			goto err;
		c = token[l - 1];
		token[l - 1] = 0;
		if (-1 == (y = parse_num(token + 1)))
			goto err;
		switch (c) {
		case 'S':
			if (((0 > y) || (60 < y)) || ((10 > y) && (3 != l)))
				goto err;
			ocra->T_step = y;
			break;
		case 'M':
			if (((0 > y) || (60 < y)) || ((10 > y) && (3 != l)))
				goto err;
			ocra->T_step = y * 60;
			break;
		case 'H':
			if (((0 > y) || (48 < y)) || ((10 < y) && (3 != l)))
				goto err;
			ocra->T_step = y * 3600;
			break;
		default:
			goto err;
			break;
		}
		if (NULL == (token = strsep(&string, "-")))
			goto done;
	}
	goto err;
done:
	ret = RFC6287_SUCCESS;
err:
	free(tofree);
	return ret;
}

static int
hex2bin(uint8_t *out, const char *in)
{
	int ret, l, g;
	char *tmp = NULL;
	BIGNUM *B;

	if (NULL == (B = BN_new()))
		return RFC6287_ERR_OPENSSL;

	if ((g = strlen(in)) % 2) {	/* pad hex string to even length */
		if (NULL == (tmp = (char *)malloc(g + 2)))
			return RFC6287_ERR_POSIX;
		memcpy(tmp, in, g);
		tmp[g] = '0';
		tmp[g + 1] = 0;
		if (0 == BN_hex2bn(&B, (const char*)tmp)) {
			ret = RFC6287_ERR_OPENSSL;
			goto err;
		}
	} else if (0 == BN_hex2bn(&B, in)) {
		ret = RFC6287_ERR_OPENSSL;
		goto err;
	}
	if (128 < (l = BN_num_bytes(B))) {
		ret = RFC6287_INVALID_CHALLENGE;
		goto err;
	}
	BN_bn2bin(B, out);
	ret = l;
err:
	free(tmp);
	if (NULL != B)
		BN_free(B);
	return ret;
}

static int
dec2bin(uint8_t *out, const char *in)
{
	int ret, l;
	char *tmp = NULL;
	BIGNUM *B;

	if ((NULL == (B = BN_new())) ||
	    (0 == BN_dec2bn(&B, in)) ||
	    (NULL == (tmp = BN_bn2hex(B)))) {
		ret = RFC6287_ERR_OPENSSL;
		goto err;
	}
	if (256 < (l = strlen(tmp))) {
		ret = RFC6287_INVALID_CHALLENGE;
		goto err;
	}
	if (1 < l && '0' == tmp[0])
		ret = hex2bin(out, tmp + 1);
	else
		ret = hex2bin(out, tmp);
err:
	if (NULL != tmp)
		OPENSSL_free(tmp);
	if (NULL != B)
		BN_free(B);
	return ret;
}

static int
format_questions(const ocra_suite * ocra, uint8_t *out, const char *Q)
{
	int l=0;

	switch (ocra->Q_fmt) {
	case a:
		if (128 < (l = strlen(Q)))
			return RFC6287_INVALID_CHALLENGE;
		else
			memcpy(out, Q, l);
		break;
	case h:
		if (0 > (l = hex2bin(out, Q)))
			return l;
		break;
	case n:
		if (0 > (l = dec2bin(out, Q)))
			return l;
		break;
	}
	memset(out + l, 0, 128 - l);
	return RFC6287_SUCCESS;
}

static int
truncate_md(const uint8_t *md, size_t md_l, int len, char **resp)
{
	uint8_t o = md[md_l - 1] & 0x0f;
	uint64_t v = md[o] << 24 | md[o + 1] << 16 | md[o + 2] << 8 | md[o + 3];
	uint64_t p[] = {
	10000, 100000, 1000000, 10000000, 100000000, 1000000000, 10000000000};

	v = (v & 0x7fffffff) % p[len - 4];
	if (NULL == (*resp = (char *)malloc(len + 1)))
		return RFC6287_ERR_POSIX;

	snprintf(*resp, len + 1, "%.*" PRIu64, len, v);
	return 0;
}

static int
check_di_params(const ocra_suite * ocra, size_t key_l, const char *Q,
    size_t P_l, size_t S_l, uint64_t T)
{
	if ((key_l != mdlen(ocra->hotp_alg)) ||
	    (strlen(Q) < (size_t)(ocra->Q_l)) ||
	    (64 < strlen(Q)) ||
	    ((ocra->flags & FL_P) && (P_l != mdlen(ocra->P_alg))) ||
	    ((ocra->flags & FL_S) && (S_l != ocra->S_l)) ||
	    ((ocra->flags & FL_T) && (0 == T)))
		return RFC6287_INVALID_PARAMS;
	else
		return 0;
}

static inline void
st64be(uint8_t *p, uint64_t x)
{
	uint64_t y = htobe64(x);

	memcpy(p, &y, sizeof(y));
}

static int
verify(const ocra_suite * ocra, const uint8_t *key, size_t key_l,
    const uint8_t *buf, size_t buf_l, const char *resp)
{
	int ret;
	unsigned int md_l = 20;
	uint8_t *md = NULL;
	char *tmp;
	HMAC_CTX ctx;

	if (NULL == ((md = (uint8_t *)malloc(mdlen(ocra->hotp_alg)))))
		return RFC6287_ERR_POSIX;

	HMAC_CTX_init(&ctx);
	if ((1 != HMAC_Init(&ctx, key, key_l, evp_md(ocra->hotp_alg))) ||
	    (1 != HMAC_Update(&ctx, buf, (int)buf_l)) ||
	    (1 != HMAC_Final(&ctx, md, &md_l)) ||
	    (md_l != mdlen(ocra->hotp_alg))) {
		HMAC_CTX_cleanup(&ctx);
		free(md);
		return RFC6287_ERR_OPENSSL;
	}
	HMAC_CTX_cleanup(&ctx);
	if (ocra->hotp_trunc) {
		ret = truncate_md(md, md_l, ocra->hotp_trunc, &tmp);
		free(md);
		if (0 != ret)
			return ret;
	} else
		tmp = (char *)md;
	if (0 != memcmp(resp, tmp,
		(ocra->hotp_trunc) ? (unsigned int)ocra->hotp_trunc : md_l))
		ret = RFC6287_VERIFY_FAILED;
	else
		ret = RFC6287_SUCCESS;
	free(tmp);
	return ret;
}

static int
verify_c(const ocra_suite * ocra, off_t C_off, const uint8_t *key, size_t key_l,
    uint64_t C, uint8_t *buf, size_t buf_l, const char *resp,
    uint32_t counter_window, uint64_t *next_C)
{
	int ret;

	*next_C = C;
	do {
		st64be(buf + C_off, *next_C);
		(*next_C)++;
		if (RFC6287_VERIFY_FAILED !=
		    (ret = verify(ocra, key, key_l, buf, buf_l, resp)))
			break;
	} while (*next_C <= (C + counter_window));
	return ret;
}

int
rfc6287_parse_suite(ocra_suite * ocra, const char *suite)
{
	int ret = RFC6287_INVALID_SUITE;
	char *token, *string, *tofree;

	memset(ocra, 0, sizeof(ocra_suite));

	if (NULL == (tofree = string = strdup(suite)))
		return RFC6287_ERR_POSIX;

	if ((NULL == (token = strsep(&string, ":"))) ||
	    (0 != strcmp(token, "OCRA-1")) ||
	    (NULL == (token = strsep(&string, ":"))) ||
	    (0 != (ret = parse_cryptofunction(ocra, token))) ||
	    (0 != (ret = parse_datainput(ocra, string)))) {
	}
	free(tofree);
	return ret;
}

int
rfc6287_timestamp(const ocra_suite * ocra, uint64_t *T)
{
	if (!(ocra->flags & FL_T)) {
		*T = 0;
		return RFC6287_SUCCESS;
	} else {
		struct timeval tv;
		int ret;

		if (0 != (ret = gettimeofday(&tv, NULL)))
			return RFC6287_ERR_POSIX;
		*T = tv.tv_sec / ocra->T_step;
		return RFC6287_SUCCESS;
	}
}

int
rfc6287_ocra(const ocra_suite * ocra, const char *suite_string,
    const uint8_t *key, size_t key_l, uint64_t C, const char *Q,
    const uint8_t *P, size_t P_l, const uint8_t *S, size_t S_l,
    uint64_t T, char **resp)
{
	int ret;
	uint8_t qbuf[128];
	uint8_t CBE[8];
	uint8_t TBE[8];
	uint8_t *md = NULL;
	unsigned int md_l = 20;
	int suite_l = strlen(suite_string) + 1;
	int flags = ocra->flags;
	HMAC_CTX ctx;

	if ((0 != (ret = check_di_params(ocra, key_l, Q, P_l, S_l, T))) ||
	    (0 != (ret = format_questions(ocra, qbuf, Q))))
		return ret;

	if (flags & FL_C)
		st64be(CBE, C);
	if (flags & FL_T)
		st64be(TBE, T);

	if (NULL == (md = (uint8_t *)malloc(mdlen(ocra->hotp_alg))))
		return RFC6287_ERR_POSIX;

	HMAC_CTX_init(&ctx);
	if ((1 != HMAC_Init(&ctx, key, key_l, evp_md(ocra->hotp_alg))) ||
	    (1 !=
		HMAC_Update(&ctx, (const uint8_t *)suite_string, suite_l)) ||
	    ((flags & FL_C) && (1 != HMAC_Update(&ctx, CBE, 8))) ||
	    (1 != HMAC_Update(&ctx, qbuf, 128)) ||
	    ((flags & FL_P) && (1 != HMAC_Update(&ctx, P, P_l))) ||
	    ((flags & FL_S) && (1 != HMAC_Update(&ctx, S, S_l))) ||
	    ((flags & FL_T) && (1 != HMAC_Update(&ctx, TBE, 8))) ||
	    (NULL == (md = (uint8_t *)malloc(mdlen(ocra->hotp_alg)))) ||
	    (1 != HMAC_Final(&ctx, md, &md_l)) ||
	    (md_l != mdlen(ocra->hotp_alg))) {
		HMAC_CTX_cleanup(&ctx);
		free(md);
		return RFC6287_ERR_OPENSSL;
	}
	HMAC_CTX_cleanup(&ctx);
	if (ocra->hotp_trunc) {
		ret = truncate_md(md, md_l, ocra->hotp_trunc, resp);
		free(md);
	} else {
		*resp = (char *)md;
		ret = 0;
	}
	return ret;
}

int
rfc6287_verify(const ocra_suite * ocra, const char *suite_string,
    const uint8_t *key, size_t key_l, uint64_t C, const char *Q,
    const uint8_t *P, size_t P_l, const uint8_t *S, size_t S_l, uint64_t T,
    const char *resp, uint32_t counter_window, uint64_t *next_C,
    uint32_t timestamp_offset)
{
	int ret;
	uint8_t *buf;
	off_t C_off, Q_off, P_off, S_off, T_off;
	size_t buf_l;
	int suite_l = strlen(suite_string) + 1;
	int flags = ocra->flags;

	if ((0 != check_di_params(ocra, key_l, Q, P_l, S_l, T)) ||
	    (timestamp_offset && !(flags & FL_T)) ||
	    (counter_window && !(flags & FL_C)))
		return RFC6287_INVALID_PARAMS;

	buf_l = 128 + suite_l;
	C_off = suite_l;
	if (flags & FL_C) {
		buf_l += 8;
		Q_off = C_off + 8;
	} else
		Q_off = C_off;
	P_off = Q_off + 128;
	if (flags & FL_P) {
		buf_l += P_l;
		S_off = P_off + P_l;
	} else
		S_off = P_off;
	if (flags & FL_S) {
		buf_l += S_l;
		T_off = S_off + S_l;
	} else
		T_off = S_off;
	if (flags & FL_T)
		buf_l += 8;


	if (NULL == (buf = (uint8_t *)malloc(buf_l)))
		return RFC6287_ERR_POSIX;

	memcpy(buf, suite_string, suite_l);

	if ((0 != (ret = format_questions(ocra, buf + Q_off, Q))))
		goto out;

	if (flags & FL_P)
		memcpy(buf + P_off, P, P_l);
	if (flags & FL_S)
		memcpy(buf + S_off, S, S_l);


	if (flags & FL_T) {
		uint64_t TT = T - timestamp_offset;

		for (; T + timestamp_offset >= TT; TT++) {
			st64be(buf + T_off, TT);
			if (flags & FL_C) {
				if (RFC6287_VERIFY_FAILED !=
				    (ret = verify_c(ocra, C_off, key, key_l, C,
					buf, buf_l, resp, counter_window,
					next_C)))
					goto out;
			} else if (RFC6287_VERIFY_FAILED !=
			    (ret = verify(ocra, key, key_l, buf, buf_l, resp)))
				goto out;
		}
	} else if (flags & FL_C)
		ret = verify_c(ocra, C_off, key, key_l, C, buf, buf_l, resp,
		    counter_window, next_C);
	else
		ret = verify(ocra, key, key_l, buf, buf_l, resp);

out:
	free(buf);
	return ret;
}

int
rfc6287_challenge(const ocra_suite * ocra, char **questions)
{
	int i;
	uint8_t buf[64];

	if (1 != RAND_bytes(buf, sizeof(buf)))
		return RFC6287_ERR_OPENSSL;
	if (NULL == (*questions = (char *)malloc(ocra->Q_l + 1)))
		return RFC6287_ERR_POSIX;

	(*questions)[ocra->Q_l] = 0;
	for (i = 0; ocra->Q_l > i; i++)
		switch (ocra->Q_fmt) {
		case a:
			(*questions)[i] = 33 + (buf[i] % 93);
			break;
		case n:
			(*questions)[i] = 48 + (buf[i] % 10);
			break;
		case h:
			sprintf((*questions) + i, "%X", (0x0f) & (buf[i]));
			break;
		}
	return RFC6287_SUCCESS;
}

const char *
rfc6287_err(int e)
{
	switch (e) {
	case RFC6287_INVALID_SUITE:
		return "invalid suite";
	case RFC6287_INVALID_CHALLENGE:
		return "invalid challenge";
	case RFC6287_INVALID_PARAMS:
		return "invalid parameters";
	case RFC6287_ERR_POSIX:
		return strerror(errno);
	case RFC6287_ERR_OPENSSL:
		return ERR_error_string(ERR_get_error(), NULL);
	case RFC6287_VERIFY_FAILED:
		return "verify failed";
	case RFC6287_SUCCESS:
	default:
		return "no error";
	}
}
