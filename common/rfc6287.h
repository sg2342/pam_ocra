#ifndef _H_PAM_RFC6287_H_
#define _H_PAM_RFC6287_H_

enum alg {
	none = 0, sha1 = 1, sha256 = 2, sha512 = 3
};
enum fmt {
	a = 1, n = 2, h = 3
};
enum {
	FL_C = 1, FL_P = 2, FL_S = 4, FL_T = 8
};

enum RFC6287_{
    RFC6287_INVALID_SUITE       = -5,
    RFC6287_INVALID_CHALLENGE   = -4,
    RFC6287_INVALID_PARAMS      = -3,
    RFC6287_ERR_POSIX           = -2, /* libc, errno is set */
    RFC6287_ERR_OPENSSL         = -1, /* use ERR_get_error() */
    RFC6287_SUCCESS             = 0,
    RFC6287_VERIFY_FAILED       = 1
};

size_t mdlen(enum alg A);
const EVP_MD * evp_md(enum alg A);

typedef struct ocra_suite_struct {
	/* CryptoFunction */
	enum alg hotp_alg;
	int	 hotp_trunc;
	/* DataInput */
	int	 flags;
	enum fmt Q_fmt;
	int	 Q_l;
	enum alg P_alg;
	size_t	 S_l;
	int	 T_step;
}	ocra_suite;

const char * rfc6287_err(int e);

int rfc6287_timestamp(
	const ocra_suite * ocra,
	uint64_t *timestamp);

int rfc6287_parse_suite(
	ocra_suite *ocra,
	const char *suite_string);

int rfc6287_challenge(
	const ocra_suite *ocra,
	char **questions);

int rfc6287_ocra(
	const ocra_suite *ocra,
	const char *suite_string,
	const uint8_t *key, size_t key_len,
	uint64_t C, 			/* 0 if no C param in suite */
	const char *Q,
	const uint8_t *P, size_t P_len, /* NULL, 0 if no P param in suite */
	const uint8_t *S, size_t S_len, /* NULL, 0 if no S param in suite */
	uint64_t T, 			/* 0 if no T param in suite */
	char **response);

int rfc6287_verify(
	const ocra_suite *ocra,
	const char *suite_string,
	const uint8_t *key, size_t key_len,
	uint64_t C, 			/* 0 if no C param in suite */
	const char *Q,
	const uint8_t *P, size_t P_len, /* NULL, 0 if no P param in suite */
	const uint8_t *S, size_t S_len, /* NULL, 0 if no S param in suite */
	uint64_t T, 			/* 0 if no T param in suite */
	const char *response,
	uint32_t counter_window, 	/* 0 if no C param in suite */
	uint64_t *next_counter,
	uint32_t timestamp_offset); 	/* 0 if no T param in suite */
#endif
