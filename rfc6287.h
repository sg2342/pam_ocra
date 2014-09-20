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

size_t mdlen(enum alg A);
const EVP_MD * evp_md(enum alg A);

typedef struct ocra_suite_struct {
	/* CryptoFunction */
	enum alg hotp_alg;
	int	hotp_trunc;
	/* DataInput */
	int	flags;
	enum fmt Q_fmt;
	int	Q_l;
	enum alg P_alg;
	int	S_l;
	int	T_step;
}	ocra_suite;

int parse_num(
	const char *);

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
		uint64_t C,
		const char *Q,
		const uint8_t *P, size_t P_len,
		const uint8_t *S, size_t S_len,
		uint64_t T,
		char **response);

int rfc6287_verify(
		const ocra_suite *ocra,
		const char *suite_string,
		const uint8_t *key, size_t key_len,
		uint64_t C,
		const char *Q,
		const uint8_t *P, size_t P_len,
		const uint8_t *S, size_t S_len,
		uint64_t T,
		const char *response,
		uint32_t counter_window,
		uint64_t *next_counter,
		uint32_t timestamp_offset);
#endif
